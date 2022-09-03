/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include <sgx_tcrypto.h>

#include "Sock.h"
#include "crypto_utils.h"

unsigned long ba = 0x0;

static unsigned int n[REF_N_SIZE_IN_UINT] = { 0 };
static unsigned int e[REF_E_SIZE_IN_UINT] = { 0 };

static void* rsa_pub_key;
static unsigned char nonce[REF_NONCE_SIZE] = { 0 };

#define CHECK(ret_code, msg) {if (ret_code != SGX_SUCCESS) {\
                                printf("[Error] %s: %x\n", msg, ret_code);\
                                return;\
                              }\
                              else {\
                                printf("[OK!] %s: %x\n", msg, ret_code);\
                              }}

void setBA(unsigned long basic_address) {
  ba = basic_address;
}

void nextNonce() {
  sgx_sha256_hash_t nonce_hash;
  sgx_status_t ret_code = sgx_sha256_msg((const uint8_t *)nonce, REF_NONCE_SIZE, &nonce_hash);
  CHECK(ret_code, "sgx_sha256_msg");
  memcpy(nonce, nonce_hash, REF_NONCE_SIZE);
}

/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

void bootSecureCommunication(void) {
  char ret[BuffSize] = { 0 };
  // message to init the boot phase (i.e., asking for keys and nonce)
  const char* mInit = "BINIT";
  ocall_monitorgatewayu(mInit, strlen(mInit), ret, BuffSize);

  unsigned int tmp = 0;
  unsigned char c = 0;
  char cc = 0;
  int x = 0;

  printf("[INFO] Boot Secure Communicatin...\n");
  for (int i = 0; i < REF_N_SIZE_IN_BYTES; i++) {
    c = (unsigned char)ret[i];
    // printf("%x ", c);
    tmp |= c << (x*8);
    x++;
    if (x == 4) {
      n[i/4] = tmp;
      x = 0;
      tmp = 0;
    }
  }

  // printf("\nthis is E:\n");
  for (int i = 0; i < REF_E_SIZE_IN_BYTES; i++) {
    c = (unsigned char)ret[REF_N_SIZE_IN_BYTES + i];
    // printf("%x ", c);
    tmp |= c << (x*8);
    x++;
    if (x == 4) {
      e[i/4] = tmp;
      x = 0;
      tmp = 0;
    }
  }
  // PRINT_ARR("\ndecoded E:\n" ,e ,REF_E_SIZE_IN_UINT);
  // PRINT_ARR("decoded N:\n" ,n ,REF_N_SIZE_IN_UINT);

  // generate pub rsa key
  sgx_status_t ret_code = sgx_create_rsa_pub1_key(sizeof(n),
                                      sizeof(e),
                                      (const unsigned char*)n,
                                      (const unsigned char*)e,
                                      &rsa_pub_key);
  CHECK(ret_code, "sgx_create_rsa_pub1_key");

  memcpy(nonce, ret + REF_N_SIZE_IN_BYTES + REF_E_SIZE_IN_BYTES, REF_NONCE_SIZE);
  PRINT_ARR("[INFO] decoded nonce: ", nonce, REF_NONCE_SIZE);

  printf("[INFO] Secure communication: DONE!\n");
}

void traceedgec(void* to) {
  sgx_status_t ret_code = SGX_ERROR_UNEXPECTED;

  void* from =  __builtin_return_address(0);

  char buf_pt[10 + REF_NONCE_SIZE] = { '\0' };
  size_t buf_pt_len = sizeof(buf_pt);
  const char* fmt = "E%04lx%04lx";
  snprintf(buf_pt, sizeof(buf_pt), fmt, (unsigned long)from -ba, (unsigned long)to - ba);
  memcpy(buf_pt + 10, nonce, REF_NONCE_SIZE);
  printf("%s\n", buf_pt);

  unsigned char buf_ct[384];
  size_t buf_ct_len = sizeof(buf_ct);
  ret_code = sgx_rsa_pub_encrypt_sha256(rsa_pub_key, buf_ct, &buf_ct_len, (const unsigned char*)buf_pt, buf_pt_len);
  CHECK(ret_code, "sgx_rsa_pub_encrypt_sha256");
  for (unsigned long i = 0; i < buf_ct_len; i++)
    printf("%02x ", buf_ct[i]);
  printf("\n");

  ocall_monitorgatewayu((const char*)buf_ct, sizeof(buf_ct), 0, 0);

  nextNonce();
}

void hello1()
{
  int x = 3;
loop:
  traceedgec((void*)printf);
  printf("Ciao %d\n", x);
  x--;
  if (x > 0) {
    traceedgec((void*)&&loop);
    goto loop;
  }

  traceedgec((void*)__builtin_return_address(0));
}

void makeEndMsg(unsigned char* msgO, size_t msgO_len) {
  unsigned char msg[4] = "end";

  sgx_status_t ret_code = sgx_rsa_pub_encrypt_sha256(rsa_pub_key, msgO, &msgO_len, (const unsigned char*)msg, sizeof(msg));
  CHECK(ret_code, "sgx_rsa_pub_encrypt_sha256");
  for (unsigned long i = 0; i < msgO_len; i++)
    printf("%02x ", msgO[i]);
  printf("\n");
}
