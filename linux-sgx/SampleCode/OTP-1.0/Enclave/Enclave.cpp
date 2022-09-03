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
#include <sgx_trts.h>

#define OPT_KEY_SIZE_BYTE 30
#define OPT_KEY_MAC_SIZE_BYTE 10

unsigned char opt_key_sender[OPT_KEY_SIZE_BYTE] = { 0 };
unsigned char opt_key_receiver[OPT_KEY_SIZE_BYTE] = { 0 };


static unsigned char ct[OPT_KEY_SIZE_BYTE] = { 0 };
// static size_t ct_len = 0;
#define PT_LEN 12
static const unsigned char pt[PT_LEN] = "Ciao Mamma!";
static unsigned char pt2[OPT_KEY_SIZE_BYTE] = { 0 };
// static size_t pt2_len = 0;

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

void rsa_enc(void) {
  sgx_sha256_hash_t nonce_hash;

  // printf("[INFO] OPT key sender:\n");
  // for (int i = 0; i < OPT_KEY_SIZE_BYTE; i++)
  //   printf("%02X", opt_key_sender[i]);
  // printf("\n");

  unsigned char tmpp[PT_LEN + OPT_KEY_SIZE_BYTE] = { 0 };
  memcpy(tmpp, pt, PT_LEN);
  memcpy(tmpp + PT_LEN, opt_key_sender, OPT_KEY_SIZE_BYTE);
  // printf("[INFO] sender tmpp computed:\n");
  // for (int i = 0; i < sizeof(tmpp); i++)
  //   printf("%02X", tmpp[i]);
  // printf("\n");

  unsigned char tmpc[OPT_KEY_MAC_SIZE_BYTE] = { 0 };
  sgx_sha256_msg((const uint8_t *)tmpp, sizeof(tmpp), &nonce_hash);
  memcpy(tmpc, nonce_hash, OPT_KEY_MAC_SIZE_BYTE);

  // printf("[INFO] mac sent:\n");
  // for (int i = 0; i < sizeof(tmpc); i++)
  //   printf("%02X", tmpc[i]);
  // printf("\n");

  for (unsigned int i = 0; i < OPT_KEY_SIZE_BYTE; i++) {
    if (i < PT_LEN)
      ct[i] = pt[i] ^ opt_key_sender[i];
    else if (i >= PT_LEN && i < PT_LEN + OPT_KEY_SIZE_BYTE)
      ct[i] = tmpc[i-PT_LEN] ^ opt_key_sender[i];
    else
      ct[i] = 0 ^ opt_key_sender[i];
  }

  sgx_sha256_msg((const uint8_t *)opt_key_sender, OPT_KEY_SIZE_BYTE, &nonce_hash);
  // CHECK(ret_code, "sgx_sha256_msg");
  memcpy(opt_key_sender, nonce_hash, OPT_KEY_SIZE_BYTE);

  // printf("[INFO] cypted text:\n");
  // for (int i = 0; i < OPT_KEY_SIZE_BYTE; i++)
  //   printf("%02X", ct[i]);
  // printf("\n");

  // printf("\n");
}

void rsa_dec(void) {
  sgx_sha256_hash_t nonce_hash;

  // printf("[INFO] OPT key receiver:\n");
  // for (int i = 0; i < OPT_KEY_SIZE_BYTE; i++)
  //   printf("%02X", opt_key_receiver[i]);
  // printf("\n");

  for (int i = 0; i < OPT_KEY_SIZE_BYTE; i++)
      pt2[i] = ct[i] ^ opt_key_receiver[i];

  // check
  unsigned char mac[OPT_KEY_MAC_SIZE_BYTE] = { 0 };
  memcpy(mac, pt2 + PT_LEN, sizeof(mac));
  // printf("[INFO] mac received:\n");
  // for (int i = 0; i < sizeof(mac); i++)
  //   printf("%02X", mac[i]);
  // printf("\n");

  unsigned char tmpp[PT_LEN + OPT_KEY_SIZE_BYTE] = { 0 };
  memcpy(tmpp, pt2, PT_LEN);
  memcpy(tmpp + PT_LEN, opt_key_receiver, OPT_KEY_SIZE_BYTE);
  // printf("[INFO] received tmpp computed:\n");
  // for (int i = 0; i < sizeof(tmpp); i++)
  //   printf("%02X", tmpp[i]);
  // printf("\n");

  unsigned char tmpc[OPT_KEY_MAC_SIZE_BYTE] = { 0 };
  sgx_sha256_msg((const uint8_t *)tmpp, sizeof(tmpp), &nonce_hash);
  memcpy(tmpc, nonce_hash, OPT_KEY_MAC_SIZE_BYTE);
  // printf("[INFO] mac computed:\n");
  // for (int i = 0; i < sizeof(tmpc); i++)
  //   printf("%02X", tmpc[i]);
  // printf("\n");

  if (memcmp(tmpc, mac, OPT_KEY_MAC_SIZE_BYTE) == 0) {
    // printf("[OK!] mac valid!\n");
  }
  else {
    printf("[ERROR] mac ugly!\n");
  }

  // NEXT KEY
  sgx_sha256_msg((const uint8_t *)opt_key_receiver, OPT_KEY_SIZE_BYTE, &nonce_hash);
  // CHECK(ret_code, "sgx_sha256_msg");
  memcpy(opt_key_receiver, nonce_hash, OPT_KEY_SIZE_BYTE);

  // printf("[INFO] plain text: %s\n", pt2);
  // printf("\n");
}

void rsa_init()
{
  sgx_status_t ret_code = SGX_ERROR_UNEXPECTED;

  printf("[INFO] original plain text: %s\n", pt);

  ret_code = sgx_read_rand(opt_key_sender, OPT_KEY_SIZE_BYTE);
  memcpy(opt_key_receiver, opt_key_sender, OPT_KEY_SIZE_BYTE);

  printf("[INFO] OPT key sender:\n");
  for (int i = 0; i < OPT_KEY_SIZE_BYTE; i++)
    printf("%02X", opt_key_sender[i]);
  printf("\n");
  printf("[INFO] OPT key receiver:\n");
  for (int i = 0; i < OPT_KEY_SIZE_BYTE; i++)
    printf("%02X", opt_key_receiver[i]);
  printf("\n");
}
