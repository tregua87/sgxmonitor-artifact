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

#include <sgx_tae_service.h>
#include <sgx_tcrypto.h>

#define REF_RSA_OAEP_3072_MOD_SIZE   384 //hardcode n size to be 384
#define REF_RSA_OAEP_3072_EXP_SIZE     4 //hardcode e size to be 4

#define REF_N_SIZE_IN_BYTES    384
#define REF_E_SIZE_IN_BYTES    4
#define REF_D_SIZE_IN_BYTES    384
#define REF_P_SIZE_IN_BYTES    192
#define REF_Q_SIZE_IN_BYTES    192
#define REF_DMP1_SIZE_IN_BYTES 192
#define REF_DMQ1_SIZE_IN_BYTES 192
#define REF_IQMP_SIZE_IN_BYTES 192

#define REF_N_SIZE_IN_UINT     REF_N_SIZE_IN_BYTES/sizeof(unsigned int)
#define REF_E_SIZE_IN_UINT     REF_E_SIZE_IN_BYTES/sizeof(unsigned int)
#define REF_D_SIZE_IN_UINT     REF_D_SIZE_IN_BYTES/sizeof(unsigned int)
#define REF_P_SIZE_IN_UINT     REF_P_SIZE_IN_BYTES/sizeof(unsigned int)
#define REF_Q_SIZE_IN_UINT     REF_Q_SIZE_IN_BYTES/sizeof(unsigned int)
#define REF_DMP1_SIZE_IN_UINT  REF_DMP1_SIZE_IN_BYTES/sizeof(unsigned int)
#define REF_DMQ1_SIZE_IN_UINT  REF_DMQ1_SIZE_IN_BYTES/sizeof(unsigned int)
#define REF_IQMP_SIZE_IN_UINT  REF_IQMP_SIZE_IN_BYTES/sizeof(unsigned int)

typedef struct _ref_rsa_params_t {
    unsigned int n[REF_N_SIZE_IN_UINT];
    unsigned int e[REF_E_SIZE_IN_UINT];
    unsigned int d[REF_D_SIZE_IN_UINT];
    unsigned int p[REF_P_SIZE_IN_UINT];
    unsigned int q[REF_Q_SIZE_IN_UINT];
    unsigned int dmp1[REF_DMP1_SIZE_IN_UINT];
    unsigned int dmq1[REF_DMQ1_SIZE_IN_UINT];
    unsigned int iqmp[REF_IQMP_SIZE_IN_UINT];
}ref_rsa_params_t;

typedef struct _rpsa_encrypt_pub_key_t {
    uint8_t n[REF_RSA_OAEP_3072_MOD_SIZE];   ///< RSA 3072 public modulus
    uint8_t e[REF_RSA_OAEP_3072_EXP_SIZE];   ///< RSA 3072 public exponent
} rpsa_encrypt_pub_key_t;

// THINGS I NEED!
static ref_rsa_params_t g_rsa_key = { 0 };
void* rsa_pub_key = NULL;
void* rsa_priv_key = NULL;

static unsigned char ct[REF_RSA_OAEP_3072_MOD_SIZE] = { 0 };
static size_t ct_len = 0;
static const unsigned char pt[12] = "Ciao Mamma!";
static size_t pt_len = 12;
static unsigned char *pt2;
static size_t pt2_len = 0;

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
  sgx_status_t ret_code = SGX_ERROR_UNEXPECTED;

  ret_code = sgx_rsa_pub_encrypt_sha256(rsa_pub_key, NULL, &ct_len, pt, pt_len);
  // if (ret_code != SGX_SUCCESS) {
  //   printf("[Error] sgx_rsa_pub_encrypt_sha256 (1): %x\n", ret_code);
  //   return;
  // }
  // else {
  //   printf("[OK!] sgx_rsa_pub_encrypt_sha256 (1): %x\n", ret_code);
  // }

  // printf("[INFO] encrypted text length: %d\n", ct_len);

  ret_code = sgx_rsa_pub_encrypt_sha256(rsa_pub_key, ct, &ct_len, pt, pt_len);
  // if (ret_code != SGX_SUCCESS) {
  //   printf("[Error] sgx_rsa_pub_encrypt_sha256 (2): %x\n", ret_code);
  //   return;
  // }
  // else {
  //   printf("[OK!] sgx_rsa_pub_encrypt_sha256 (2): %x\n", ret_code);
  // }

  // printf("[INFO] encrypted text:\n");
  // for (int i = 0; i < ct_len; i++)
  //   printf("%02x ", ct[i]);
  // printf("\n");
}

void rsa_dec(void) {
  sgx_status_t ret_code = SGX_ERROR_UNEXPECTED;

  ret_code = sgx_rsa_priv_decrypt_sha256(rsa_priv_key, NULL, &pt2_len, ct, ct_len);
  // if (ret_code != SGX_SUCCESS) {
  //   printf("[Error] sgx_rsa_priv_decrypt_sha256 (1): %x\n", ret_code);
  //   return;
  // }
  // else {
  //   printf("[OK!] sgx_rsa_priv_decrypt_sha256 (1): %x\n", ret_code);
  // }

  // printf("[INFO] decrypted text length %d:\n", pt2_len);

  pt2 = (unsigned char*)malloc(pt2_len);
  ret_code = sgx_rsa_priv_decrypt_sha256(rsa_priv_key, pt2, &pt2_len, ct, ct_len);
  // if (ret_code != SGX_SUCCESS) {
  //   printf("[Error] sgx_rsa_priv_decrypt_sha256: %x\n", ret_code);
  //   return;
  // }
  // else {
  //   printf("[OK!] sgx_rsa_priv_decrypt_sha256: %x\n", ret_code);
  // }

  // printf("[INFO] decrypted text: %s\n", pt2);
}

void rsa_init()
{
  sgx_status_t ret_code = SGX_ERROR_UNEXPECTED;

  printf("[INFO] original plain text: %s\n", pt);

  // I need an exponent, I guess..
  g_rsa_key.e[0] = 0x10001;
  ret_code = sgx_create_rsa_key_pair(REF_RSA_OAEP_3072_MOD_SIZE,
      REF_RSA_OAEP_3072_EXP_SIZE,
      (unsigned char*)g_rsa_key.n,
      (unsigned char*)g_rsa_key.d,
      (unsigned char*)g_rsa_key.e,
      (unsigned char*)g_rsa_key.p,
      (unsigned char*)g_rsa_key.q,
      (unsigned char*)g_rsa_key.dmp1,
      (unsigned char*)g_rsa_key.dmq1,
      (unsigned char*)g_rsa_key.iqmp);
  if (ret_code != SGX_SUCCESS) {
      printf("[Error] sgx_create_rsa_key_pair: %x\n", ret_code);
      return;
  }
  else {
    printf("[OK!] sgx_create_rsa_key_pair: %x\n", ret_code);
  }

  ret_code = sgx_create_rsa_pub1_key(sizeof(g_rsa_key.n),
                                      sizeof(g_rsa_key.e),
                                      (const unsigned char*)g_rsa_key.n,
                                      (const unsigned char*)g_rsa_key.e,
                                      &rsa_pub_key);
  if (ret_code != SGX_SUCCESS) {
    printf("[Error] sgx_create_rsa_pub1_key: %x\n", ret_code);
    return;
  }
  else {
    printf("[OK!] sgx_create_rsa_pub1_key: %x\n", ret_code);
  }

  ret_code = sgx_create_rsa_priv2_key(REF_RSA_OAEP_3072_MOD_SIZE,
      REF_RSA_OAEP_3072_EXP_SIZE,
      (const unsigned char*)g_rsa_key.e,
      (const unsigned char*)g_rsa_key.p,
      (const unsigned char*)g_rsa_key.q,
      (const unsigned char*)g_rsa_key.dmp1,
      (const unsigned char*)g_rsa_key.dmq1,
      (const unsigned char*)g_rsa_key.iqmp,
      &rsa_priv_key);
  if (ret_code != SGX_SUCCESS) {
    printf("[Error] sgx_create_rsa_priv2_key: %x\n", ret_code);
    return;
  }
  else {
    printf("[OK!] sgx_create_rsa_priv2_key: %x\n", ret_code);
  }

  // free(pt2);
  // sgx_free_rsa_key(rsa_priv_key, SGX_RSA_PRIVATE_KEY, sizeof(g_rsa_key.n), sizeof(g_rsa_key.e));
  // printf("[INFO] free private key: DONE\n");
  // sgx_free_rsa_key(rsa_pub_key, SGX_RSA_PUBLIC_KEY, sizeof(g_rsa_key.n), sizeof(g_rsa_key.e));
  // printf("[INFO] free pulic key: DONE\n");
  // pt2 = NULL;
}
