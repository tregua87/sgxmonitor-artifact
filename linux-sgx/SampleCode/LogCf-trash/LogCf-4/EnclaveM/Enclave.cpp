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

#include "crypto_utils.h"
#include "uthash.h"

#define EDGE_SIZE 10
struct mentry {
    char edge[EDGE_SIZE];              /* key */
    struct mentry *edges;
    UT_hash_handle hh;         /* makes this structure hashable */
};
char prevEdge[EDGE_SIZE] = { 0 };

struct mentry *model = NULL;

static void* rsa_priv_key = NULL;
static unsigned char pub_nonce[REF_NONCE_SIZE] = { 0 };

#define CHECK(ret_code, msg) {if (ret_code != SGX_SUCCESS) {\
                                printf("[Error] %s: %x\n", msg, ret_code);\
                                return;\
                              }\
                              else {\
                                printf("[OK!] %s: %x\n", msg, ret_code);\
                              }}

void nextNonce() {
  sgx_sha256_hash_t nonce_hash;
  sgx_status_t ret_code = sgx_sha256_msg((const uint8_t *)pub_nonce, REF_NONCE_SIZE, &nonce_hash);
  CHECK(ret_code, "sgx_sha256_msg");
  memcpy(pub_nonce, nonce_hash, REF_NONCE_SIZE);
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

void generateSecrets(unsigned int* n, unsigned int* e, unsigned char* nonce) {
  if (rsa_priv_key)
    return;

  sgx_status_t ret_code = SGX_ERROR_UNEXPECTED;

  printf("[INFO] make and export public key\n");

  g_rsa_key.e[0] = 0x10001;

  // generate rsa keys
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
  CHECK(ret_code, "sgx_create_rsa_key_pair");

  memcpy(n, g_rsa_key.n, REF_N_SIZE_IN_BYTES);
  PRINT_ARR("[INFO] n value (inside the enclave):\n", g_rsa_key.n, REF_N_SIZE_IN_UINT);
  memcpy(e, g_rsa_key.e, REF_E_SIZE_IN_BYTES);
  PRINT_ARR("[INFO] e value (inside the enclave):\n", g_rsa_key.e, REF_E_SIZE_IN_UINT);

  // generate priv rsa key
  ret_code = sgx_create_rsa_priv2_key(REF_RSA_OAEP_3072_MOD_SIZE,
                                      REF_RSA_OAEP_3072_EXP_SIZE,
                                      (const unsigned char*)g_rsa_key.e,
                                      (const unsigned char*)g_rsa_key.p,
                                      (const unsigned char*)g_rsa_key.q,
                                      (const unsigned char*)g_rsa_key.dmp1,
                                      (const unsigned char*)g_rsa_key.dmq1,
                                      (const unsigned char*)g_rsa_key.iqmp,
                                      &rsa_priv_key);
  CHECK(ret_code, "sgx_create_rsa_priv2_key");

  ret_code = sgx_read_rand(pub_nonce, REF_NONCE_SIZE);
  CHECK(ret_code, "sgx_read_rand");
  PRINT_ARR("[INFO] NONCE: ",pub_nonce, REF_NONCE_SIZE);
  memcpy(nonce, pub_nonce, sizeof(pub_nonce));
}

void decrypt(unsigned char *b, size_t b_len, char *res) {
  if (rsa_priv_key == NULL) {
    printf("[ERROR!] Private key is uset!");
    return;
  }

  // X means Unpredictable error
  *res = 'X';

  sgx_status_t ret_code = SGX_ERROR_UNEXPECTED;
  unsigned char pt[384];
  size_t pt_len = 384;
  size_t payload_len = 10;

  ret_code = sgx_rsa_priv_decrypt_sha256(rsa_priv_key, (unsigned char*)pt, &pt_len, b, b_len);
  CHECK(ret_code, "sgx_rsa_priv_decrypt_sha256");

  // memcpy(msg, pt, payload_len);

  // PRINT_ARR("[INFO] Nonce received: ", (pt + payload_len), REF_NONCE_SIZE);
  // PRINT_ARR("[INFO] Nonce saved: ", pub_nonce, REF_NONCE_SIZE);

  // split message and nonce
  if (memcmp(pt + payload_len, pub_nonce, REF_NONCE_SIZE) == 0)
    printf("[OK!] THE NONCEs MATCH\n");
  else
    printf("[ERROR!] The NONCEs do not match\n");

  nextNonce();

  // this is an edge
  if (pt[0] == 'E') {
    struct mentry *e = (struct mentry*)malloc(sizeof(struct mentry));
    memcpy(e->edge, pt, EDGE_SIZE);
    e->edges = NULL;

    if (prevEdge[0] == 0) {
      // model[k] = set<string>();
      HASH_ADD(hh, model, edge, EDGE_SIZE, e);
    } else {
      struct mentry *p, *k;
      HASH_FIND(hh, model, prevEdge, EDGE_SIZE, p);

      HASH_FIND(hh, p->edges, pt, EDGE_SIZE, k);
      if (k == NULL)
        HASH_ADD(hh, p->edges, edge, EDGE_SIZE, e);

      HASH_FIND(hh, model, pt, EDGE_SIZE, k);
      if (k == NULL) {
        k = (struct mentry*)malloc(sizeof(struct mentry));
        memcpy(k->edge, pt, EDGE_SIZE);
        k->edges = NULL;
        HASH_ADD(hh, model, edge, EDGE_SIZE, k);
        // model[k] = set<string>();
      }
    }

    // update previous key
    memcpy(prevEdge, pt, EDGE_SIZE);

    // C means continue
    *res = 'C';
  }
  // end message => stop the monitor
  if (memcmp(pt, "end", 3) == 0) {
    // B means break
    *res = 'B';
    return;
  }
}

void printModel() {
  struct mentry *e, *r;
  printf("Model:\n");
  for(e=model; e != NULL; e=(struct mentry*)e->hh.next) {
      printf("%s: ", e->edge);
      if (e->edges) {
          for(r=e->edges; r != NULL; r=(struct mentry*)r->hh.next) {
            printf("%s ", r->edge);
          }
      }
      printf("\n");

  }
}
