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

unsigned char opt_key[OPT_KEY_SIZE_BYTE] = { 0 };

bucket_t *b;
short *exit_loop;

#define EDGE_SIZE 17
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

void generateSecrets(unsigned char* k, unsigned char* nonce) {
  sgx_status_t ret_code = SGX_ERROR_UNEXPECTED;

  printf("[INFO] make and export OTP key\n");

  ret_code = sgx_read_rand(opt_key, OPT_KEY_SIZE_BYTE);
  CHECK(ret_code, "sgx_read_rand");
  PRINT_ARR("[INFO] OPT key:\n",opt_key, OPT_KEY_SIZE_BYTE);
  memcpy(k, opt_key, OPT_KEY_SIZE_BYTE);

  ret_code = sgx_read_rand(pub_nonce, REF_NONCE_SIZE);
  CHECK(ret_code, "sgx_read_rand");
  PRINT_ARR("[INFO] NONCE:\n",pub_nonce, REF_NONCE_SIZE);
  memcpy(nonce, pub_nonce, sizeof(pub_nonce));
}

long cMsg = 0;
void decrypt(unsigned char *b, size_t b_len, char *res) {
  // printf("[INFO] I decrypt something\n");

  sgx_sha256_hash_t nonce_hash;

  // X means Unpredictable error
  *res = 'X';

  // printf("[INFO] (enclave) crypted buff receiver:\n");
  // for (int i = 0; i < b_len; i++)
  //   printf("%02X ", b[i]);
  // printf("\n");

  sgx_status_t ret_code = SGX_ERROR_UNEXPECTED;
  unsigned char pt[OPT_KEY_SIZE_BYTE];
  size_t pt_len = OPT_KEY_SIZE_BYTE;
  size_t payload_len = 10;

  // decrypt
  for (int i = 0; i < OPT_KEY_SIZE_BYTE; i++)
      pt[i] = b[i] ^ opt_key[i];

  // check
  unsigned char mac[OPT_KEY_MAC_SIZE_BYTE] = { 0 };
  memcpy(mac, pt + EDGE_SIZE, sizeof(mac));
  // PRINT_ARR("[INFO] mac received:\n", mac, sizeof(mac))

  unsigned char tmpp[EDGE_SIZE + OPT_KEY_SIZE_BYTE] = { 0 };
  memcpy(tmpp, pt, EDGE_SIZE);
  memcpy(tmpp + EDGE_SIZE, opt_key, OPT_KEY_SIZE_BYTE);
  // PRINT_ARR("[INFO] received tmpp computed:\n", tmpp, sizeof(tmpp))

  unsigned char tmpc[OPT_KEY_MAC_SIZE_BYTE] = { 0 };
  sgx_sha256_msg((const uint8_t *)tmpp, sizeof(tmpp), &nonce_hash);
  memcpy(tmpc, nonce_hash, OPT_KEY_MAC_SIZE_BYTE);
  // PRINT_ARR("[INFO] mac computed:\n", tmpc, sizeof(tmpc))

  if (memcmp(tmpc, mac, OPT_KEY_MAC_SIZE_BYTE) == 0) {
    // printf("[OK!] mac valid!\n");
  }
  else {
    // printf("[ERROR] mac ugly!\n");
    return;
  }

  // NEXT KEY
  sgx_sha256_msg((const uint8_t *)opt_key, OPT_KEY_SIZE_BYTE, &nonce_hash);
  // CHECK(ret_code, "sgx_sha256_msg");
  memcpy(opt_key, nonce_hash, OPT_KEY_SIZE_BYTE);

  // if (pt[0] == 'T') {
  //   // printf("[INFO] GOT AN EEXIT\n");
  //   dumpEdges(cMsg);
  //   cMsg = 0;
  // }

  /*
  type of edges:
  E: edge, function call, indirect jump, or return
  A: function pointer assignment
  V: virtual pointer assignment (for virtual class in C++)
  F: new frame generated when a function is invoked (to get local variables easier)
  G: ocall_context generation
  C: ocall_contect consumption
  J: sgx_exception_info generation
  K: sgx_exception_info consumption
  N: EENTER
  B: conditional branch (1: taken, 2: not taken)
  T: EEXIT
  */
  // valid branches
  if (pt[0] >= 'A' and pt[0] <= 'Z') {
    cMsg ++;
    struct mentry *e = (struct mentry*)malloc(sizeof(struct mentry));

    if (!e) {
      printf("[ERROR] HEAP EXAUSTED! (for *e)\n");
      abort();
    }

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
      else
        free(e);

      HASH_FIND(hh, model, pt, EDGE_SIZE, k);
      if (k == NULL) {
        k = (struct mentry*)malloc(sizeof(struct mentry));
        if (!k) {
          printf("[ERROR] HEAP EXAUSTED! (for *k)\n");
          abort();
        }
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

void printEdge(char *edge) {
  // sizeof(edge) = EDGE_SIZE

  char t = edge[0];
  void *op1, *op2;

  memcpy(&op1, edge + 1, 8);
  memcpy(&op2, edge + 9, 8);

  printf("%c[%p, %p]", t, op1, op2);
}

void printModel() {
  struct mentry *e, *r;
  printf("Model:\n");
  for(e=model; e != NULL; e=(struct mentry*)e->hh.next) {
      // printf("%s: ", e->edge);
      printEdge(e->edge);
      printf(": ");
      if (e->edges) {
          for(r=e->edges; r != NULL; r=(struct mentry*)r->hh.next) {
            // printf("%s ", r->edge);
            printEdge(r->edge);
            printf(" ");
          }
      }
      printf("\n");

  }
}

void startConsumer() {
  unsigned long i = 0;
  char res;
  while(!*exit_loop) {
    // sleep(nap_time);
    // if (b->entries[i].status == RED) {
    //   // decrypt(unsigned char *b, size_t b_len, char *res)
    //   decrypt(b->entries[i].buf, ENTRY_SIZE, &res);
    //   *exit_loop = true;
    // }
    if (b->entries[i].status == BLACK) {
      decrypt(b->entries[i].buf, ENTRY_SIZE, &res);
      // *exit_loop = true;

      if (res == 'B')
        *exit_loop = true;

      b->entries[i].status = WHITE;

      // increase read counter
      i = (i + 1) % BUCKET_SIZE;
      //printf("enclave bucket[%s] = %d\n",i, b->entries[i].status);
    }
    if (b->entries[i].status == RED) {
      *exit_loop = true;
    }
    if (b->entries[i].status == WHITE || b->entries[i].status == GRAY)
      continue;
  }
}

void setBucket(bucket_t* b1, short* e1) {
  exit_loop = e1;
  b = b1;
}
