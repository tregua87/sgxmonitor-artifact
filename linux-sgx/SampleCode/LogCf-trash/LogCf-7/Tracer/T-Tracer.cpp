
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include <sgx_tcrypto.h>
#include <sgx_thread.h>

#include "Sock.h"
#include "crypto_utils.h"
#include "async_bucket.h"


#define EDGE_SIZE 10

unsigned long ba = 0x0;

static unsigned int n[REF_N_SIZE_IN_UINT] = { 0 };
static unsigned int e[REF_E_SIZE_IN_UINT] = { 0 };

static void* rsa_pub_key;

#define OPT_KEY_SIZE_BYTE 30
#define OPT_KEY_MAC_SIZE_BYTE 10

unsigned char opt_key[OPT_KEY_SIZE_BYTE] = { 0 };
static unsigned char nonce[REF_NONCE_SIZE] = { 0 };

static bucket* pub_bucket;

// void writeToBuffer(unsigned char*,size_t,entry_status);
void writeToBuffer(unsigned char*, size_t, entry_status = BLACK);
void nextNonce(void);

int printf_2(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

void makeEndMsg() {
  unsigned char msg[4] = "end";

  sgx_sha256_hash_t nonce_hash;

  // PRINT_ARR_2("[INFO] OPT key sender:\n", opt_key, OPT_KEY_SIZE_BYTE);

  unsigned char tmpp[EDGE_SIZE + OPT_KEY_SIZE_BYTE] = { 0 };
  memcpy(tmpp, msg, sizeof(msg));
  memcpy(tmpp + sizeof(msg), opt_key, OPT_KEY_SIZE_BYTE);
  // PRINT_ARR_2("[INFO] sender tmpp computed:\n", tmpp, sizeof(tmpp))

  unsigned char tmpc[OPT_KEY_MAC_SIZE_BYTE] = { 0 };
  sgx_sha256_msg((const uint8_t *)tmpp, sizeof(tmpp), &nonce_hash);
  memcpy(tmpc, nonce_hash, OPT_KEY_MAC_SIZE_BYTE);
  // PRINT_ARR_2("[INFO] mac sent:\n", tmpc, sizeof(tmpc))

  unsigned char ct[OPT_KEY_SIZE_BYTE] = { 0 };

  // actualy encryption phase!
  for (unsigned int i = 0; i < OPT_KEY_SIZE_BYTE; i++) {
    // this is for the edge
    if (i < sizeof(msg))
      ct[i] = msg[i] ^ opt_key[i];
    // this is for the mac
    else if (i >= sizeof(msg) && i < sizeof(msg) + OPT_KEY_SIZE_BYTE)
      ct[i] = tmpc[i-sizeof(msg)] ^ opt_key[i];
    // padding
    else
      ct[i] = 0 ^ opt_key[i];
  }

  sgx_sha256_msg((const uint8_t *)opt_key, OPT_KEY_SIZE_BYTE, &nonce_hash);
  // CHECK(ret_code, "sgx_sha256_msg");
  memcpy(opt_key, nonce_hash, OPT_KEY_SIZE_BYTE);

  // PRINT_ARR_2("[INFO] cypted text:\n", ct, OPT_KEY_SIZE_BYTE)


  if (USE_BUFFER)
    writeToBuffer(ct, OPT_KEY_SIZE_BYTE, RED);
  else
    ocall_monitorgatewayu((const char*)ct, OPT_KEY_SIZE_BYTE, 0, 0);

}

void setBucket(bucket *b) {
  pub_bucket = b;
}



void bootSecureCommunication(void) {
  char ret[BuffSize] = { 0 };
  // message to init the boot phase (i.e., asking for keys and nonce)
  const char* mInit = "BINIT";
  ocall_monitorgatewayu(mInit, strlen(mInit), ret, BuffSize);

  unsigned int tmp = 0;
  unsigned char c = 0;
  unsigned int x = 0;

  // PRINT_ARR_2("[INFO] ret", ret, BuffSize);

  printf_2("[INFO] Boot Secure Communicatin...\n");
  memcpy(opt_key, ret, OPT_KEY_SIZE_BYTE);
  PRINT_ARR_2("[INFO] decoded OPT KEY\n", opt_key, OPT_KEY_SIZE_BYTE);
  // PRINT_ARR_2("\ndecoded E:\n" ,e ,REF_E_SIZE_IN_UINT);
  // PRINT_ARR_2("decoded N:\n" ,n ,REF_N_SIZE_IN_UINT);

  memcpy(nonce, ret + OPT_KEY_SIZE_BYTE, REF_NONCE_SIZE);
  PRINT_ARR_2("[INFO] decoded nonce:\n", nonce, REF_NONCE_SIZE);

  printf_2("[INFO] Secure communication: DONE!\n");
}

void traceedgec(void* to) {
  sgx_status_t ret_code = SGX_ERROR_UNEXPECTED;

  void* from =  __builtin_return_address(0);

  char buf_pt[OPT_KEY_SIZE_BYTE] = { 0 };
  size_t buf_pt_len = sizeof(buf_pt);
  const char* fmt = "E%04lx%04lx";
  snprintf(buf_pt, sizeof(buf_pt), fmt, (unsigned long)from -ba, (unsigned long)to - ba);

  sgx_sha256_hash_t nonce_hash;

  // PRINT_ARR_2("[INFO] OPT key sender:\n", opt_key, OPT_KEY_SIZE_BYTE);

  unsigned char tmpp[EDGE_SIZE + OPT_KEY_SIZE_BYTE] = { 0 };
  memcpy(tmpp, buf_pt, EDGE_SIZE);
  memcpy(tmpp + EDGE_SIZE, opt_key, OPT_KEY_SIZE_BYTE);
  // PRINT_ARR_2("[INFO] sender tmpp computed:\n", tmpp, sizeof(tmpp))

  unsigned char tmpc[OPT_KEY_MAC_SIZE_BYTE] = { 0 };
  sgx_sha256_msg((const uint8_t *)tmpp, sizeof(tmpp), &nonce_hash);
  memcpy(tmpc, nonce_hash, OPT_KEY_MAC_SIZE_BYTE);
  // PRINT_ARR_2("[INFO] mac sent:\n", tmpc, sizeof(tmpc))

  unsigned char ct[OPT_KEY_SIZE_BYTE] = { 0 };

  // actualy encryption phase!
  for (unsigned int i = 0; i < OPT_KEY_SIZE_BYTE; i++) {
    // this is for the edge
    if (i < EDGE_SIZE)
      ct[i] = buf_pt[i] ^ opt_key[i];
    // this is for the mac
    else if (i >= EDGE_SIZE && i < EDGE_SIZE + OPT_KEY_SIZE_BYTE)
      ct[i] = tmpc[i-EDGE_SIZE] ^ opt_key[i];
    // padding
    else
      ct[i] = 0 ^ opt_key[i];
  }

  sgx_sha256_msg((const uint8_t *)opt_key, OPT_KEY_SIZE_BYTE, &nonce_hash);
  // CHECK(ret_code, "sgx_sha256_msg");
  memcpy(opt_key, nonce_hash, OPT_KEY_SIZE_BYTE);

  // PRINT_ARR_2("[INFO] cypted text:\n", ct, OPT_KEY_SIZE_BYTE)

  // printf_2("\n");

  if (USE_BUFFER)
    writeToBuffer(ct, OPT_KEY_SIZE_BYTE);
  else
    ocall_monitorgatewayu((const char*)ct, OPT_KEY_SIZE_BYTE, 0, 0);

  nextNonce();
}

void setBA(unsigned long basic_address) {
  ba = basic_address;
}

static sgx_thread_mutex_t global_mutex = SGX_THREAD_MUTEX_INITIALIZER;

void writeToBuffer(unsigned char *str, size_t str_len, entry_status A_COLOR) {
  // write in the buffer outside
  // INPUT: - buf_ct is the encrypted buffer
  //        - buf_ct_len is the length of the encrypted buffer

  do {
    if (pub_bucket->entries[pub_bucket->idx].status == WHITE) {
      sgx_thread_mutex_lock(&global_mutex);
      if (pub_bucket->entries[pub_bucket->idx].status != WHITE) {
        sgx_thread_mutex_unlock(&global_mutex);
        continue;
      }
      pub_bucket->entries[pub_bucket->idx].status = GRAY;
      memcpy(pub_bucket->entries[pub_bucket->idx].buf, str, str_len);
      // usually BLACK, that's RED when the ecall ends
      pub_bucket->entries[pub_bucket->idx].status = A_COLOR;
      pub_bucket->idx = (pub_bucket->idx + 1) % BUCKET_SIZE;
      sgx_thread_mutex_unlock(&global_mutex);
      break;
    }
  } while(1);
}

void nextNonce() {
  sgx_sha256_hash_t nonce_hash;
  sgx_status_t ret_code = sgx_sha256_msg((const uint8_t *)nonce, REF_NONCE_SIZE, &nonce_hash);
  // CHECK(ret_code, "sgx_sha256_msg");
  memcpy(nonce, nonce_hash, REF_NONCE_SIZE);
}
