#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_pwnme(const char* str, size_t l);
int generateKeyEnclave(uint8_t* sealed_key, size_t sealedkey_len);
int loadKeyEnclave(uint8_t* key, size_t len);
int enclaveProcess(void* inQueue);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
