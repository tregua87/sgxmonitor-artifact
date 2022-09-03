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

void rsa_make_public(unsigned int* n, unsigned int* e);
void rsa_import_emit(unsigned int* n, unsigned int* e, unsigned char* ct, size_t* ct_len);
void rsa_read_decrypt(unsigned char* ct, size_t ct_len);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
