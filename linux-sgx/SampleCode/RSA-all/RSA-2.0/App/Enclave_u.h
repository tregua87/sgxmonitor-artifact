#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif

sgx_status_t rsa_make_public(sgx_enclave_id_t eid, unsigned int* n, unsigned int* e);
sgx_status_t rsa_import_emit(sgx_enclave_id_t eid, unsigned int* n, unsigned int* e, unsigned char* ct, size_t* ct_len);
sgx_status_t rsa_read_decrypt(sgx_enclave_id_t eid, unsigned char* ct, size_t ct_len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
