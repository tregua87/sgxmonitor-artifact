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

void init_store(void);
void free_store(void);
void add_to_store(const void* bytes, size_t len);
void get_from_store(void* out_var, size_t len, size_t index);
void encrypt_store(const char* fname);
void decrypt_store(const uint8_t* ebytes, size_t len);
void store_to_bytes(void);

sgx_status_t SGX_CDECL ocall_write_resource(const char* str, const void* bytes, size_t len);
sgx_status_t SGX_CDECL ocall_write_out(const void* bytes, size_t len);
sgx_status_t SGX_CDECL ocall_print_raw(const void* bytes, size_t len);
sgx_status_t SGX_CDECL ocall_print_string(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
