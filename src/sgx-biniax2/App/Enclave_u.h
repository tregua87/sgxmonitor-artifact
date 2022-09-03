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

#ifndef OCALL_WRITE_RESOURCE_DEFINED__
#define OCALL_WRITE_RESOURCE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write_resource, (const char* str, const void* bytes, size_t len));
#endif
#ifndef OCALL_WRITE_OUT_DEFINED__
#define OCALL_WRITE_OUT_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_write_out, (const void* bytes, size_t len));
#endif
#ifndef OCALL_PRINT_RAW_DEFINED__
#define OCALL_PRINT_RAW_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_raw, (const void* bytes, size_t len));
#endif
#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif

sgx_status_t init_store(sgx_enclave_id_t eid);
sgx_status_t free_store(sgx_enclave_id_t eid);
sgx_status_t add_to_store(sgx_enclave_id_t eid, const void* bytes, size_t len);
sgx_status_t get_from_store(sgx_enclave_id_t eid, void* out_var, size_t len, size_t index);
sgx_status_t encrypt_store(sgx_enclave_id_t eid, const char* fname);
sgx_status_t decrypt_store(sgx_enclave_id_t eid, const uint8_t* ebytes, size_t len);
sgx_status_t store_to_bytes(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
