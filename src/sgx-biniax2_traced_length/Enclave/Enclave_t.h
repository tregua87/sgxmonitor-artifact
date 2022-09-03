#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "Async_Bucket.h"

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
void setBucket(bucket_t* b);
void setActionCounter(int* ac);
void bootSecureCommunication(void);
void makeEndMsg(void);

sgx_status_t SGX_CDECL ocall_write_resource(const char* str, const void* bytes, size_t len);
sgx_status_t SGX_CDECL ocall_write_out(const void* bytes, size_t len);
sgx_status_t SGX_CDECL ocall_print_raw(const void* bytes, size_t len);
sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_monitorgatewayu(const char* strI, size_t lenI, char* strO, size_t lenO);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
