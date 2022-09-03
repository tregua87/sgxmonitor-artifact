#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */

#include "Async_Bucket.h"

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
#ifndef OCALL_MONITORGATEWAYU_DEFINED__
#define OCALL_MONITORGATEWAYU_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_monitorgatewayu, (const char* strI, size_t lenI, char* strO, size_t lenO));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif

sgx_status_t init_store(sgx_enclave_id_t eid);
sgx_status_t free_store(sgx_enclave_id_t eid);
sgx_status_t add_to_store(sgx_enclave_id_t eid, const void* bytes, size_t len);
sgx_status_t get_from_store(sgx_enclave_id_t eid, void* out_var, size_t len, size_t index);
sgx_status_t encrypt_store(sgx_enclave_id_t eid, const char* fname);
sgx_status_t decrypt_store(sgx_enclave_id_t eid, const uint8_t* ebytes, size_t len);
sgx_status_t store_to_bytes(sgx_enclave_id_t eid);
sgx_status_t setBucket(sgx_enclave_id_t eid, bucket_t* b);
sgx_status_t setActionCounter(sgx_enclave_id_t eid, int* ac);
sgx_status_t bootSecureCommunication(sgx_enclave_id_t eid);
sgx_status_t makeEndMsg(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
