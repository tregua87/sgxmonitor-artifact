#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "sabd.h"
#include "stdbool.h"
#include "sgx_quote.h"
#include "sgx_report.h"
#include "sgxsd.h"
#include "Async_Bucket.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

sgx_status_t sgxsd_enclave_node_init(const sgxsd_node_init_args_t* p_args);
sgx_status_t sgxsd_enclave_get_next_report(sgx_target_info_t qe_target_info, sgx_report_t* p_report);
sgx_status_t sgxsd_enclave_set_current_quote(void);
sgx_status_t sgxsd_enclave_negotiate_request(const sgxsd_request_negotiation_request_t* p_request, sgxsd_request_negotiation_response_t* p_response);
sgx_status_t sgxsd_enclave_server_start(const sgxsd_server_init_args_t* p_args, sgxsd_server_state_handle_t state_handle);
sgx_status_t sgxsd_enclave_server_call(const sgxsd_server_handle_call_args_t* p_args, const sgxsd_msg_header_t* msg_header, uint8_t* msg_data, size_t msg_size, sgxsd_msg_tag_t msg_tag, sgxsd_server_state_handle_t state_handle);
sgx_status_t sgxsd_enclave_server_stop(const sgxsd_server_terminate_args_t* p_args, sgxsd_server_state_handle_t state_handle);
void setBucket(bucket_t* b);
void setActionCounter(int* ac);
void bootSecureCommunication(void);
void makeEndMsg(void);

sgx_status_t SGX_CDECL sgxsd_ocall_reply(sgx_status_t* retval, const sgxsd_msg_header_t* reply_header, const uint8_t* reply_data, size_t reply_data_size, sgxsd_msg_tag_t msg_tag);
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
