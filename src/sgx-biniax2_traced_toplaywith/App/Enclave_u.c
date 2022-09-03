#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_add_to_store_t {
	const void* ms_bytes;
	size_t ms_len;
} ms_add_to_store_t;

typedef struct ms_get_from_store_t {
	void* ms_out_var;
	size_t ms_len;
	size_t ms_index;
} ms_get_from_store_t;

typedef struct ms_encrypt_store_t {
	const char* ms_fname;
	size_t ms_fname_len;
} ms_encrypt_store_t;

typedef struct ms_decrypt_store_t {
	const uint8_t* ms_ebytes;
	size_t ms_len;
} ms_decrypt_store_t;

typedef struct ms_setBucket_t {
	bucket_t* ms_b;
} ms_setBucket_t;

typedef struct ms_setActionCounter_t {
	int* ms_ac;
} ms_setActionCounter_t;

typedef struct ms_ocall_write_resource_t {
	const char* ms_str;
	const void* ms_bytes;
	size_t ms_len;
} ms_ocall_write_resource_t;

typedef struct ms_ocall_write_out_t {
	const void* ms_bytes;
	size_t ms_len;
} ms_ocall_write_out_t;

typedef struct ms_ocall_print_raw_t {
	const void* ms_bytes;
	size_t ms_len;
} ms_ocall_print_raw_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_monitorgatewayu_t {
	const char* ms_strI;
	size_t ms_lenI;
	char* ms_strO;
	size_t ms_lenO;
} ms_ocall_monitorgatewayu_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL Enclave_ocall_write_resource(void* pms)
{
	ms_ocall_write_resource_t* ms = SGX_CAST(ms_ocall_write_resource_t*, pms);
	ocall_write_resource(ms->ms_str, ms->ms_bytes, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_write_out(void* pms)
{
	ms_ocall_write_out_t* ms = SGX_CAST(ms_ocall_write_out_t*, pms);
	ocall_write_out(ms->ms_bytes, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print_raw(void* pms)
{
	ms_ocall_print_raw_t* ms = SGX_CAST(ms_ocall_print_raw_t*, pms);
	ocall_print_raw(ms->ms_bytes, ms->ms_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_monitorgatewayu(void* pms)
{
	ms_ocall_monitorgatewayu_t* ms = SGX_CAST(ms_ocall_monitorgatewayu_t*, pms);
	ocall_monitorgatewayu(ms->ms_strI, ms->ms_lenI, ms->ms_strO, ms->ms_lenO);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[9];
} ocall_table_Enclave = {
	9,
	{
		(void*)Enclave_ocall_write_resource,
		(void*)Enclave_ocall_write_out,
		(void*)Enclave_ocall_print_raw,
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_ocall_monitorgatewayu,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t init_store(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t free_store(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t add_to_store(sgx_enclave_id_t eid, const void* bytes, size_t len)
{
	sgx_status_t status;
	ms_add_to_store_t ms;
	ms.ms_bytes = bytes;
	ms.ms_len = len;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t get_from_store(sgx_enclave_id_t eid, void* out_var, size_t len, size_t index)
{
	sgx_status_t status;
	ms_get_from_store_t ms;
	ms.ms_out_var = out_var;
	ms.ms_len = len;
	ms.ms_index = index;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t encrypt_store(sgx_enclave_id_t eid, const char* fname)
{
	sgx_status_t status;
	ms_encrypt_store_t ms;
	ms.ms_fname = fname;
	ms.ms_fname_len = fname ? strlen(fname) + 1 : 0;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t decrypt_store(sgx_enclave_id_t eid, const uint8_t* ebytes, size_t len)
{
	sgx_status_t status;
	ms_decrypt_store_t ms;
	ms.ms_ebytes = ebytes;
	ms.ms_len = len;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t store_to_bytes(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t setBucket(sgx_enclave_id_t eid, bucket_t* b)
{
	sgx_status_t status;
	ms_setBucket_t ms;
	ms.ms_b = b;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t setActionCounter(sgx_enclave_id_t eid, int* ac)
{
	sgx_status_t status;
	ms_setActionCounter_t ms;
	ms.ms_ac = ac;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t bootSecureCommunication(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 9, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t makeEndMsg(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 10, &ocall_table_Enclave, NULL);
	return status;
}

