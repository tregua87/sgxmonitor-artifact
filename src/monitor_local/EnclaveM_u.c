#include "EnclaveM_u.h"
#include <errno.h>

typedef struct ms_generateSecrets_t {
	unsigned char* ms_k;
	unsigned char* ms_nonce;
} ms_generateSecrets_t;

typedef struct ms_decrypt_t {
	unsigned char* ms_b;
	size_t ms_b_len;
	char* ms_res;
} ms_decrypt_t;

typedef struct ms_setBucketM_t {
	bucket_t* ms_b;
	short int* ms_exit_loop;
} ms_setBucketM_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

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

static sgx_status_t SGX_CDECL EnclaveM_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EnclaveM_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EnclaveM_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EnclaveM_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL EnclaveM_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[5];
} ocall_table_EnclaveM = {
	5,
	{
		(void*)EnclaveM_ocall_print_string,
		(void*)EnclaveM_sgx_thread_wait_untrusted_event_ocall,
		(void*)EnclaveM_sgx_thread_set_untrusted_event_ocall,
		(void*)EnclaveM_sgx_thread_setwait_untrusted_events_ocall,
		(void*)EnclaveM_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t generateSecrets(sgx_enclave_id_t eid, unsigned char* k, unsigned char* nonce)
{
	sgx_status_t status;
	ms_generateSecrets_t ms;
	ms.ms_k = k;
	ms.ms_nonce = nonce;
	status = sgx_ecall(eid, 0, &ocall_table_EnclaveM, &ms);
	return status;
}

sgx_status_t decrypt(sgx_enclave_id_t eid, unsigned char* b, size_t b_len, char* res)
{
	sgx_status_t status;
	ms_decrypt_t ms;
	ms.ms_b = b;
	ms.ms_b_len = b_len;
	ms.ms_res = res;
	status = sgx_ecall(eid, 1, &ocall_table_EnclaveM, &ms);
	return status;
}

sgx_status_t printModel(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 2, &ocall_table_EnclaveM, NULL);
	return status;
}

sgx_status_t startConsumer(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 3, &ocall_table_EnclaveM, NULL);
	return status;
}

sgx_status_t setBucketM(sgx_enclave_id_t eid, bucket_t* b, short int* exit_loop)
{
	sgx_status_t status;
	ms_setBucketM_t ms;
	ms.ms_b = b;
	ms.ms_exit_loop = exit_loop;
	status = sgx_ecall(eid, 4, &ocall_table_EnclaveM, &ms);
	return status;
}

