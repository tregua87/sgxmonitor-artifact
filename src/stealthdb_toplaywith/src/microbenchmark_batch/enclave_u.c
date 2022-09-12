#include "enclave_u.h"
#include <errno.h>

typedef struct ms_ecall_pwnme_t {
	const char* ms_str;
	size_t ms_l;
} ms_ecall_pwnme_t;

typedef struct ms_generateKeyEnclave_t {
	int ms_retval;
	uint8_t* ms_sealed_key;
	size_t ms_sealedkey_len;
} ms_generateKeyEnclave_t;

typedef struct ms_loadKeyEnclave_t {
	int ms_retval;
	uint8_t* ms_key;
	size_t ms_len;
} ms_loadKeyEnclave_t;

typedef struct ms_enclaveProcess_t {
	int ms_retval;
	void* ms_inQueue;
} ms_enclaveProcess_t;

typedef struct ms_setBucket_t {
	bucket_t* ms_b;
} ms_setBucket_t;

typedef struct ms_setActionCounter_t {
	int* ms_ac;
} ms_setActionCounter_t;

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

static sgx_status_t SGX_CDECL enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_ocall_monitorgatewayu(void* pms)
{
	ms_ocall_monitorgatewayu_t* ms = SGX_CAST(ms_ocall_monitorgatewayu_t*, pms);
	ocall_monitorgatewayu(ms->ms_strI, ms->ms_lenI, ms->ms_strO, ms->ms_lenO);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[6];
} ocall_table_enclave = {
	6,
	{
		(void*)enclave_ocall_print_string,
		(void*)enclave_ocall_monitorgatewayu,
		(void*)enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t ecall_pwnme(sgx_enclave_id_t eid, const char* str, size_t l)
{
	sgx_status_t status;
	ms_ecall_pwnme_t ms;
	ms.ms_str = str;
	ms.ms_l = l;
	status = sgx_ecall(eid, 0, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t generateKeyEnclave(sgx_enclave_id_t eid, int* retval, uint8_t* sealed_key, size_t sealedkey_len)
{
	sgx_status_t status;
	ms_generateKeyEnclave_t ms;
	ms.ms_sealed_key = sealed_key;
	ms.ms_sealedkey_len = sealedkey_len;
	status = sgx_ecall(eid, 1, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t loadKeyEnclave(sgx_enclave_id_t eid, int* retval, uint8_t* key, size_t len)
{
	sgx_status_t status;
	ms_loadKeyEnclave_t ms;
	ms.ms_key = key;
	ms.ms_len = len;
	status = sgx_ecall(eid, 2, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t enclaveProcess(sgx_enclave_id_t eid, int* retval, void* inQueue)
{
	sgx_status_t status;
	ms_enclaveProcess_t ms;
	ms.ms_inQueue = inQueue;
	status = sgx_ecall(eid, 3, &ocall_table_enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t setBucket(sgx_enclave_id_t eid, bucket_t* b)
{
	sgx_status_t status;
	ms_setBucket_t ms;
	ms.ms_b = b;
	status = sgx_ecall(eid, 4, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t setActionCounter(sgx_enclave_id_t eid, int* ac)
{
	sgx_status_t status;
	ms_setActionCounter_t ms;
	ms.ms_ac = ac;
	status = sgx_ecall(eid, 5, &ocall_table_enclave, &ms);
	return status;
}

sgx_status_t bootSecureCommunication(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 6, &ocall_table_enclave, NULL);
	return status;
}

sgx_status_t makeEndMsg(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 7, &ocall_table_enclave, NULL);
	return status;
}

