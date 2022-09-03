#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_testOcalls_t {
	size_t ms_amount_of_ocalls;
	size_t ms_max;
} ms_testOcalls_t;

typedef struct ms_testEcalls_t {
	int ms_dummy;
} ms_testEcalls_t;

typedef struct ms_testOcallsSingle_t {
	int ms_dummy;
} ms_testOcallsSingle_t;

typedef struct ms_testOcall_t {
	int ms_dummy;
} ms_testOcall_t;

static sgx_status_t SGX_CDECL Enclave_testOcall(void* pms)
{
	ms_testOcall_t* ms = SGX_CAST(ms_testOcall_t*, pms);
	testOcall(ms->ms_dummy);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	1,
	{
		(void*)Enclave_testOcall,
	}
};
sgx_status_t testOcalls(sgx_enclave_id_t eid, size_t amount_of_ocalls, size_t max)
{
	sgx_status_t status;
	ms_testOcalls_t ms;
	ms.ms_amount_of_ocalls = amount_of_ocalls;
	ms.ms_max = max;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t testEcalls(sgx_enclave_id_t eid, int dummy)
{
	sgx_status_t status;
	ms_testEcalls_t ms;
	ms.ms_dummy = dummy;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t testOcallsSingle(sgx_enclave_id_t eid, int dummy)
{
	sgx_status_t status;
	ms_testOcallsSingle_t ms;
	ms.ms_dummy = dummy;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

