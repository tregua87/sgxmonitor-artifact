#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_hello1_t {
	int ms_x;
} ms_hello1_t;

typedef struct ms_test_exception_t {
	int ms_retval;
	int ms_i;
} ms_test_exception_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	1,
	{
		(void*)Enclave_ocall_print_string,
	}
};
sgx_status_t hello1(sgx_enclave_id_t eid, int x)
{
	sgx_status_t status;
	ms_hello1_t ms;
	ms.ms_x = x;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t hello2(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t test_exception(sgx_enclave_id_t eid, int* retval, int i)
{
	sgx_status_t status;
	ms_test_exception_t ms;
	ms.ms_i = i;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

