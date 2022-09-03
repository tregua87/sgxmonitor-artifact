#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_setBA_t {
	unsigned long int ms_basic_address;
} ms_setBA_t;

typedef struct ms_makeEndMsg_t {
	unsigned char* ms_strO;
	size_t ms_lenO;
} ms_makeEndMsg_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_monitorgatewayu_t {
	const char* ms_strI;
	size_t ms_lenI;
	char* ms_strO;
	size_t ms_lenO;
} ms_ocall_monitorgatewayu_t;

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

static const struct {
	size_t nr_ocall;
	void * table[2];
} ocall_table_Enclave = {
	2,
	{
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_ocall_monitorgatewayu,
	}
};
sgx_status_t hello1(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t setBA(sgx_enclave_id_t eid, unsigned long int basic_address)
{
	sgx_status_t status;
	ms_setBA_t ms;
	ms.ms_basic_address = basic_address;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t bootSecureCommunication(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t makeEndMsg(sgx_enclave_id_t eid, unsigned char* strO, size_t lenO)
{
	sgx_status_t status;
	ms_makeEndMsg_t ms;
	ms.ms_strO = strO;
	ms.ms_lenO = lenO;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	return status;
}

