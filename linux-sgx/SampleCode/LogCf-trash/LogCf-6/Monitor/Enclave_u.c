#include "Enclave_u.h"
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
sgx_status_t generateSecrets(sgx_enclave_id_t eid, unsigned char* k, unsigned char* nonce)
{
	sgx_status_t status;
	ms_generateSecrets_t ms;
	ms.ms_k = k;
	ms.ms_nonce = nonce;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t decrypt(sgx_enclave_id_t eid, unsigned char* b, size_t b_len, char* res)
{
	sgx_status_t status;
	ms_decrypt_t ms;
	ms.ms_b = b;
	ms.ms_b_len = b_len;
	ms.ms_res = res;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t printModel(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, NULL);
	return status;
}

