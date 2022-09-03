#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_rsa_make_public_t {
	unsigned int* ms_n;
	unsigned int* ms_e;
} ms_rsa_make_public_t;

typedef struct ms_rsa_import_emit_t {
	unsigned int* ms_n;
	unsigned int* ms_e;
	unsigned char* ms_ct;
	size_t* ms_ct_len;
} ms_rsa_import_emit_t;

typedef struct ms_rsa_read_decrypt_t {
	unsigned char* ms_ct;
	size_t ms_ct_len;
} ms_rsa_read_decrypt_t;

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
sgx_status_t rsa_make_public(sgx_enclave_id_t eid, unsigned int* n, unsigned int* e)
{
	sgx_status_t status;
	ms_rsa_make_public_t ms;
	ms.ms_n = n;
	ms.ms_e = e;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t rsa_import_emit(sgx_enclave_id_t eid, unsigned int* n, unsigned int* e, unsigned char* ct, size_t* ct_len)
{
	sgx_status_t status;
	ms_rsa_import_emit_t ms;
	ms.ms_n = n;
	ms.ms_e = e;
	ms.ms_ct = ct;
	ms.ms_ct_len = ct_len;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t rsa_read_decrypt(sgx_enclave_id_t eid, unsigned char* ct, size_t ct_len)
{
	sgx_status_t status;
	ms_rsa_read_decrypt_t ms;
	ms.ms_ct = ct;
	ms.ms_ct_len = ct_len;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	return status;
}

