#include "Enclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_generateSecrets(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_generateSecrets_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_generateSecrets_t* ms = SGX_CAST(ms_generateSecrets_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_k = ms->ms_k;
	unsigned char* _tmp_nonce = ms->ms_nonce;



	generateSecrets(_tmp_k, _tmp_nonce);


	return status;
}

static sgx_status_t SGX_CDECL sgx_decrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_decrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_decrypt_t* ms = SGX_CAST(ms_decrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_b = ms->ms_b;
	size_t _tmp_b_len = ms->ms_b_len;
	size_t _len_b = _tmp_b_len;
	unsigned char* _in_b = NULL;
	char* _tmp_res = ms->ms_res;
	size_t _len_res = 1;
	char* _in_res = NULL;

	CHECK_UNIQUE_POINTER(_tmp_b, _len_b);
	CHECK_UNIQUE_POINTER(_tmp_res, _len_res);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_b != NULL && _len_b != 0) {
		if ( _len_b % sizeof(*_tmp_b) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_b = (unsigned char*)malloc(_len_b);
		if (_in_b == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_b, _len_b, _tmp_b, _len_b)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_res != NULL && _len_res != 0) {
		if ( _len_res % sizeof(*_tmp_res) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_res = (char*)malloc(_len_res)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_res, 0, _len_res);
	}

	decrypt(_in_b, _tmp_b_len, _in_res);
	if (_in_res) {
		if (memcpy_s(_tmp_res, _len_res, _in_res, _len_res)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_b) free(_in_b);
	if (_in_res) free(_in_res);
	return status;
}

static sgx_status_t SGX_CDECL sgx_printModel(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	printModel();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[3];
} g_ecall_table = {
	3,
	{
		{(void*)(uintptr_t)sgx_generateSecrets, 0},
		{(void*)(uintptr_t)sgx_decrypt, 0},
		{(void*)(uintptr_t)sgx_printModel, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[1][3];
} g_dyn_entry_table = {
	1,
	{
		{0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

