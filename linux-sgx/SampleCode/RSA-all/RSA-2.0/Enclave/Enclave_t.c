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

static sgx_status_t SGX_CDECL sgx_rsa_make_public(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_rsa_make_public_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_rsa_make_public_t* ms = SGX_CAST(ms_rsa_make_public_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned int* _tmp_n = ms->ms_n;
	unsigned int* _tmp_e = ms->ms_e;



	rsa_make_public(_tmp_n, _tmp_e);


	return status;
}

static sgx_status_t SGX_CDECL sgx_rsa_import_emit(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_rsa_import_emit_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_rsa_import_emit_t* ms = SGX_CAST(ms_rsa_import_emit_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned int* _tmp_n = ms->ms_n;
	unsigned int* _tmp_e = ms->ms_e;
	unsigned char* _tmp_ct = ms->ms_ct;
	size_t* _tmp_ct_len = ms->ms_ct_len;



	rsa_import_emit(_tmp_n, _tmp_e, _tmp_ct, _tmp_ct_len);


	return status;
}

static sgx_status_t SGX_CDECL sgx_rsa_read_decrypt(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_rsa_read_decrypt_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_rsa_read_decrypt_t* ms = SGX_CAST(ms_rsa_read_decrypt_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	unsigned char* _tmp_ct = ms->ms_ct;



	rsa_read_decrypt(_tmp_ct, ms->ms_ct_len);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[3];
} g_ecall_table = {
	3,
	{
		{(void*)(uintptr_t)sgx_rsa_make_public, 0},
		{(void*)(uintptr_t)sgx_rsa_import_emit, 0},
		{(void*)(uintptr_t)sgx_rsa_read_decrypt, 0},
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

