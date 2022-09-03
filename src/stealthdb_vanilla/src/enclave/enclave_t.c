#include "enclave_t.h"

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

static sgx_status_t SGX_CDECL sgx_ecall_pwnme(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_pwnme_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_pwnme_t* ms = SGX_CAST(ms_ecall_pwnme_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_str = ms->ms_str;
	size_t _tmp_l = ms->ms_l;
	size_t _len_str = _tmp_l;
	char* _in_str = NULL;

	CHECK_UNIQUE_POINTER(_tmp_str, _len_str);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_str != NULL && _len_str != 0) {
		if ( _len_str % sizeof(*_tmp_str) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_str = (char*)malloc(_len_str);
		if (_in_str == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_str, _len_str, _tmp_str, _len_str)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ecall_pwnme((const char*)_in_str, _tmp_l);

err:
	if (_in_str) free(_in_str);
	return status;
}

static sgx_status_t SGX_CDECL sgx_generateKeyEnclave(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_generateKeyEnclave_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_generateKeyEnclave_t* ms = SGX_CAST(ms_generateKeyEnclave_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_sealed_key = ms->ms_sealed_key;
	size_t _tmp_sealedkey_len = ms->ms_sealedkey_len;
	size_t _len_sealed_key = _tmp_sealedkey_len;
	uint8_t* _in_sealed_key = NULL;

	CHECK_UNIQUE_POINTER(_tmp_sealed_key, _len_sealed_key);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_sealed_key != NULL && _len_sealed_key != 0) {
		if ( _len_sealed_key % sizeof(*_tmp_sealed_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_sealed_key = (uint8_t*)malloc(_len_sealed_key)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_sealed_key, 0, _len_sealed_key);
	}

	ms->ms_retval = generateKeyEnclave(_in_sealed_key, _tmp_sealedkey_len);
	if (_in_sealed_key) {
		if (memcpy_s(_tmp_sealed_key, _len_sealed_key, _in_sealed_key, _len_sealed_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_sealed_key) free(_in_sealed_key);
	return status;
}

static sgx_status_t SGX_CDECL sgx_loadKeyEnclave(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_loadKeyEnclave_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_loadKeyEnclave_t* ms = SGX_CAST(ms_loadKeyEnclave_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_key = ms->ms_key;
	size_t _tmp_len = ms->ms_len;
	size_t _len_key = _tmp_len;
	uint8_t* _in_key = NULL;

	CHECK_UNIQUE_POINTER(_tmp_key, _len_key);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_key != NULL && _len_key != 0) {
		if ( _len_key % sizeof(*_tmp_key) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_key = (uint8_t*)malloc(_len_key);
		if (_in_key == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_key, _len_key, _tmp_key, _len_key)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = loadKeyEnclave(_in_key, _tmp_len);

err:
	if (_in_key) free(_in_key);
	return status;
}

static sgx_status_t SGX_CDECL sgx_enclaveProcess(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_enclaveProcess_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_enclaveProcess_t* ms = SGX_CAST(ms_enclaveProcess_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_inQueue = ms->ms_inQueue;



	ms->ms_retval = enclaveProcess(_tmp_inQueue);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_ecall_pwnme, 0},
		{(void*)(uintptr_t)sgx_generateKeyEnclave, 0},
		{(void*)(uintptr_t)sgx_loadKeyEnclave, 0},
		{(void*)(uintptr_t)sgx_enclaveProcess, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
} g_dyn_entry_table = {
	0,
};


