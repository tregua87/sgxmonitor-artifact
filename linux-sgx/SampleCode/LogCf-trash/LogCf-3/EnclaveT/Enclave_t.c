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


typedef struct ms_setBA_t {
	unsigned long int ms_basic_address;
} ms_setBA_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_monitorgatewayu_t {
	const char* ms_strI;
	size_t ms_lenI;
	char* ms_strO;
	size_t ms_lenO;
} ms_ocall_monitorgatewayu_t;

static sgx_status_t SGX_CDECL sgx_hello1(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	hello1();
	return status;
}

static sgx_status_t SGX_CDECL sgx_setBA(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_setBA_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_setBA_t* ms = SGX_CAST(ms_setBA_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	setBA(ms->ms_basic_address);


	return status;
}

static sgx_status_t SGX_CDECL sgx_bootSecureCommunication(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	bootSecureCommunication();
	return status;
}

static sgx_status_t SGX_CDECL sgx_makeEndMsg(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	makeEndMsg();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[4];
} g_ecall_table = {
	4,
	{
		{(void*)(uintptr_t)sgx_hello1, 0},
		{(void*)(uintptr_t)sgx_setBA, 0},
		{(void*)(uintptr_t)sgx_bootSecureCommunication, 0},
		{(void*)(uintptr_t)sgx_makeEndMsg, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[2][4];
} g_dyn_entry_table = {
	2,
	{
		{0, 0, 0, 0, },
		{0, 0, 0, 0, },
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

sgx_status_t SGX_CDECL ocall_monitorgatewayu(const char* strI, size_t lenI, char* strO, size_t lenO)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_strI = lenI * sizeof(char);
	size_t _len_strO = lenO * sizeof(char);

	ms_ocall_monitorgatewayu_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_monitorgatewayu_t);
	void *__tmp = NULL;

	void *__tmp_strO = NULL;

	CHECK_ENCLAVE_POINTER(strI, _len_strI);
	CHECK_ENCLAVE_POINTER(strO, _len_strO);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (strI != NULL) ? _len_strI : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (strO != NULL) ? _len_strO : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_monitorgatewayu_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_monitorgatewayu_t));
	ocalloc_size -= sizeof(ms_ocall_monitorgatewayu_t);

	if (strI != NULL) {
		ms->ms_strI = (const char*)__tmp;
		if (_len_strI % sizeof(*strI) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, strI, _len_strI)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_strI);
		ocalloc_size -= _len_strI;
	} else {
		ms->ms_strI = NULL;
	}
	
	ms->ms_lenI = lenI;
	if (strO != NULL) {
		ms->ms_strO = (char*)__tmp;
		__tmp_strO = __tmp;
		if (_len_strO % sizeof(*strO) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_strO, 0, _len_strO);
		__tmp = (void *)((size_t)__tmp + _len_strO);
		ocalloc_size -= _len_strO;
	} else {
		ms->ms_strO = NULL;
	}
	
	ms->ms_lenO = lenO;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (strO) {
			if (memcpy_s((void*)strO, _len_strO, __tmp_strO, _len_strO)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

