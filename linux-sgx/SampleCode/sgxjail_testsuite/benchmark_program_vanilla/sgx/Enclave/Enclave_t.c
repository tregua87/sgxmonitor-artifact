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

static sgx_status_t SGX_CDECL sgx_testOcalls(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_testOcalls_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_testOcalls_t* ms = SGX_CAST(ms_testOcalls_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	testOcalls(ms->ms_amount_of_ocalls, ms->ms_max);


	return status;
}

static sgx_status_t SGX_CDECL sgx_testEcalls(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_testEcalls_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_testEcalls_t* ms = SGX_CAST(ms_testEcalls_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	testEcalls(ms->ms_dummy);


	return status;
}

static sgx_status_t SGX_CDECL sgx_testOcallsSingle(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_testOcallsSingle_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_testOcallsSingle_t* ms = SGX_CAST(ms_testOcallsSingle_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	testOcallsSingle(ms->ms_dummy);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[3];
} g_ecall_table = {
	3,
	{
		{(void*)(uintptr_t)sgx_testOcalls, 0},
		{(void*)(uintptr_t)sgx_testEcalls, 0},
		{(void*)(uintptr_t)sgx_testOcallsSingle, 0},
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


sgx_status_t SGX_CDECL testOcall(int dummy)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_testOcall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_testOcall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_testOcall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_testOcall_t));
	ocalloc_size -= sizeof(ms_testOcall_t);

	ms->ms_dummy = dummy;
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

