#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_testEcall1_t {
	int ms_retval;
	char ms_a;
	int ms_b;
	float ms_c;
	double ms_d;
	size_t ms_e;
	wchar_t ms_f;
} ms_testEcall1_t;

typedef struct ms_testEcall2_t {
	int ms_retval;
	struct struct_t ms_a;
	enum enum_t ms_b;
	enum enum_t ms_c;
	enum enum_t ms_d;
	union union_t ms_u;
} ms_testEcall2_t;

typedef struct ms_testEcall3_t {
	int ms_retval;
	int* ms_a;
	int* ms_b;
	int* ms_c;
} ms_testEcall3_t;

typedef struct ms_testEcall4_t {
	int ms_retval;
	char* ms_s1;
	size_t ms_s1_len;
	const char* ms_s2;
	size_t ms_s2_len;
	char* ms_s3;
	size_t ms_s3_len;
} ms_testEcall4_t;

typedef struct ms_testOcallSimple_t {
	int ms_retval;
	char ms_dummy;
} ms_testOcallSimple_t;

typedef struct ms_testEcallNested1_t {
	int ms_retval;
	int ms_level;
	int* ms_a;
	int* ms_b;
} ms_testEcallNested1_t;

typedef struct ms_testEcallNested2_t {
	int ms_retval;
	int ms_level;
	int* ms_a;
	int* ms_b;
} ms_testEcallNested2_t;

typedef struct ms_testEcallRecursive_t {
	int ms_retval;
	int ms_level;
	int* ms_a;
	int* ms_b;
} ms_testEcallRecursive_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall1_t {
	int ms_retval;
	char ms_a;
	int ms_b;
	float ms_c;
	double ms_d;
	size_t ms_e;
	wchar_t ms_f;
} ms_ocall1_t;

typedef struct ms_ocall2_t {
	int ms_retval;
	struct struct_t ms_a;
	enum enum_t ms_b;
	enum enum_t ms_c;
	enum enum_t ms_d;
	union union_t ms_u;
} ms_ocall2_t;

typedef struct ms_ocall3_t {
	int ms_retval;
	int* ms_a;
	int* ms_b;
	int* ms_c;
} ms_ocall3_t;

typedef struct ms_testOcallNested1_t {
	int ms_retval;
	int ms_level;
	int* ms_a;
	int* ms_b;
} ms_testOcallNested1_t;

typedef struct ms_testOcallNested2_t {
	int ms_retval;
	int ms_level;
	int* ms_a;
	int* ms_b;
} ms_testOcallNested2_t;

typedef struct ms_testOcallRecursive_t {
	int ms_retval;
	int ms_level;
	int* ms_a;
	int* ms_b;
} ms_testOcallRecursive_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall0(void* pms)
{
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ocall0();
	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall1(void* pms)
{
	ms_ocall1_t* ms = SGX_CAST(ms_ocall1_t*, pms);
	ms->ms_retval = ocall1(ms->ms_a, ms->ms_b, ms->ms_c, ms->ms_d, ms->ms_e, ms->ms_f);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall2(void* pms)
{
	ms_ocall2_t* ms = SGX_CAST(ms_ocall2_t*, pms);
	ms->ms_retval = ocall2(ms->ms_a, ms->ms_b, ms->ms_c, ms->ms_d, ms->ms_u);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall3(void* pms)
{
	ms_ocall3_t* ms = SGX_CAST(ms_ocall3_t*, pms);
	ms->ms_retval = ocall3(ms->ms_a, ms->ms_b, ms->ms_c);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_testOcallNested1(void* pms)
{
	ms_testOcallNested1_t* ms = SGX_CAST(ms_testOcallNested1_t*, pms);
	ms->ms_retval = testOcallNested1(ms->ms_level, ms->ms_a, ms->ms_b);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_testOcallNested2(void* pms)
{
	ms_testOcallNested2_t* ms = SGX_CAST(ms_testOcallNested2_t*, pms);
	ms->ms_retval = testOcallNested2(ms->ms_level, ms->ms_a, ms->ms_b);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_testOcallRecursive(void* pms)
{
	ms_testOcallRecursive_t* ms = SGX_CAST(ms_testOcallRecursive_t*, pms);
	ms->ms_retval = testOcallRecursive(ms->ms_level, ms->ms_a, ms->ms_b);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[8];
} ocall_table_Enclave = {
	8,
	{
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_ocall0,
		(void*)Enclave_ocall1,
		(void*)Enclave_ocall2,
		(void*)Enclave_ocall3,
		(void*)Enclave_testOcallNested1,
		(void*)Enclave_testOcallNested2,
		(void*)Enclave_testOcallRecursive,
	}
};
sgx_status_t testEcall0(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t testEcall1(sgx_enclave_id_t eid, int* retval, char a, int b, float c, double d, size_t e, wchar_t f)
{
	sgx_status_t status;
	ms_testEcall1_t ms;
	ms.ms_a = a;
	ms.ms_b = b;
	ms.ms_c = c;
	ms.ms_d = d;
	ms.ms_e = e;
	ms.ms_f = f;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t testEcall2(sgx_enclave_id_t eid, int* retval, struct struct_t a, enum enum_t b, enum enum_t c, enum enum_t d, union union_t u)
{
	sgx_status_t status;
	ms_testEcall2_t ms;
	ms.ms_a = a;
	ms.ms_b = b;
	ms.ms_c = c;
	ms.ms_d = d;
	ms.ms_u = u;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t testEcall3(sgx_enclave_id_t eid, int* retval, int a[2], int b[2], int c[2])
{
	sgx_status_t status;
	ms_testEcall3_t ms;
	ms.ms_a = (int*)a;
	ms.ms_b = (int*)b;
	ms.ms_c = (int*)c;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t testEcall4(sgx_enclave_id_t eid, int* retval, char* s1, const char* s2, char* s3)
{
	sgx_status_t status;
	ms_testEcall4_t ms;
	ms.ms_s1 = s1;
	ms.ms_s1_len = s1 ? strlen(s1) + 1 : 0;
	ms.ms_s2 = s2;
	ms.ms_s2_len = s2 ? strlen(s2) + 1 : 0;
	ms.ms_s3 = s3;
	ms.ms_s3_len = s3 ? strlen(s3) + 1 : 0;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t testOcallSimple(sgx_enclave_id_t eid, int* retval, char dummy)
{
	sgx_status_t status;
	ms_testOcallSimple_t ms;
	ms.ms_dummy = dummy;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t testEcallNested1(sgx_enclave_id_t eid, int* retval, int level, int a[2], int b[2])
{
	sgx_status_t status;
	ms_testEcallNested1_t ms;
	ms.ms_level = level;
	ms.ms_a = (int*)a;
	ms.ms_b = (int*)b;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t testEcallNested2(sgx_enclave_id_t eid, int* retval, int level, int a[2], int b[2])
{
	sgx_status_t status;
	ms_testEcallNested2_t ms;
	ms.ms_level = level;
	ms.ms_a = (int*)a;
	ms.ms_b = (int*)b;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t testEcallRecursive(sgx_enclave_id_t eid, int* retval, int level, int a[2], int b[2])
{
	sgx_status_t status;
	ms_testEcallRecursive_t ms;
	ms.ms_level = level;
	ms.ms_a = (int*)a;
	ms.ms_b = (int*)b;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

