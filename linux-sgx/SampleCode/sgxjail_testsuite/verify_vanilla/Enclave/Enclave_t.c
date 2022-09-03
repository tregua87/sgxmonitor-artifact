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

static sgx_status_t SGX_CDECL sgx_testEcall0(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	testEcall0();
	return status;
}

static sgx_status_t SGX_CDECL sgx_testEcall1(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_testEcall1_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_testEcall1_t* ms = SGX_CAST(ms_testEcall1_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = testEcall1(ms->ms_a, ms->ms_b, ms->ms_c, ms->ms_d, ms->ms_e, ms->ms_f);


	return status;
}

static sgx_status_t SGX_CDECL sgx_testEcall2(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_testEcall2_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_testEcall2_t* ms = SGX_CAST(ms_testEcall2_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = testEcall2(ms->ms_a, ms->ms_b, ms->ms_c, ms->ms_d, ms->ms_u);


	return status;
}

static sgx_status_t SGX_CDECL sgx_testEcall3(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_testEcall3_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_testEcall3_t* ms = SGX_CAST(ms_testEcall3_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_a = ms->ms_a;
	size_t _len_a = 2 * sizeof(int);
	int* _in_a = NULL;
	int* _tmp_b = ms->ms_b;
	size_t _len_b = 2 * sizeof(int);
	int* _in_b = NULL;
	int* _tmp_c = ms->ms_c;
	size_t _len_c = 2 * sizeof(int);
	int* _in_c = NULL;

	CHECK_UNIQUE_POINTER(_tmp_a, _len_a);
	CHECK_UNIQUE_POINTER(_tmp_b, _len_b);
	CHECK_UNIQUE_POINTER(_tmp_c, _len_c);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_a != NULL && _len_a != 0) {
		if ( _len_a % sizeof(*_tmp_a) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_a = (int*)malloc(_len_a);
		if (_in_a == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_a, _len_a, _tmp_a, _len_a)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_b != NULL && _len_b != 0) {
		if ( _len_b % sizeof(*_tmp_b) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_b = (int*)malloc(_len_b)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_b, 0, _len_b);
	}
	if (_tmp_c != NULL && _len_c != 0) {
		if ( _len_c % sizeof(*_tmp_c) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_c = (int*)malloc(_len_c);
		if (_in_c == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_c, _len_c, _tmp_c, _len_c)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	ms->ms_retval = testEcall3(_in_a, _in_b, _in_c);
	if (_in_b) {
		if (memcpy_s(_tmp_b, _len_b, _in_b, _len_b)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_c) {
		if (memcpy_s(_tmp_c, _len_c, _in_c, _len_c)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_a) free(_in_a);
	if (_in_b) free(_in_b);
	if (_in_c) free(_in_c);
	return status;
}

static sgx_status_t SGX_CDECL sgx_testEcall4(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_testEcall4_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_testEcall4_t* ms = SGX_CAST(ms_testEcall4_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_s1 = ms->ms_s1;
	size_t _len_s1 = ms->ms_s1_len ;
	char* _in_s1 = NULL;
	const char* _tmp_s2 = ms->ms_s2;
	size_t _len_s2 = ms->ms_s2_len ;
	char* _in_s2 = NULL;
	char* _tmp_s3 = ms->ms_s3;
	size_t _len_s3 = ms->ms_s3_len ;
	char* _in_s3 = NULL;

	CHECK_UNIQUE_POINTER(_tmp_s1, _len_s1);
	CHECK_UNIQUE_POINTER(_tmp_s2, _len_s2);
	CHECK_UNIQUE_POINTER(_tmp_s3, _len_s3);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_s1 != NULL && _len_s1 != 0) {
		_in_s1 = (char*)malloc(_len_s1);
		if (_in_s1 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_s1, _len_s1, _tmp_s1, _len_s1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_s1[_len_s1 - 1] = '\0';
		if (_len_s1 != strlen(_in_s1) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_s2 != NULL && _len_s2 != 0) {
		_in_s2 = (char*)malloc(_len_s2);
		if (_in_s2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_s2, _len_s2, _tmp_s2, _len_s2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_s2[_len_s2 - 1] = '\0';
		if (_len_s2 != strlen(_in_s2) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_tmp_s3 != NULL && _len_s3 != 0) {
		_in_s3 = (char*)malloc(_len_s3);
		if (_in_s3 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_s3, _len_s3, _tmp_s3, _len_s3)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_s3[_len_s3 - 1] = '\0';
		if (_len_s3 != strlen(_in_s3) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	ms->ms_retval = testEcall4(_in_s1, (const char*)_in_s2, _in_s3);
	if (_in_s3)
	{
		_in_s3[_len_s3 - 1] = '\0';
		_len_s3 = strlen(_in_s3) + 1;
		if (memcpy_s((void*)_tmp_s3, _len_s3, _in_s3, _len_s3)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_s1) free(_in_s1);
	if (_in_s2) free(_in_s2);
	if (_in_s3) free(_in_s3);
	return status;
}

static sgx_status_t SGX_CDECL sgx_testOcallSimple(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_testOcallSimple_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_testOcallSimple_t* ms = SGX_CAST(ms_testOcallSimple_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = testOcallSimple(ms->ms_dummy);


	return status;
}

static sgx_status_t SGX_CDECL sgx_testEcallNested1(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_testEcallNested1_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_testEcallNested1_t* ms = SGX_CAST(ms_testEcallNested1_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_a = ms->ms_a;
	size_t _len_a = 2 * sizeof(int);
	int* _in_a = NULL;
	int* _tmp_b = ms->ms_b;
	size_t _len_b = 2 * sizeof(int);
	int* _in_b = NULL;

	CHECK_UNIQUE_POINTER(_tmp_a, _len_a);
	CHECK_UNIQUE_POINTER(_tmp_b, _len_b);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_a != NULL && _len_a != 0) {
		if ( _len_a % sizeof(*_tmp_a) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_a = (int*)malloc(_len_a);
		if (_in_a == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_a, _len_a, _tmp_a, _len_a)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_b != NULL && _len_b != 0) {
		if ( _len_b % sizeof(*_tmp_b) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_b = (int*)malloc(_len_b)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_b, 0, _len_b);
	}

	ms->ms_retval = testEcallNested1(ms->ms_level, _in_a, _in_b);
	if (_in_b) {
		if (memcpy_s(_tmp_b, _len_b, _in_b, _len_b)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_a) free(_in_a);
	if (_in_b) free(_in_b);
	return status;
}

static sgx_status_t SGX_CDECL sgx_testEcallNested2(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_testEcallNested2_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_testEcallNested2_t* ms = SGX_CAST(ms_testEcallNested2_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_a = ms->ms_a;
	size_t _len_a = 2 * sizeof(int);
	int* _in_a = NULL;
	int* _tmp_b = ms->ms_b;
	size_t _len_b = 2 * sizeof(int);
	int* _in_b = NULL;

	CHECK_UNIQUE_POINTER(_tmp_a, _len_a);
	CHECK_UNIQUE_POINTER(_tmp_b, _len_b);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_a != NULL && _len_a != 0) {
		if ( _len_a % sizeof(*_tmp_a) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_a = (int*)malloc(_len_a);
		if (_in_a == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_a, _len_a, _tmp_a, _len_a)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_b != NULL && _len_b != 0) {
		if ( _len_b % sizeof(*_tmp_b) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_b = (int*)malloc(_len_b)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_b, 0, _len_b);
	}

	ms->ms_retval = testEcallNested2(ms->ms_level, _in_a, _in_b);
	if (_in_b) {
		if (memcpy_s(_tmp_b, _len_b, _in_b, _len_b)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_a) free(_in_a);
	if (_in_b) free(_in_b);
	return status;
}

static sgx_status_t SGX_CDECL sgx_testEcallRecursive(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_testEcallRecursive_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_testEcallRecursive_t* ms = SGX_CAST(ms_testEcallRecursive_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_a = ms->ms_a;
	size_t _len_a = 2 * sizeof(int);
	int* _in_a = NULL;
	int* _tmp_b = ms->ms_b;
	size_t _len_b = 2 * sizeof(int);
	int* _in_b = NULL;

	CHECK_UNIQUE_POINTER(_tmp_a, _len_a);
	CHECK_UNIQUE_POINTER(_tmp_b, _len_b);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_a != NULL && _len_a != 0) {
		if ( _len_a % sizeof(*_tmp_a) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_a = (int*)malloc(_len_a);
		if (_in_a == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_a, _len_a, _tmp_a, _len_a)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_b != NULL && _len_b != 0) {
		if ( _len_b % sizeof(*_tmp_b) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_b = (int*)malloc(_len_b)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_b, 0, _len_b);
	}

	ms->ms_retval = testEcallRecursive(ms->ms_level, _in_a, _in_b);
	if (_in_b) {
		if (memcpy_s(_tmp_b, _len_b, _in_b, _len_b)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_a) free(_in_a);
	if (_in_b) free(_in_b);
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[9];
} g_ecall_table = {
	9,
	{
		{(void*)(uintptr_t)sgx_testEcall0, 0},
		{(void*)(uintptr_t)sgx_testEcall1, 0},
		{(void*)(uintptr_t)sgx_testEcall2, 0},
		{(void*)(uintptr_t)sgx_testEcall3, 0},
		{(void*)(uintptr_t)sgx_testEcall4, 0},
		{(void*)(uintptr_t)sgx_testOcallSimple, 0},
		{(void*)(uintptr_t)sgx_testEcallNested1, 0},
		{(void*)(uintptr_t)sgx_testEcallNested2, 0},
		{(void*)(uintptr_t)sgx_testEcallRecursive, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[8][9];
} g_dyn_entry_table = {
	8,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 1, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 1, },
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

sgx_status_t SGX_CDECL ocall0(void)
{
	sgx_status_t status = SGX_SUCCESS;
	status = sgx_ocall(1, NULL);

	return status;
}
sgx_status_t SGX_CDECL ocall1(int* retval, char a, int b, float c, double d, size_t e, wchar_t f)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall1_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall1_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall1_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall1_t));
	ocalloc_size -= sizeof(ms_ocall1_t);

	ms->ms_a = a;
	ms->ms_b = b;
	ms->ms_c = c;
	ms->ms_d = d;
	ms->ms_e = e;
	ms->ms_f = f;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall2(int* retval, struct struct_t a, enum enum_t b, enum enum_t c, enum enum_t d, union union_t u)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall2_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall2_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall2_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall2_t));
	ocalloc_size -= sizeof(ms_ocall2_t);

	ms->ms_a = a;
	ms->ms_b = b;
	ms->ms_c = c;
	ms->ms_d = d;
	ms->ms_u = u;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall3(int* retval, int a[2], int b[2], int c[2])
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_a = 2 * sizeof(int);
	size_t _len_b = 2 * sizeof(int);
	size_t _len_c = 2 * sizeof(int);

	ms_ocall3_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall3_t);
	void *__tmp = NULL;

	void *__tmp_b = NULL;
	void *__tmp_c = NULL;

	CHECK_ENCLAVE_POINTER(a, _len_a);
	CHECK_ENCLAVE_POINTER(b, _len_b);
	CHECK_ENCLAVE_POINTER(c, _len_c);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (a != NULL) ? _len_a : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (b != NULL) ? _len_b : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (c != NULL) ? _len_c : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall3_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall3_t));
	ocalloc_size -= sizeof(ms_ocall3_t);

	if (a != NULL) {
		ms->ms_a = (int*)__tmp;
		if (_len_a % sizeof(*a) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, a, _len_a)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_a);
		ocalloc_size -= _len_a;
	} else {
		ms->ms_a = NULL;
	}
	
	if (b != NULL) {
		ms->ms_b = (int*)__tmp;
		__tmp_b = __tmp;
		if (_len_b % sizeof(*b) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_b, 0, _len_b);
		__tmp = (void *)((size_t)__tmp + _len_b);
		ocalloc_size -= _len_b;
	} else {
		ms->ms_b = NULL;
	}
	
	if (c != NULL) {
		ms->ms_c = (int*)__tmp;
		__tmp_c = __tmp;
		if (_len_c % sizeof(*c) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp_c, ocalloc_size, c, _len_c)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_c);
		ocalloc_size -= _len_c;
	} else {
		ms->ms_c = NULL;
	}
	
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (b) {
			if (memcpy_s((void*)b, _len_b, __tmp_b, _len_b)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (c) {
			if (memcpy_s((void*)c, _len_c, __tmp_c, _len_c)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL testOcallNested1(int* retval, int level, int a[2], int b[2])
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_a = 2 * sizeof(int);
	size_t _len_b = 2 * sizeof(int);

	ms_testOcallNested1_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_testOcallNested1_t);
	void *__tmp = NULL;

	void *__tmp_b = NULL;

	CHECK_ENCLAVE_POINTER(a, _len_a);
	CHECK_ENCLAVE_POINTER(b, _len_b);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (a != NULL) ? _len_a : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (b != NULL) ? _len_b : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_testOcallNested1_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_testOcallNested1_t));
	ocalloc_size -= sizeof(ms_testOcallNested1_t);

	ms->ms_level = level;
	if (a != NULL) {
		ms->ms_a = (int*)__tmp;
		if (_len_a % sizeof(*a) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, a, _len_a)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_a);
		ocalloc_size -= _len_a;
	} else {
		ms->ms_a = NULL;
	}
	
	if (b != NULL) {
		ms->ms_b = (int*)__tmp;
		__tmp_b = __tmp;
		if (_len_b % sizeof(*b) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_b, 0, _len_b);
		__tmp = (void *)((size_t)__tmp + _len_b);
		ocalloc_size -= _len_b;
	} else {
		ms->ms_b = NULL;
	}
	
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (b) {
			if (memcpy_s((void*)b, _len_b, __tmp_b, _len_b)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL testOcallNested2(int* retval, int level, int a[2], int b[2])
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_a = 2 * sizeof(int);
	size_t _len_b = 2 * sizeof(int);

	ms_testOcallNested2_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_testOcallNested2_t);
	void *__tmp = NULL;

	void *__tmp_b = NULL;

	CHECK_ENCLAVE_POINTER(a, _len_a);
	CHECK_ENCLAVE_POINTER(b, _len_b);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (a != NULL) ? _len_a : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (b != NULL) ? _len_b : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_testOcallNested2_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_testOcallNested2_t));
	ocalloc_size -= sizeof(ms_testOcallNested2_t);

	ms->ms_level = level;
	if (a != NULL) {
		ms->ms_a = (int*)__tmp;
		if (_len_a % sizeof(*a) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, a, _len_a)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_a);
		ocalloc_size -= _len_a;
	} else {
		ms->ms_a = NULL;
	}
	
	if (b != NULL) {
		ms->ms_b = (int*)__tmp;
		__tmp_b = __tmp;
		if (_len_b % sizeof(*b) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_b, 0, _len_b);
		__tmp = (void *)((size_t)__tmp + _len_b);
		ocalloc_size -= _len_b;
	} else {
		ms->ms_b = NULL;
	}
	
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (b) {
			if (memcpy_s((void*)b, _len_b, __tmp_b, _len_b)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL testOcallRecursive(int* retval, int level, int a[2], int b[2])
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_a = 2 * sizeof(int);
	size_t _len_b = 2 * sizeof(int);

	ms_testOcallRecursive_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_testOcallRecursive_t);
	void *__tmp = NULL;

	void *__tmp_b = NULL;

	CHECK_ENCLAVE_POINTER(a, _len_a);
	CHECK_ENCLAVE_POINTER(b, _len_b);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (a != NULL) ? _len_a : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (b != NULL) ? _len_b : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_testOcallRecursive_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_testOcallRecursive_t));
	ocalloc_size -= sizeof(ms_testOcallRecursive_t);

	ms->ms_level = level;
	if (a != NULL) {
		ms->ms_a = (int*)__tmp;
		if (_len_a % sizeof(*a) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, a, _len_a)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_a);
		ocalloc_size -= _len_a;
	} else {
		ms->ms_a = NULL;
	}
	
	if (b != NULL) {
		ms->ms_b = (int*)__tmp;
		__tmp_b = __tmp;
		if (_len_b % sizeof(*b) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_b, 0, _len_b);
		__tmp = (void *)((size_t)__tmp + _len_b);
		ocalloc_size -= _len_b;
	} else {
		ms->ms_b = NULL;
	}
	
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (b) {
			if (memcpy_s((void*)b, _len_b, __tmp_b, _len_b)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

