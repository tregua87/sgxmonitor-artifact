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

typedef struct ms_setBucket_t {
	bucket_t* ms_b;
} ms_setBucket_t;

typedef struct ms_setActionCounter_t {
	int* ms_ac;
} ms_setActionCounter_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_monitorgatewayu_t {
	const char* ms_strI;
	size_t ms_lenI;
	char* ms_strO;
	size_t ms_lenO;
} ms_ocall_monitorgatewayu_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

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

static sgx_status_t SGX_CDECL sgx_setBucket(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_setBucket_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_setBucket_t* ms = SGX_CAST(ms_setBucket_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	bucket_t* _tmp_b = ms->ms_b;



	setBucket(_tmp_b);


	return status;
}

static sgx_status_t SGX_CDECL sgx_setActionCounter(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_setActionCounter_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_setActionCounter_t* ms = SGX_CAST(ms_setActionCounter_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	int* _tmp_ac = ms->ms_ac;



	setActionCounter(_tmp_ac);


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
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[8];
} g_ecall_table = {
	8,
	{
		{(void*)(uintptr_t)sgx_ecall_pwnme, 0},
		{(void*)(uintptr_t)sgx_generateKeyEnclave, 0},
		{(void*)(uintptr_t)sgx_loadKeyEnclave, 0},
		{(void*)(uintptr_t)sgx_enclaveProcess, 0},
		{(void*)(uintptr_t)sgx_setBucket, 0},
		{(void*)(uintptr_t)sgx_setActionCounter, 0},
		{(void*)(uintptr_t)sgx_bootSecureCommunication, 0},
		{(void*)(uintptr_t)sgx_makeEndMsg, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[6][8];
} g_dyn_entry_table = {
	6,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
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

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

