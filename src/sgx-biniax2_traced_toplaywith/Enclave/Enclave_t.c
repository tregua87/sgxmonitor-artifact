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


typedef struct ms_add_to_store_t {
	const void* ms_bytes;
	size_t ms_len;
} ms_add_to_store_t;

typedef struct ms_get_from_store_t {
	void* ms_out_var;
	size_t ms_len;
	size_t ms_index;
} ms_get_from_store_t;

typedef struct ms_encrypt_store_t {
	const char* ms_fname;
	size_t ms_fname_len;
} ms_encrypt_store_t;

typedef struct ms_decrypt_store_t {
	const uint8_t* ms_ebytes;
	size_t ms_len;
} ms_decrypt_store_t;

typedef struct ms_setBucket_t {
	bucket_t* ms_b;
} ms_setBucket_t;

typedef struct ms_setActionCounter_t {
	int* ms_ac;
} ms_setActionCounter_t;

typedef struct ms_ocall_write_resource_t {
	const char* ms_str;
	const void* ms_bytes;
	size_t ms_len;
} ms_ocall_write_resource_t;

typedef struct ms_ocall_write_out_t {
	const void* ms_bytes;
	size_t ms_len;
} ms_ocall_write_out_t;

typedef struct ms_ocall_print_raw_t {
	const void* ms_bytes;
	size_t ms_len;
} ms_ocall_print_raw_t;

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

static sgx_status_t SGX_CDECL sgx_init_store(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	init_store();
	return status;
}

static sgx_status_t SGX_CDECL sgx_free_store(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	free_store();
	return status;
}

static sgx_status_t SGX_CDECL sgx_add_to_store(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_add_to_store_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_add_to_store_t* ms = SGX_CAST(ms_add_to_store_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const void* _tmp_bytes = ms->ms_bytes;
	size_t _tmp_len = ms->ms_len;
	size_t _len_bytes = _tmp_len;
	void* _in_bytes = NULL;

	CHECK_UNIQUE_POINTER(_tmp_bytes, _len_bytes);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_bytes != NULL && _len_bytes != 0) {
		_in_bytes = (void*)malloc(_len_bytes);
		if (_in_bytes == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_bytes, _len_bytes, _tmp_bytes, _len_bytes)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	add_to_store((const void*)_in_bytes, _tmp_len);

err:
	if (_in_bytes) free(_in_bytes);
	return status;
}

static sgx_status_t SGX_CDECL sgx_get_from_store(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_get_from_store_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_get_from_store_t* ms = SGX_CAST(ms_get_from_store_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_out_var = ms->ms_out_var;
	size_t _tmp_len = ms->ms_len;
	size_t _len_out_var = _tmp_len;
	void* _in_out_var = NULL;

	CHECK_UNIQUE_POINTER(_tmp_out_var, _len_out_var);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_out_var != NULL && _len_out_var != 0) {
		if ((_in_out_var = (void*)malloc(_len_out_var)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_out_var, 0, _len_out_var);
	}

	get_from_store(_in_out_var, _tmp_len, ms->ms_index);
	if (_in_out_var) {
		if (memcpy_s(_tmp_out_var, _len_out_var, _in_out_var, _len_out_var)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_out_var) free(_in_out_var);
	return status;
}

static sgx_status_t SGX_CDECL sgx_encrypt_store(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_encrypt_store_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_encrypt_store_t* ms = SGX_CAST(ms_encrypt_store_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const char* _tmp_fname = ms->ms_fname;
	size_t _len_fname = ms->ms_fname_len ;
	char* _in_fname = NULL;

	CHECK_UNIQUE_POINTER(_tmp_fname, _len_fname);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_fname != NULL && _len_fname != 0) {
		_in_fname = (char*)malloc(_len_fname);
		if (_in_fname == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_fname, _len_fname, _tmp_fname, _len_fname)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

		_in_fname[_len_fname - 1] = '\0';
		if (_len_fname != strlen(_in_fname) + 1)
		{
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

	encrypt_store((const char*)_in_fname);

err:
	if (_in_fname) free(_in_fname);
	return status;
}

static sgx_status_t SGX_CDECL sgx_decrypt_store(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_decrypt_store_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_decrypt_store_t* ms = SGX_CAST(ms_decrypt_store_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	const uint8_t* _tmp_ebytes = ms->ms_ebytes;
	size_t _tmp_len = ms->ms_len;
	size_t _len_ebytes = _tmp_len;
	uint8_t* _in_ebytes = NULL;

	CHECK_UNIQUE_POINTER(_tmp_ebytes, _len_ebytes);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_ebytes != NULL && _len_ebytes != 0) {
		if ( _len_ebytes % sizeof(*_tmp_ebytes) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		_in_ebytes = (uint8_t*)malloc(_len_ebytes);
		if (_in_ebytes == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_ebytes, _len_ebytes, _tmp_ebytes, _len_ebytes)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}

	decrypt_store((const uint8_t*)_in_ebytes, _tmp_len);

err:
	if (_in_ebytes) free(_in_ebytes);
	return status;
}

static sgx_status_t SGX_CDECL sgx_store_to_bytes(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	store_to_bytes();
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
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[11];
} g_ecall_table = {
	11,
	{
		{(void*)(uintptr_t)sgx_init_store, 0},
		{(void*)(uintptr_t)sgx_free_store, 0},
		{(void*)(uintptr_t)sgx_add_to_store, 0},
		{(void*)(uintptr_t)sgx_get_from_store, 0},
		{(void*)(uintptr_t)sgx_encrypt_store, 0},
		{(void*)(uintptr_t)sgx_decrypt_store, 0},
		{(void*)(uintptr_t)sgx_store_to_bytes, 0},
		{(void*)(uintptr_t)sgx_setBucket, 0},
		{(void*)(uintptr_t)sgx_setActionCounter, 0},
		{(void*)(uintptr_t)sgx_bootSecureCommunication, 0},
		{(void*)(uintptr_t)sgx_makeEndMsg, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[9][11];
} g_dyn_entry_table = {
	9,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_write_resource(const char* str, const void* bytes, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;
	size_t _len_bytes = len;

	ms_ocall_write_resource_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_write_resource_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);
	CHECK_ENCLAVE_POINTER(bytes, _len_bytes);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (bytes != NULL) ? _len_bytes : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_write_resource_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_write_resource_t));
	ocalloc_size -= sizeof(ms_ocall_write_resource_t);

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
	
	if (bytes != NULL) {
		ms->ms_bytes = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, bytes, _len_bytes)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_bytes);
		ocalloc_size -= _len_bytes;
	} else {
		ms->ms_bytes = NULL;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_write_out(const void* bytes, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_bytes = len;

	ms_ocall_write_out_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_write_out_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(bytes, _len_bytes);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (bytes != NULL) ? _len_bytes : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_write_out_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_write_out_t));
	ocalloc_size -= sizeof(ms_ocall_write_out_t);

	if (bytes != NULL) {
		ms->ms_bytes = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, bytes, _len_bytes)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_bytes);
		ocalloc_size -= _len_bytes;
	} else {
		ms->ms_bytes = NULL;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_print_raw(const void* bytes, size_t len)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_bytes = len;

	ms_ocall_print_raw_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_raw_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(bytes, _len_bytes);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (bytes != NULL) ? _len_bytes : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_raw_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_raw_t));
	ocalloc_size -= sizeof(ms_ocall_print_raw_t);

	if (bytes != NULL) {
		ms->ms_bytes = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, bytes, _len_bytes)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_bytes);
		ocalloc_size -= _len_bytes;
	} else {
		ms->ms_bytes = NULL;
	}
	
	ms->ms_len = len;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

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
	
	status = sgx_ocall(3, ms);

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
	status = sgx_ocall(4, ms);

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
	status = sgx_ocall(5, ms);

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
	status = sgx_ocall(6, ms);

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
	status = sgx_ocall(7, ms);

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
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

