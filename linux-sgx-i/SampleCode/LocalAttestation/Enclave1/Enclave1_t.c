#include "Enclave1_t.h"

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


typedef struct ms_test_create_session_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	sgx_enclave_id_t ms_dest_enclave_id;
} ms_test_create_session_t;

typedef struct ms_test_enclave_to_enclave_call_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	sgx_enclave_id_t ms_dest_enclave_id;
} ms_test_enclave_to_enclave_call_t;

typedef struct ms_test_message_exchange_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	sgx_enclave_id_t ms_dest_enclave_id;
} ms_test_message_exchange_t;

typedef struct ms_test_close_session_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	sgx_enclave_id_t ms_dest_enclave_id;
} ms_test_close_session_t;

typedef struct ms_session_request_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	sgx_dh_msg1_t* ms_dh_msg1;
	uint32_t* ms_session_id;
} ms_session_request_t;

typedef struct ms_exchange_report_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	sgx_dh_msg2_t* ms_dh_msg2;
	sgx_dh_msg3_t* ms_dh_msg3;
	uint32_t ms_session_id;
} ms_exchange_report_t;

typedef struct ms_generate_response_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	secure_message_t* ms_req_message;
	size_t ms_req_message_size;
	size_t ms_max_payload_size;
	secure_message_t* ms_resp_message;
	size_t ms_resp_message_size;
} ms_generate_response_t;

typedef struct ms_end_session_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
} ms_end_session_t;

typedef struct ms_session_request_ocall_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	sgx_enclave_id_t ms_dest_enclave_id;
	sgx_dh_msg1_t* ms_dh_msg1;
	uint32_t* ms_session_id;
} ms_session_request_ocall_t;

typedef struct ms_exchange_report_ocall_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	sgx_enclave_id_t ms_dest_enclave_id;
	sgx_dh_msg2_t* ms_dh_msg2;
	sgx_dh_msg3_t* ms_dh_msg3;
	uint32_t ms_session_id;
} ms_exchange_report_ocall_t;

typedef struct ms_send_request_ocall_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	sgx_enclave_id_t ms_dest_enclave_id;
	secure_message_t* ms_req_message;
	size_t ms_req_message_size;
	size_t ms_max_payload_size;
	secure_message_t* ms_resp_message;
	size_t ms_resp_message_size;
} ms_send_request_ocall_t;

typedef struct ms_end_session_ocall_t {
	uint32_t ms_retval;
	sgx_enclave_id_t ms_src_enclave_id;
	sgx_enclave_id_t ms_dest_enclave_id;
} ms_end_session_ocall_t;

static sgx_status_t SGX_CDECL sgx_test_create_session(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_test_create_session_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_test_create_session_t* ms = SGX_CAST(ms_test_create_session_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = test_create_session(ms->ms_src_enclave_id, ms->ms_dest_enclave_id);


	return status;
}

static sgx_status_t SGX_CDECL sgx_test_enclave_to_enclave_call(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_test_enclave_to_enclave_call_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_test_enclave_to_enclave_call_t* ms = SGX_CAST(ms_test_enclave_to_enclave_call_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = test_enclave_to_enclave_call(ms->ms_src_enclave_id, ms->ms_dest_enclave_id);


	return status;
}

static sgx_status_t SGX_CDECL sgx_test_message_exchange(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_test_message_exchange_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_test_message_exchange_t* ms = SGX_CAST(ms_test_message_exchange_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = test_message_exchange(ms->ms_src_enclave_id, ms->ms_dest_enclave_id);


	return status;
}

static sgx_status_t SGX_CDECL sgx_test_close_session(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_test_close_session_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_test_close_session_t* ms = SGX_CAST(ms_test_close_session_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = test_close_session(ms->ms_src_enclave_id, ms->ms_dest_enclave_id);


	return status;
}

static sgx_status_t SGX_CDECL sgx_session_request(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_session_request_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_session_request_t* ms = SGX_CAST(ms_session_request_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_dh_msg1_t* _tmp_dh_msg1 = ms->ms_dh_msg1;
	size_t _len_dh_msg1 = sizeof(sgx_dh_msg1_t);
	sgx_dh_msg1_t* _in_dh_msg1 = NULL;
	uint32_t* _tmp_session_id = ms->ms_session_id;
	size_t _len_session_id = sizeof(uint32_t);
	uint32_t* _in_session_id = NULL;

	CHECK_UNIQUE_POINTER(_tmp_dh_msg1, _len_dh_msg1);
	CHECK_UNIQUE_POINTER(_tmp_session_id, _len_session_id);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_dh_msg1 != NULL && _len_dh_msg1 != 0) {
		if ((_in_dh_msg1 = (sgx_dh_msg1_t*)malloc(_len_dh_msg1)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_dh_msg1, 0, _len_dh_msg1);
	}
	if (_tmp_session_id != NULL && _len_session_id != 0) {
		if ( _len_session_id % sizeof(*_tmp_session_id) != 0)
		{
			status = SGX_ERROR_INVALID_PARAMETER;
			goto err;
		}
		if ((_in_session_id = (uint32_t*)malloc(_len_session_id)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_session_id, 0, _len_session_id);
	}

	ms->ms_retval = session_request(ms->ms_src_enclave_id, _in_dh_msg1, _in_session_id);
	if (_in_dh_msg1) {
		if (memcpy_s(_tmp_dh_msg1, _len_dh_msg1, _in_dh_msg1, _len_dh_msg1)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}
	if (_in_session_id) {
		if (memcpy_s(_tmp_session_id, _len_session_id, _in_session_id, _len_session_id)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_dh_msg1) free(_in_dh_msg1);
	if (_in_session_id) free(_in_session_id);
	return status;
}

static sgx_status_t SGX_CDECL sgx_exchange_report(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_exchange_report_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_exchange_report_t* ms = SGX_CAST(ms_exchange_report_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	sgx_dh_msg2_t* _tmp_dh_msg2 = ms->ms_dh_msg2;
	size_t _len_dh_msg2 = sizeof(sgx_dh_msg2_t);
	sgx_dh_msg2_t* _in_dh_msg2 = NULL;
	sgx_dh_msg3_t* _tmp_dh_msg3 = ms->ms_dh_msg3;
	size_t _len_dh_msg3 = sizeof(sgx_dh_msg3_t);
	sgx_dh_msg3_t* _in_dh_msg3 = NULL;

	CHECK_UNIQUE_POINTER(_tmp_dh_msg2, _len_dh_msg2);
	CHECK_UNIQUE_POINTER(_tmp_dh_msg3, _len_dh_msg3);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_dh_msg2 != NULL && _len_dh_msg2 != 0) {
		_in_dh_msg2 = (sgx_dh_msg2_t*)malloc(_len_dh_msg2);
		if (_in_dh_msg2 == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_dh_msg2, _len_dh_msg2, _tmp_dh_msg2, _len_dh_msg2)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_dh_msg3 != NULL && _len_dh_msg3 != 0) {
		if ((_in_dh_msg3 = (sgx_dh_msg3_t*)malloc(_len_dh_msg3)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_dh_msg3, 0, _len_dh_msg3);
	}

	ms->ms_retval = exchange_report(ms->ms_src_enclave_id, _in_dh_msg2, _in_dh_msg3, ms->ms_session_id);
	if (_in_dh_msg3) {
		if (memcpy_s(_tmp_dh_msg3, _len_dh_msg3, _in_dh_msg3, _len_dh_msg3)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_dh_msg2) free(_in_dh_msg2);
	if (_in_dh_msg3) free(_in_dh_msg3);
	return status;
}

static sgx_status_t SGX_CDECL sgx_generate_response(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_generate_response_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_generate_response_t* ms = SGX_CAST(ms_generate_response_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	secure_message_t* _tmp_req_message = ms->ms_req_message;
	size_t _tmp_req_message_size = ms->ms_req_message_size;
	size_t _len_req_message = _tmp_req_message_size;
	secure_message_t* _in_req_message = NULL;
	secure_message_t* _tmp_resp_message = ms->ms_resp_message;
	size_t _tmp_resp_message_size = ms->ms_resp_message_size;
	size_t _len_resp_message = _tmp_resp_message_size;
	secure_message_t* _in_resp_message = NULL;

	CHECK_UNIQUE_POINTER(_tmp_req_message, _len_req_message);
	CHECK_UNIQUE_POINTER(_tmp_resp_message, _len_resp_message);

	//
	// fence after pointer checks
	//
	sgx_lfence();

	if (_tmp_req_message != NULL && _len_req_message != 0) {
		_in_req_message = (secure_message_t*)malloc(_len_req_message);
		if (_in_req_message == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		if (memcpy_s(_in_req_message, _len_req_message, _tmp_req_message, _len_req_message)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}

	}
	if (_tmp_resp_message != NULL && _len_resp_message != 0) {
		if ((_in_resp_message = (secure_message_t*)malloc(_len_resp_message)) == NULL) {
			status = SGX_ERROR_OUT_OF_MEMORY;
			goto err;
		}

		memset((void*)_in_resp_message, 0, _len_resp_message);
	}

	ms->ms_retval = generate_response(ms->ms_src_enclave_id, _in_req_message, _tmp_req_message_size, ms->ms_max_payload_size, _in_resp_message, _tmp_resp_message_size);
	if (_in_resp_message) {
		if (memcpy_s(_tmp_resp_message, _len_resp_message, _in_resp_message, _len_resp_message)) {
			status = SGX_ERROR_UNEXPECTED;
			goto err;
		}
	}

err:
	if (_in_req_message) free(_in_req_message);
	if (_in_resp_message) free(_in_resp_message);
	return status;
}

static sgx_status_t SGX_CDECL sgx_end_session(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_end_session_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_end_session_t* ms = SGX_CAST(ms_end_session_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ms->ms_retval = end_session(ms->ms_src_enclave_id);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[8];
} g_ecall_table = {
	8,
	{
		{(void*)(uintptr_t)sgx_test_create_session, 0},
		{(void*)(uintptr_t)sgx_test_enclave_to_enclave_call, 0},
		{(void*)(uintptr_t)sgx_test_message_exchange, 0},
		{(void*)(uintptr_t)sgx_test_close_session, 0},
		{(void*)(uintptr_t)sgx_session_request, 0},
		{(void*)(uintptr_t)sgx_exchange_report, 0},
		{(void*)(uintptr_t)sgx_generate_response, 0},
		{(void*)(uintptr_t)sgx_end_session, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[4][8];
} g_dyn_entry_table = {
	4,
	{
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL session_request_ocall(uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, sgx_dh_msg1_t* dh_msg1, uint32_t* session_id)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dh_msg1 = sizeof(sgx_dh_msg1_t);
	size_t _len_session_id = sizeof(uint32_t);

	ms_session_request_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_session_request_ocall_t);
	void *__tmp = NULL;

	void *__tmp_dh_msg1 = NULL;
	void *__tmp_session_id = NULL;

	CHECK_ENCLAVE_POINTER(dh_msg1, _len_dh_msg1);
	CHECK_ENCLAVE_POINTER(session_id, _len_session_id);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (dh_msg1 != NULL) ? _len_dh_msg1 : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (session_id != NULL) ? _len_session_id : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_session_request_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_session_request_ocall_t));
	ocalloc_size -= sizeof(ms_session_request_ocall_t);

	ms->ms_src_enclave_id = src_enclave_id;
	ms->ms_dest_enclave_id = dest_enclave_id;
	if (dh_msg1 != NULL) {
		ms->ms_dh_msg1 = (sgx_dh_msg1_t*)__tmp;
		__tmp_dh_msg1 = __tmp;
		memset(__tmp_dh_msg1, 0, _len_dh_msg1);
		__tmp = (void *)((size_t)__tmp + _len_dh_msg1);
		ocalloc_size -= _len_dh_msg1;
	} else {
		ms->ms_dh_msg1 = NULL;
	}
	
	if (session_id != NULL) {
		ms->ms_session_id = (uint32_t*)__tmp;
		__tmp_session_id = __tmp;
		if (_len_session_id % sizeof(*session_id) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_session_id, 0, _len_session_id);
		__tmp = (void *)((size_t)__tmp + _len_session_id);
		ocalloc_size -= _len_session_id;
	} else {
		ms->ms_session_id = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (dh_msg1) {
			if (memcpy_s((void*)dh_msg1, _len_dh_msg1, __tmp_dh_msg1, _len_dh_msg1)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
		if (session_id) {
			if (memcpy_s((void*)session_id, _len_session_id, __tmp_session_id, _len_session_id)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL exchange_report_ocall(uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, sgx_dh_msg2_t* dh_msg2, sgx_dh_msg3_t* dh_msg3, uint32_t session_id)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_dh_msg2 = sizeof(sgx_dh_msg2_t);
	size_t _len_dh_msg3 = sizeof(sgx_dh_msg3_t);

	ms_exchange_report_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_exchange_report_ocall_t);
	void *__tmp = NULL;

	void *__tmp_dh_msg3 = NULL;

	CHECK_ENCLAVE_POINTER(dh_msg2, _len_dh_msg2);
	CHECK_ENCLAVE_POINTER(dh_msg3, _len_dh_msg3);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (dh_msg2 != NULL) ? _len_dh_msg2 : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (dh_msg3 != NULL) ? _len_dh_msg3 : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_exchange_report_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_exchange_report_ocall_t));
	ocalloc_size -= sizeof(ms_exchange_report_ocall_t);

	ms->ms_src_enclave_id = src_enclave_id;
	ms->ms_dest_enclave_id = dest_enclave_id;
	if (dh_msg2 != NULL) {
		ms->ms_dh_msg2 = (sgx_dh_msg2_t*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, dh_msg2, _len_dh_msg2)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_dh_msg2);
		ocalloc_size -= _len_dh_msg2;
	} else {
		ms->ms_dh_msg2 = NULL;
	}
	
	if (dh_msg3 != NULL) {
		ms->ms_dh_msg3 = (sgx_dh_msg3_t*)__tmp;
		__tmp_dh_msg3 = __tmp;
		memset(__tmp_dh_msg3, 0, _len_dh_msg3);
		__tmp = (void *)((size_t)__tmp + _len_dh_msg3);
		ocalloc_size -= _len_dh_msg3;
	} else {
		ms->ms_dh_msg3 = NULL;
	}
	
	ms->ms_session_id = session_id;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (dh_msg3) {
			if (memcpy_s((void*)dh_msg3, _len_dh_msg3, __tmp_dh_msg3, _len_dh_msg3)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL send_request_ocall(uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id, secure_message_t* req_message, size_t req_message_size, size_t max_payload_size, secure_message_t* resp_message, size_t resp_message_size)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_req_message = req_message_size;
	size_t _len_resp_message = resp_message_size;

	ms_send_request_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_send_request_ocall_t);
	void *__tmp = NULL;

	void *__tmp_resp_message = NULL;

	CHECK_ENCLAVE_POINTER(req_message, _len_req_message);
	CHECK_ENCLAVE_POINTER(resp_message, _len_resp_message);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (req_message != NULL) ? _len_req_message : 0))
		return SGX_ERROR_INVALID_PARAMETER;
	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (resp_message != NULL) ? _len_resp_message : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_send_request_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_send_request_ocall_t));
	ocalloc_size -= sizeof(ms_send_request_ocall_t);

	ms->ms_src_enclave_id = src_enclave_id;
	ms->ms_dest_enclave_id = dest_enclave_id;
	if (req_message != NULL) {
		ms->ms_req_message = (secure_message_t*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, req_message, _len_req_message)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_req_message);
		ocalloc_size -= _len_req_message;
	} else {
		ms->ms_req_message = NULL;
	}
	
	ms->ms_req_message_size = req_message_size;
	ms->ms_max_payload_size = max_payload_size;
	if (resp_message != NULL) {
		ms->ms_resp_message = (secure_message_t*)__tmp;
		__tmp_resp_message = __tmp;
		memset(__tmp_resp_message, 0, _len_resp_message);
		__tmp = (void *)((size_t)__tmp + _len_resp_message);
		ocalloc_size -= _len_resp_message;
	} else {
		ms->ms_resp_message = NULL;
	}
	
	ms->ms_resp_message_size = resp_message_size;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (resp_message) {
			if (memcpy_s((void*)resp_message, _len_resp_message, __tmp_resp_message, _len_resp_message)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL end_session_ocall(uint32_t* retval, sgx_enclave_id_t src_enclave_id, sgx_enclave_id_t dest_enclave_id)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_end_session_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_end_session_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_end_session_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_end_session_ocall_t));
	ocalloc_size -= sizeof(ms_end_session_ocall_t);

	ms->ms_src_enclave_id = src_enclave_id;
	ms->ms_dest_enclave_id = dest_enclave_id;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

