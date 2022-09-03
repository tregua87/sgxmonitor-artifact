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


typedef struct ms_sec_dvdcss_test_t {
	int ms_retval;
	void* ms_dvdcss;
} ms_sec_dvdcss_test_t;

typedef struct ms_sec_dvdcss_title_t {
	int ms_retval;
	void* ms_dvdcss;
	int ms_i_block;
} ms_sec_dvdcss_title_t;

typedef struct ms_sec_dvdcss_unscramble_t {
	int ms_retval;
	uint8_t* ms_p_key;
	uint8_t* ms_p_sec;
} ms_sec_dvdcss_unscramble_t;

typedef struct ms_sec_dvdcss_disckey_t {
	int ms_retval;
	void* ms_dvdcss;
} ms_sec_dvdcss_disckey_t;

typedef struct ms_wrap_ioctl_ReadCopyright_t {
	int ms_retval;
	int ms_i_fd;
	int ms_i_layer;
	int* ms_pi_copyright;
} ms_wrap_ioctl_ReadCopyright_t;

typedef struct ms_wrap_ioctl_ReportRPC_t {
	int ms_retval;
	int ms_i_fd;
	int* ms_p_type;
	int* ms_p_mask;
	int* ms_p_scheme;
} ms_wrap_ioctl_ReportRPC_t;

typedef struct ms_wrap_ioctl_InvalidateAgid_t {
	int ms_retval;
	int ms_i_fd;
	int* ms_pi_agid;
} ms_wrap_ioctl_InvalidateAgid_t;

typedef struct ms_wrap_ioctl_ReadTitleKey_t {
	int ms_retval;
	int ms_i_fd;
	int* ms_pi_agid;
	int ms_i_pos;
	uint8_t* ms_p_key;
} ms_wrap_ioctl_ReadTitleKey_t;

typedef struct ms_wrap_ioctl_ReportASF_t {
	int ms_retval;
	int ms_i_fd;
	int* ms_pi_asf;
} ms_wrap_ioctl_ReportASF_t;

typedef struct ms_wrap_ioctl_SendKey2_t {
	int ms_retval;
	int ms_i_fd;
	int* ms_pi_agid;
	uint8_t* ms_p_key;
} ms_wrap_ioctl_SendKey2_t;

typedef struct ms_wrap_ioctl_ReportChallenge_t {
	int ms_retval;
	int ms_i_fd;
	int* ms_pi_agid;
	uint8_t* ms_p_challenge;
} ms_wrap_ioctl_ReportChallenge_t;

typedef struct ms_wrap_ioctl_ReportKey1_t {
	int ms_retval;
	int ms_i_fd;
	int* ms_pi_agid;
	uint8_t* ms_p_key;
} ms_wrap_ioctl_ReportKey1_t;

typedef struct ms_wrap_ioctl_SendChallenge_t {
	int ms_retval;
	int ms_i_fd;
	int* ms_pi_agid;
	uint8_t* ms_p_challenge;
} ms_wrap_ioctl_SendChallenge_t;

typedef struct ms_wrap_ioctl_ReportAgid_t {
	int ms_retval;
	int ms_i_fd;
	int* ms_pi_agid;
} ms_wrap_ioctl_ReportAgid_t;

typedef struct ms_wrap_ioctl_ReadDiscKey_t {
	int ms_retval;
	int ms_i_fd;
	int* ms_pi_agid;
	uint8_t* ms_p_key;
} ms_wrap_ioctl_ReadDiscKey_t;

typedef struct ms_raw_pf_seek_t {
	int ms_retval;
	void* ms_self;
	void* ms_dvdcss;
	int ms_pos;
} ms_raw_pf_seek_t;

typedef struct ms_raw_pf_read_t {
	int ms_retval;
	void* ms_self;
	void* ms_dvdcss;
	void* ms_buff;
	int ms_pos;
} ms_raw_pf_read_t;

typedef struct ms_open_u_t {
	int ms_retval;
	char* ms_path;
	int ms_flags;
} ms_open_u_t;

typedef struct ms_open2_u_t {
	int ms_retval;
	char* ms_path;
	int ms_flags;
	int ms_flags2;
} ms_open2_u_t;

typedef struct ms_read_u_t {
	int ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_nbyte;
} ms_read_u_t;

typedef struct ms_close_u_t {
	int ms_retval;
	int ms_fd;
} ms_close_u_t;

typedef struct ms_write_u_t {
	int ms_retval;
	int ms_fd;
	void* ms_buf;
	size_t ms_nbyte;
} ms_write_u_t;

typedef struct ms_dvdcss_open_device_u_t {
	int ms_retval;
	void* ms_dvdcss;
} ms_dvdcss_open_device_u_t;

typedef struct ms_dvdcss_close_device_u_t {
	int ms_retval;
	void* ms_dvdcss;
} ms_dvdcss_close_device_u_t;

typedef struct ms_dvdcss_read_u_t {
	int ms_retval;
	void* ms_dvdcss;
	void* ms_p_buffer;
	int ms_i_blocks;
	int ms_i_flags;
} ms_dvdcss_read_u_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL sgx_sec_dvdcss_test(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sec_dvdcss_test_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sec_dvdcss_test_t* ms = SGX_CAST(ms_sec_dvdcss_test_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_dvdcss = ms->ms_dvdcss;



	ms->ms_retval = sec_dvdcss_test(_tmp_dvdcss);


	return status;
}

static sgx_status_t SGX_CDECL sgx_sec_dvdcss_title(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sec_dvdcss_title_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sec_dvdcss_title_t* ms = SGX_CAST(ms_sec_dvdcss_title_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_dvdcss = ms->ms_dvdcss;



	ms->ms_retval = sec_dvdcss_title(_tmp_dvdcss, ms->ms_i_block);


	return status;
}

static sgx_status_t SGX_CDECL sgx_sec_dvdcss_unscramble(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sec_dvdcss_unscramble_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sec_dvdcss_unscramble_t* ms = SGX_CAST(ms_sec_dvdcss_unscramble_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	uint8_t* _tmp_p_key = ms->ms_p_key;
	uint8_t* _tmp_p_sec = ms->ms_p_sec;



	ms->ms_retval = sec_dvdcss_unscramble(_tmp_p_key, _tmp_p_sec);


	return status;
}

static sgx_status_t SGX_CDECL sgx_sec_dvdcss_disckey(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_sec_dvdcss_disckey_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_sec_dvdcss_disckey_t* ms = SGX_CAST(ms_sec_dvdcss_disckey_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_dvdcss = ms->ms_dvdcss;



	ms->ms_retval = sec_dvdcss_disckey(_tmp_dvdcss);


	return status;
}

static sgx_status_t SGX_CDECL sgx_hello(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	hello();
	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv;} ecall_table[5];
} g_ecall_table = {
	5,
	{
		{(void*)(uintptr_t)sgx_sec_dvdcss_test, 0},
		{(void*)(uintptr_t)sgx_sec_dvdcss_title, 0},
		{(void*)(uintptr_t)sgx_sec_dvdcss_unscramble, 0},
		{(void*)(uintptr_t)sgx_sec_dvdcss_disckey, 0},
		{(void*)(uintptr_t)sgx_hello, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[22][5];
} g_dyn_entry_table = {
	22,
	{
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL wrap_ioctl_ReadCopyright(int* retval, int i_fd, int i_layer, int* pi_copyright)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_pi_copyright = 4;

	ms_wrap_ioctl_ReadCopyright_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_wrap_ioctl_ReadCopyright_t);
	void *__tmp = NULL;

	void *__tmp_pi_copyright = NULL;

	CHECK_ENCLAVE_POINTER(pi_copyright, _len_pi_copyright);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (pi_copyright != NULL) ? _len_pi_copyright : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_wrap_ioctl_ReadCopyright_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_wrap_ioctl_ReadCopyright_t));
	ocalloc_size -= sizeof(ms_wrap_ioctl_ReadCopyright_t);

	ms->ms_i_fd = i_fd;
	ms->ms_i_layer = i_layer;
	if (pi_copyright != NULL) {
		ms->ms_pi_copyright = (int*)__tmp;
		__tmp_pi_copyright = __tmp;
		if (_len_pi_copyright % sizeof(*pi_copyright) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp_pi_copyright, ocalloc_size, pi_copyright, _len_pi_copyright)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_pi_copyright);
		ocalloc_size -= _len_pi_copyright;
	} else {
		ms->ms_pi_copyright = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (pi_copyright) {
			if (memcpy_s((void*)pi_copyright, _len_pi_copyright, __tmp_pi_copyright, _len_pi_copyright)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL wrap_ioctl_ReportRPC(int* retval, int i_fd, int* p_type, int* p_mask, int* p_scheme)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_wrap_ioctl_ReportRPC_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_wrap_ioctl_ReportRPC_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_wrap_ioctl_ReportRPC_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_wrap_ioctl_ReportRPC_t));
	ocalloc_size -= sizeof(ms_wrap_ioctl_ReportRPC_t);

	ms->ms_i_fd = i_fd;
	ms->ms_p_type = p_type;
	ms->ms_p_mask = p_mask;
	ms->ms_p_scheme = p_scheme;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL wrap_ioctl_InvalidateAgid(int* retval, int i_fd, int* pi_agid)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_wrap_ioctl_InvalidateAgid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_wrap_ioctl_InvalidateAgid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_wrap_ioctl_InvalidateAgid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_wrap_ioctl_InvalidateAgid_t));
	ocalloc_size -= sizeof(ms_wrap_ioctl_InvalidateAgid_t);

	ms->ms_i_fd = i_fd;
	ms->ms_pi_agid = pi_agid;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL wrap_ioctl_ReadTitleKey(int* retval, int i_fd, int* pi_agid, int i_pos, uint8_t* p_key)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_wrap_ioctl_ReadTitleKey_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_wrap_ioctl_ReadTitleKey_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_wrap_ioctl_ReadTitleKey_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_wrap_ioctl_ReadTitleKey_t));
	ocalloc_size -= sizeof(ms_wrap_ioctl_ReadTitleKey_t);

	ms->ms_i_fd = i_fd;
	ms->ms_pi_agid = pi_agid;
	ms->ms_i_pos = i_pos;
	ms->ms_p_key = p_key;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL wrap_ioctl_ReportASF(int* retval, int i_fd, int* pi_asf)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_wrap_ioctl_ReportASF_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_wrap_ioctl_ReportASF_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_wrap_ioctl_ReportASF_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_wrap_ioctl_ReportASF_t));
	ocalloc_size -= sizeof(ms_wrap_ioctl_ReportASF_t);

	ms->ms_i_fd = i_fd;
	ms->ms_pi_asf = pi_asf;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL wrap_ioctl_SendKey2(int* retval, int i_fd, int* pi_agid, uint8_t* p_key)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_wrap_ioctl_SendKey2_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_wrap_ioctl_SendKey2_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_wrap_ioctl_SendKey2_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_wrap_ioctl_SendKey2_t));
	ocalloc_size -= sizeof(ms_wrap_ioctl_SendKey2_t);

	ms->ms_i_fd = i_fd;
	ms->ms_pi_agid = pi_agid;
	ms->ms_p_key = p_key;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL wrap_ioctl_ReportChallenge(int* retval, int i_fd, int* pi_agid, uint8_t* p_challenge)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_wrap_ioctl_ReportChallenge_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_wrap_ioctl_ReportChallenge_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_wrap_ioctl_ReportChallenge_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_wrap_ioctl_ReportChallenge_t));
	ocalloc_size -= sizeof(ms_wrap_ioctl_ReportChallenge_t);

	ms->ms_i_fd = i_fd;
	ms->ms_pi_agid = pi_agid;
	ms->ms_p_challenge = p_challenge;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL wrap_ioctl_ReportKey1(int* retval, int i_fd, int* pi_agid, uint8_t* p_key)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_p_key = 10;

	ms_wrap_ioctl_ReportKey1_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_wrap_ioctl_ReportKey1_t);
	void *__tmp = NULL;

	void *__tmp_p_key = NULL;

	CHECK_ENCLAVE_POINTER(p_key, _len_p_key);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p_key != NULL) ? _len_p_key : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_wrap_ioctl_ReportKey1_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_wrap_ioctl_ReportKey1_t));
	ocalloc_size -= sizeof(ms_wrap_ioctl_ReportKey1_t);

	ms->ms_i_fd = i_fd;
	ms->ms_pi_agid = pi_agid;
	if (p_key != NULL) {
		ms->ms_p_key = (uint8_t*)__tmp;
		__tmp_p_key = __tmp;
		if (_len_p_key % sizeof(*p_key) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp_p_key, ocalloc_size, p_key, _len_p_key)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_p_key);
		ocalloc_size -= _len_p_key;
	} else {
		ms->ms_p_key = NULL;
	}
	
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (p_key) {
			if (memcpy_s((void*)p_key, _len_p_key, __tmp_p_key, _len_p_key)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL wrap_ioctl_SendChallenge(int* retval, int i_fd, int* pi_agid, uint8_t* p_challenge)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_p_challenge = 10;

	ms_wrap_ioctl_SendChallenge_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_wrap_ioctl_SendChallenge_t);
	void *__tmp = NULL;

	void *__tmp_p_challenge = NULL;

	CHECK_ENCLAVE_POINTER(p_challenge, _len_p_challenge);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (p_challenge != NULL) ? _len_p_challenge : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_wrap_ioctl_SendChallenge_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_wrap_ioctl_SendChallenge_t));
	ocalloc_size -= sizeof(ms_wrap_ioctl_SendChallenge_t);

	ms->ms_i_fd = i_fd;
	ms->ms_pi_agid = pi_agid;
	if (p_challenge != NULL) {
		ms->ms_p_challenge = (uint8_t*)__tmp;
		__tmp_p_challenge = __tmp;
		if (_len_p_challenge % sizeof(*p_challenge) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp_p_challenge, ocalloc_size, p_challenge, _len_p_challenge)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_p_challenge);
		ocalloc_size -= _len_p_challenge;
	} else {
		ms->ms_p_challenge = NULL;
	}
	
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (p_challenge) {
			if (memcpy_s((void*)p_challenge, _len_p_challenge, __tmp_p_challenge, _len_p_challenge)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL wrap_ioctl_ReportAgid(int* retval, int i_fd, int* pi_agid)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_wrap_ioctl_ReportAgid_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_wrap_ioctl_ReportAgid_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_wrap_ioctl_ReportAgid_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_wrap_ioctl_ReportAgid_t));
	ocalloc_size -= sizeof(ms_wrap_ioctl_ReportAgid_t);

	ms->ms_i_fd = i_fd;
	ms->ms_pi_agid = pi_agid;
	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL wrap_ioctl_ReadDiscKey(int* retval, int i_fd, int* pi_agid, uint8_t* p_key)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_wrap_ioctl_ReadDiscKey_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_wrap_ioctl_ReadDiscKey_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_wrap_ioctl_ReadDiscKey_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_wrap_ioctl_ReadDiscKey_t));
	ocalloc_size -= sizeof(ms_wrap_ioctl_ReadDiscKey_t);

	ms->ms_i_fd = i_fd;
	ms->ms_pi_agid = pi_agid;
	ms->ms_p_key = p_key;
	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL raw_pf_seek(int* retval, void* self, void* dvdcss, int pos)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_raw_pf_seek_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_raw_pf_seek_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_raw_pf_seek_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_raw_pf_seek_t));
	ocalloc_size -= sizeof(ms_raw_pf_seek_t);

	ms->ms_self = self;
	ms->ms_dvdcss = dvdcss;
	ms->ms_pos = pos;
	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL raw_pf_read(int* retval, void* self, void* dvdcss, void* buff, int pos)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_raw_pf_read_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_raw_pf_read_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_raw_pf_read_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_raw_pf_read_t));
	ocalloc_size -= sizeof(ms_raw_pf_read_t);

	ms->ms_self = self;
	ms->ms_dvdcss = dvdcss;
	ms->ms_buff = buff;
	ms->ms_pos = pos;
	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL open_u(int* retval, char* path, int flags)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;

	ms_open_u_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_open_u_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(path, _len_path);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path != NULL) ? _len_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_open_u_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_open_u_t));
	ocalloc_size -= sizeof(ms_open_u_t);

	if (path != NULL) {
		ms->ms_path = (char*)__tmp;
		if (_len_path % sizeof(*path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}
	
	ms->ms_flags = flags;
	status = sgx_ocall(13, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL open2_u(int* retval, char* path, int flags, int flags2)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_path = path ? strlen(path) + 1 : 0;

	ms_open2_u_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_open2_u_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(path, _len_path);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (path != NULL) ? _len_path : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_open2_u_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_open2_u_t));
	ocalloc_size -= sizeof(ms_open2_u_t);

	if (path != NULL) {
		ms->ms_path = (char*)__tmp;
		if (_len_path % sizeof(*path) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, path, _len_path)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_path);
		ocalloc_size -= _len_path;
	} else {
		ms->ms_path = NULL;
	}
	
	ms->ms_flags = flags;
	ms->ms_flags2 = flags2;
	status = sgx_ocall(14, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL read_u(int* retval, int fd, void* buf, size_t nbyte)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = nbyte;

	ms_read_u_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_read_u_t);
	void *__tmp = NULL;

	void *__tmp_buf = NULL;

	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_read_u_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_read_u_t));
	ocalloc_size -= sizeof(ms_read_u_t);

	ms->ms_fd = fd;
	if (buf != NULL) {
		ms->ms_buf = (void*)__tmp;
		__tmp_buf = __tmp;
		memset(__tmp_buf, 0, _len_buf);
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_nbyte = nbyte;
	status = sgx_ocall(15, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
		if (buf) {
			if (memcpy_s((void*)buf, _len_buf, __tmp_buf, _len_buf)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL close_u(int* retval, int fd)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_close_u_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_close_u_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_close_u_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_close_u_t));
	ocalloc_size -= sizeof(ms_close_u_t);

	ms->ms_fd = fd;
	status = sgx_ocall(16, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL write_u(int* retval, int fd, void* buf, size_t nbyte)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_buf = nbyte;

	ms_write_u_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_write_u_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(buf, _len_buf);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (buf != NULL) ? _len_buf : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_write_u_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_write_u_t));
	ocalloc_size -= sizeof(ms_write_u_t);

	ms->ms_fd = fd;
	if (buf != NULL) {
		ms->ms_buf = (void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, buf, _len_buf)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_buf);
		ocalloc_size -= _len_buf;
	} else {
		ms->ms_buf = NULL;
	}
	
	ms->ms_nbyte = nbyte;
	status = sgx_ocall(17, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL dvdcss_open_device_u(int* retval, void* dvdcss)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_dvdcss_open_device_u_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_dvdcss_open_device_u_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_dvdcss_open_device_u_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_dvdcss_open_device_u_t));
	ocalloc_size -= sizeof(ms_dvdcss_open_device_u_t);

	ms->ms_dvdcss = dvdcss;
	status = sgx_ocall(18, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL dvdcss_close_device_u(int* retval, void* dvdcss)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_dvdcss_close_device_u_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_dvdcss_close_device_u_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_dvdcss_close_device_u_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_dvdcss_close_device_u_t));
	ocalloc_size -= sizeof(ms_dvdcss_close_device_u_t);

	ms->ms_dvdcss = dvdcss;
	status = sgx_ocall(19, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL dvdcss_read_u(int* retval, void* dvdcss, void* p_buffer, int i_blocks, int i_flags)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_dvdcss_read_u_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_dvdcss_read_u_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_dvdcss_read_u_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_dvdcss_read_u_t));
	ocalloc_size -= sizeof(ms_dvdcss_read_u_t);

	ms->ms_dvdcss = dvdcss;
	ms->ms_p_buffer = p_buffer;
	ms->ms_i_blocks = i_blocks;
	ms->ms_i_flags = i_flags;
	status = sgx_ocall(20, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
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
	
	status = sgx_ocall(21, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

