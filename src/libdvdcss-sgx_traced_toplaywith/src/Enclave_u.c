#include "Enclave_u.h"
#include <errno.h>

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

typedef struct ms_setBucket_t {
	bucket_t* ms_b;
} ms_setBucket_t;

typedef struct ms_setActionCounter_t {
	int* ms_ac;
} ms_setActionCounter_t;

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

static sgx_status_t SGX_CDECL Enclave_wrap_ioctl_ReadCopyright(void* pms)
{
	ms_wrap_ioctl_ReadCopyright_t* ms = SGX_CAST(ms_wrap_ioctl_ReadCopyright_t*, pms);
	ms->ms_retval = wrap_ioctl_ReadCopyright(ms->ms_i_fd, ms->ms_i_layer, ms->ms_pi_copyright);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_wrap_ioctl_ReportRPC(void* pms)
{
	ms_wrap_ioctl_ReportRPC_t* ms = SGX_CAST(ms_wrap_ioctl_ReportRPC_t*, pms);
	ms->ms_retval = wrap_ioctl_ReportRPC(ms->ms_i_fd, ms->ms_p_type, ms->ms_p_mask, ms->ms_p_scheme);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_wrap_ioctl_InvalidateAgid(void* pms)
{
	ms_wrap_ioctl_InvalidateAgid_t* ms = SGX_CAST(ms_wrap_ioctl_InvalidateAgid_t*, pms);
	ms->ms_retval = wrap_ioctl_InvalidateAgid(ms->ms_i_fd, ms->ms_pi_agid);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_wrap_ioctl_ReadTitleKey(void* pms)
{
	ms_wrap_ioctl_ReadTitleKey_t* ms = SGX_CAST(ms_wrap_ioctl_ReadTitleKey_t*, pms);
	ms->ms_retval = wrap_ioctl_ReadTitleKey(ms->ms_i_fd, ms->ms_pi_agid, ms->ms_i_pos, ms->ms_p_key);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_wrap_ioctl_ReportASF(void* pms)
{
	ms_wrap_ioctl_ReportASF_t* ms = SGX_CAST(ms_wrap_ioctl_ReportASF_t*, pms);
	ms->ms_retval = wrap_ioctl_ReportASF(ms->ms_i_fd, ms->ms_pi_asf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_wrap_ioctl_SendKey2(void* pms)
{
	ms_wrap_ioctl_SendKey2_t* ms = SGX_CAST(ms_wrap_ioctl_SendKey2_t*, pms);
	ms->ms_retval = wrap_ioctl_SendKey2(ms->ms_i_fd, ms->ms_pi_agid, ms->ms_p_key);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_wrap_ioctl_ReportChallenge(void* pms)
{
	ms_wrap_ioctl_ReportChallenge_t* ms = SGX_CAST(ms_wrap_ioctl_ReportChallenge_t*, pms);
	ms->ms_retval = wrap_ioctl_ReportChallenge(ms->ms_i_fd, ms->ms_pi_agid, ms->ms_p_challenge);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_wrap_ioctl_ReportKey1(void* pms)
{
	ms_wrap_ioctl_ReportKey1_t* ms = SGX_CAST(ms_wrap_ioctl_ReportKey1_t*, pms);
	ms->ms_retval = wrap_ioctl_ReportKey1(ms->ms_i_fd, ms->ms_pi_agid, ms->ms_p_key);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_wrap_ioctl_SendChallenge(void* pms)
{
	ms_wrap_ioctl_SendChallenge_t* ms = SGX_CAST(ms_wrap_ioctl_SendChallenge_t*, pms);
	ms->ms_retval = wrap_ioctl_SendChallenge(ms->ms_i_fd, ms->ms_pi_agid, ms->ms_p_challenge);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_wrap_ioctl_ReportAgid(void* pms)
{
	ms_wrap_ioctl_ReportAgid_t* ms = SGX_CAST(ms_wrap_ioctl_ReportAgid_t*, pms);
	ms->ms_retval = wrap_ioctl_ReportAgid(ms->ms_i_fd, ms->ms_pi_agid);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_wrap_ioctl_ReadDiscKey(void* pms)
{
	ms_wrap_ioctl_ReadDiscKey_t* ms = SGX_CAST(ms_wrap_ioctl_ReadDiscKey_t*, pms);
	ms->ms_retval = wrap_ioctl_ReadDiscKey(ms->ms_i_fd, ms->ms_pi_agid, ms->ms_p_key);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_raw_pf_seek(void* pms)
{
	ms_raw_pf_seek_t* ms = SGX_CAST(ms_raw_pf_seek_t*, pms);
	ms->ms_retval = raw_pf_seek(ms->ms_self, ms->ms_dvdcss, ms->ms_pos);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_raw_pf_read(void* pms)
{
	ms_raw_pf_read_t* ms = SGX_CAST(ms_raw_pf_read_t*, pms);
	ms->ms_retval = raw_pf_read(ms->ms_self, ms->ms_dvdcss, ms->ms_buff, ms->ms_pos);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_open_u(void* pms)
{
	ms_open_u_t* ms = SGX_CAST(ms_open_u_t*, pms);
	ms->ms_retval = open_u(ms->ms_path, ms->ms_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_open2_u(void* pms)
{
	ms_open2_u_t* ms = SGX_CAST(ms_open2_u_t*, pms);
	ms->ms_retval = open2_u(ms->ms_path, ms->ms_flags, ms->ms_flags2);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_read_u(void* pms)
{
	ms_read_u_t* ms = SGX_CAST(ms_read_u_t*, pms);
	ms->ms_retval = read_u(ms->ms_fd, ms->ms_buf, ms->ms_nbyte);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_close_u(void* pms)
{
	ms_close_u_t* ms = SGX_CAST(ms_close_u_t*, pms);
	ms->ms_retval = close_u(ms->ms_fd);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_write_u(void* pms)
{
	ms_write_u_t* ms = SGX_CAST(ms_write_u_t*, pms);
	ms->ms_retval = write_u(ms->ms_fd, ms->ms_buf, ms->ms_nbyte);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_dvdcss_open_device_u(void* pms)
{
	ms_dvdcss_open_device_u_t* ms = SGX_CAST(ms_dvdcss_open_device_u_t*, pms);
	ms->ms_retval = dvdcss_open_device_u(ms->ms_dvdcss);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_dvdcss_close_device_u(void* pms)
{
	ms_dvdcss_close_device_u_t* ms = SGX_CAST(ms_dvdcss_close_device_u_t*, pms);
	ms->ms_retval = dvdcss_close_device_u(ms->ms_dvdcss);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_dvdcss_read_u(void* pms)
{
	ms_dvdcss_read_u_t* ms = SGX_CAST(ms_dvdcss_read_u_t*, pms);
	ms->ms_retval = dvdcss_read_u(ms->ms_dvdcss, ms->ms_p_buffer, ms->ms_i_blocks, ms->ms_i_flags);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_ocall_monitorgatewayu(void* pms)
{
	ms_ocall_monitorgatewayu_t* ms = SGX_CAST(ms_ocall_monitorgatewayu_t*, pms);
	ocall_monitorgatewayu(ms->ms_strI, ms->ms_lenI, ms->ms_strO, ms->ms_lenO);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL Enclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[27];
} ocall_table_Enclave = {
	27,
	{
		(void*)Enclave_wrap_ioctl_ReadCopyright,
		(void*)Enclave_wrap_ioctl_ReportRPC,
		(void*)Enclave_wrap_ioctl_InvalidateAgid,
		(void*)Enclave_wrap_ioctl_ReadTitleKey,
		(void*)Enclave_wrap_ioctl_ReportASF,
		(void*)Enclave_wrap_ioctl_SendKey2,
		(void*)Enclave_wrap_ioctl_ReportChallenge,
		(void*)Enclave_wrap_ioctl_ReportKey1,
		(void*)Enclave_wrap_ioctl_SendChallenge,
		(void*)Enclave_wrap_ioctl_ReportAgid,
		(void*)Enclave_wrap_ioctl_ReadDiscKey,
		(void*)Enclave_raw_pf_seek,
		(void*)Enclave_raw_pf_read,
		(void*)Enclave_open_u,
		(void*)Enclave_open2_u,
		(void*)Enclave_read_u,
		(void*)Enclave_close_u,
		(void*)Enclave_write_u,
		(void*)Enclave_dvdcss_open_device_u,
		(void*)Enclave_dvdcss_close_device_u,
		(void*)Enclave_dvdcss_read_u,
		(void*)Enclave_ocall_print_string,
		(void*)Enclave_ocall_monitorgatewayu,
		(void*)Enclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_set_untrusted_event_ocall,
		(void*)Enclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)Enclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t sec_dvdcss_test(sgx_enclave_id_t eid, int* retval, void* dvdcss)
{
	sgx_status_t status;
	ms_sec_dvdcss_test_t ms;
	ms.ms_dvdcss = dvdcss;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sec_dvdcss_title(sgx_enclave_id_t eid, int* retval, void* dvdcss, int i_block)
{
	sgx_status_t status;
	ms_sec_dvdcss_title_t ms;
	ms.ms_dvdcss = dvdcss;
	ms.ms_i_block = i_block;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sec_dvdcss_unscramble(sgx_enclave_id_t eid, int* retval, uint8_t* p_key, uint8_t* p_sec)
{
	sgx_status_t status;
	ms_sec_dvdcss_unscramble_t ms;
	ms.ms_p_key = p_key;
	ms.ms_p_sec = p_sec;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t sec_dvdcss_disckey(sgx_enclave_id_t eid, int* retval, void* dvdcss)
{
	sgx_status_t status;
	ms_sec_dvdcss_disckey_t ms;
	ms.ms_dvdcss = dvdcss;
	status = sgx_ecall(eid, 3, &ocall_table_Enclave, &ms);
	if (status == SGX_SUCCESS && retval) *retval = ms.ms_retval;
	return status;
}

sgx_status_t hello(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 4, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t setBucket(sgx_enclave_id_t eid, bucket_t* b)
{
	sgx_status_t status;
	ms_setBucket_t ms;
	ms.ms_b = b;
	status = sgx_ecall(eid, 5, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t setActionCounter(sgx_enclave_id_t eid, int* ac)
{
	sgx_status_t status;
	ms_setActionCounter_t ms;
	ms.ms_ac = ac;
	status = sgx_ecall(eid, 6, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t bootSecureCommunication(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 7, &ocall_table_Enclave, NULL);
	return status;
}

sgx_status_t makeEndMsg(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 8, &ocall_table_Enclave, NULL);
	return status;
}

