#ifndef ENCLAVE_T_H__
#define ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

int sec_dvdcss_test(void* dvdcss);
int sec_dvdcss_title(void* dvdcss, int i_block);
int sec_dvdcss_unscramble(uint8_t* p_key, uint8_t* p_sec);
int sec_dvdcss_disckey(void* dvdcss);
void hello(void);

sgx_status_t SGX_CDECL wrap_ioctl_ReadCopyright(int* retval, int i_fd, int i_layer, int* pi_copyright);
sgx_status_t SGX_CDECL wrap_ioctl_ReportRPC(int* retval, int i_fd, int* p_type, int* p_mask, int* p_scheme);
sgx_status_t SGX_CDECL wrap_ioctl_InvalidateAgid(int* retval, int i_fd, int* pi_agid);
sgx_status_t SGX_CDECL wrap_ioctl_ReadTitleKey(int* retval, int i_fd, int* pi_agid, int i_pos, uint8_t* p_key);
sgx_status_t SGX_CDECL wrap_ioctl_ReportASF(int* retval, int i_fd, int* pi_asf);
sgx_status_t SGX_CDECL wrap_ioctl_SendKey2(int* retval, int i_fd, int* pi_agid, uint8_t* p_key);
sgx_status_t SGX_CDECL wrap_ioctl_ReportChallenge(int* retval, int i_fd, int* pi_agid, uint8_t* p_challenge);
sgx_status_t SGX_CDECL wrap_ioctl_ReportKey1(int* retval, int i_fd, int* pi_agid, uint8_t* p_key);
sgx_status_t SGX_CDECL wrap_ioctl_SendChallenge(int* retval, int i_fd, int* pi_agid, uint8_t* p_challenge);
sgx_status_t SGX_CDECL wrap_ioctl_ReportAgid(int* retval, int i_fd, int* pi_agid);
sgx_status_t SGX_CDECL wrap_ioctl_ReadDiscKey(int* retval, int i_fd, int* pi_agid, uint8_t* p_key);
sgx_status_t SGX_CDECL raw_pf_seek(int* retval, void* self, void* dvdcss, int pos);
sgx_status_t SGX_CDECL raw_pf_read(int* retval, void* self, void* dvdcss, void* buff, int pos);
sgx_status_t SGX_CDECL open_u(int* retval, char* path, int flags);
sgx_status_t SGX_CDECL open2_u(int* retval, char* path, int flags, int flags2);
sgx_status_t SGX_CDECL read_u(int* retval, int fd, void* buf, size_t nbyte);
sgx_status_t SGX_CDECL close_u(int* retval, int fd);
sgx_status_t SGX_CDECL write_u(int* retval, int fd, void* buf, size_t nbyte);
sgx_status_t SGX_CDECL dvdcss_open_device_u(int* retval, void* dvdcss);
sgx_status_t SGX_CDECL dvdcss_close_device_u(int* retval, void* dvdcss);
sgx_status_t SGX_CDECL dvdcss_read_u(int* retval, void* dvdcss, void* p_buffer, int i_blocks, int i_flags);
sgx_status_t SGX_CDECL ocall_print_string(const char* str);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
