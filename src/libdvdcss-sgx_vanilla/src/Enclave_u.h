#ifndef ENCLAVE_U_H__
#define ENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef WRAP_IOCTL_READCOPYRIGHT_DEFINED__
#define WRAP_IOCTL_READCOPYRIGHT_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, wrap_ioctl_ReadCopyright, (int i_fd, int i_layer, int* pi_copyright));
#endif
#ifndef WRAP_IOCTL_REPORTRPC_DEFINED__
#define WRAP_IOCTL_REPORTRPC_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, wrap_ioctl_ReportRPC, (int i_fd, int* p_type, int* p_mask, int* p_scheme));
#endif
#ifndef WRAP_IOCTL_INVALIDATEAGID_DEFINED__
#define WRAP_IOCTL_INVALIDATEAGID_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, wrap_ioctl_InvalidateAgid, (int i_fd, int* pi_agid));
#endif
#ifndef WRAP_IOCTL_READTITLEKEY_DEFINED__
#define WRAP_IOCTL_READTITLEKEY_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, wrap_ioctl_ReadTitleKey, (int i_fd, int* pi_agid, int i_pos, uint8_t* p_key));
#endif
#ifndef WRAP_IOCTL_REPORTASF_DEFINED__
#define WRAP_IOCTL_REPORTASF_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, wrap_ioctl_ReportASF, (int i_fd, int* pi_asf));
#endif
#ifndef WRAP_IOCTL_SENDKEY2_DEFINED__
#define WRAP_IOCTL_SENDKEY2_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, wrap_ioctl_SendKey2, (int i_fd, int* pi_agid, uint8_t* p_key));
#endif
#ifndef WRAP_IOCTL_REPORTCHALLENGE_DEFINED__
#define WRAP_IOCTL_REPORTCHALLENGE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, wrap_ioctl_ReportChallenge, (int i_fd, int* pi_agid, uint8_t* p_challenge));
#endif
#ifndef WRAP_IOCTL_REPORTKEY1_DEFINED__
#define WRAP_IOCTL_REPORTKEY1_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, wrap_ioctl_ReportKey1, (int i_fd, int* pi_agid, uint8_t* p_key));
#endif
#ifndef WRAP_IOCTL_SENDCHALLENGE_DEFINED__
#define WRAP_IOCTL_SENDCHALLENGE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, wrap_ioctl_SendChallenge, (int i_fd, int* pi_agid, uint8_t* p_challenge));
#endif
#ifndef WRAP_IOCTL_REPORTAGID_DEFINED__
#define WRAP_IOCTL_REPORTAGID_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, wrap_ioctl_ReportAgid, (int i_fd, int* pi_agid));
#endif
#ifndef WRAP_IOCTL_READDISCKEY_DEFINED__
#define WRAP_IOCTL_READDISCKEY_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, wrap_ioctl_ReadDiscKey, (int i_fd, int* pi_agid, uint8_t* p_key));
#endif
#ifndef RAW_PF_SEEK_DEFINED__
#define RAW_PF_SEEK_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, raw_pf_seek, (void* self, void* dvdcss, int pos));
#endif
#ifndef RAW_PF_READ_DEFINED__
#define RAW_PF_READ_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, raw_pf_read, (void* self, void* dvdcss, void* buff, int pos));
#endif
#ifndef OPEN_U_DEFINED__
#define OPEN_U_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, open_u, (char* path, int flags));
#endif
#ifndef OPEN2_U_DEFINED__
#define OPEN2_U_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, open2_u, (char* path, int flags, int flags2));
#endif
#ifndef READ_U_DEFINED__
#define READ_U_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, read_u, (int fd, void* buf, size_t nbyte));
#endif
#ifndef CLOSE_U_DEFINED__
#define CLOSE_U_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, close_u, (int fd));
#endif
#ifndef WRITE_U_DEFINED__
#define WRITE_U_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, write_u, (int fd, void* buf, size_t nbyte));
#endif
#ifndef DVDCSS_OPEN_DEVICE_U_DEFINED__
#define DVDCSS_OPEN_DEVICE_U_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, dvdcss_open_device_u, (void* dvdcss));
#endif
#ifndef DVDCSS_CLOSE_DEVICE_U_DEFINED__
#define DVDCSS_CLOSE_DEVICE_U_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, dvdcss_close_device_u, (void* dvdcss));
#endif
#ifndef DVDCSS_READ_U_DEFINED__
#define DVDCSS_READ_U_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, dvdcss_read_u, (void* dvdcss, void* p_buffer, int i_blocks, int i_flags));
#endif
#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif

sgx_status_t sec_dvdcss_test(sgx_enclave_id_t eid, int* retval, void* dvdcss);
sgx_status_t sec_dvdcss_title(sgx_enclave_id_t eid, int* retval, void* dvdcss, int i_block);
sgx_status_t sec_dvdcss_unscramble(sgx_enclave_id_t eid, int* retval, uint8_t* p_key, uint8_t* p_sec);
sgx_status_t sec_dvdcss_disckey(sgx_enclave_id_t eid, int* retval, void* dvdcss);
sgx_status_t hello(sgx_enclave_id_t eid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
