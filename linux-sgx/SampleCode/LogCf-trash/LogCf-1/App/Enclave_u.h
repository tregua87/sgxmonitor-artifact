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

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_MONITORGATEWAYU_DEFINED__
#define OCALL_MONITORGATEWAYU_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_monitorgatewayu, (const char* strI, size_t lenI, char* strO, size_t lenO));
#endif

sgx_status_t hello1(sgx_enclave_id_t eid);
sgx_status_t setBA(sgx_enclave_id_t eid, unsigned long int basic_address);
sgx_status_t bootSecureCommunication(sgx_enclave_id_t eid);
sgx_status_t makeEndMsg(sgx_enclave_id_t eid, unsigned char* strO, size_t lenO);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
