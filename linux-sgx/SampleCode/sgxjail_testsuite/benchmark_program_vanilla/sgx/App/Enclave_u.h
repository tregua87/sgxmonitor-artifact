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

#ifndef TESTOCALL_DEFINED__
#define TESTOCALL_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, testOcall, (int dummy));
#endif

sgx_status_t testOcalls(sgx_enclave_id_t eid, size_t amount_of_ocalls, size_t max);
sgx_status_t testEcalls(sgx_enclave_id_t eid, int dummy);
sgx_status_t testOcallsSingle(sgx_enclave_id_t eid, int dummy);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
