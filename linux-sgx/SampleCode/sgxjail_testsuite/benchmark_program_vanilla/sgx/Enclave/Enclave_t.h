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

void testOcalls(size_t amount_of_ocalls, size_t max);
void testEcalls(int dummy);
void testOcallsSingle(int dummy);

sgx_status_t SGX_CDECL testOcall(int dummy);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
