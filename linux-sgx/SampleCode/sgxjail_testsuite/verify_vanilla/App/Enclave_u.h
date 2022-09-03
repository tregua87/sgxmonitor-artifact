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

typedef struct struct_t {
	uint16_t x;
	uint32_t y;
	uint64_t z;
} struct_t;

typedef enum enum_t {
	ENUM_X = 0,
	ENUM_Y = 1,
	ENUM_Z = 1000,
} enum_t;

typedef union union_t {
	uint64_t x;
	uint64_t y;
	uint64_t z;
} union_t;

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL0_DEFINED__
#define OCALL0_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall0, (void));
#endif
#ifndef OCALL1_DEFINED__
#define OCALL1_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall1, (char a, int b, float c, double d, size_t e, wchar_t f));
#endif
#ifndef OCALL2_DEFINED__
#define OCALL2_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall2, (struct struct_t a, enum enum_t b, enum enum_t c, enum enum_t d, union union_t u));
#endif
#ifndef OCALL3_DEFINED__
#define OCALL3_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, ocall3, (int a[2], int b[2], int c[2]));
#endif
#ifndef TESTOCALLNESTED1_DEFINED__
#define TESTOCALLNESTED1_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, testOcallNested1, (int level, int a[2], int b[2]));
#endif
#ifndef TESTOCALLNESTED2_DEFINED__
#define TESTOCALLNESTED2_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, testOcallNested2, (int level, int a[2], int b[2]));
#endif
#ifndef TESTOCALLRECURSIVE_DEFINED__
#define TESTOCALLRECURSIVE_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, testOcallRecursive, (int level, int a[2], int b[2]));
#endif

sgx_status_t testEcall0(sgx_enclave_id_t eid);
sgx_status_t testEcall1(sgx_enclave_id_t eid, int* retval, char a, int b, float c, double d, size_t e, wchar_t f);
sgx_status_t testEcall2(sgx_enclave_id_t eid, int* retval, struct struct_t a, enum enum_t b, enum enum_t c, enum enum_t d, union union_t u);
sgx_status_t testEcall3(sgx_enclave_id_t eid, int* retval, int a[2], int b[2], int c[2]);
sgx_status_t testEcall4(sgx_enclave_id_t eid, int* retval, char* s1, const char* s2, char* s3);
sgx_status_t testOcallSimple(sgx_enclave_id_t eid, int* retval, char dummy);
sgx_status_t testEcallNested1(sgx_enclave_id_t eid, int* retval, int level, int a[2], int b[2]);
sgx_status_t testEcallNested2(sgx_enclave_id_t eid, int* retval, int level, int a[2], int b[2]);
sgx_status_t testEcallRecursive(sgx_enclave_id_t eid, int* retval, int level, int a[2], int b[2]);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
