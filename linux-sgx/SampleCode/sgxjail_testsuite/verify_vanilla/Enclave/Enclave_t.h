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

void testEcall0(void);
int testEcall1(char a, int b, float c, double d, size_t e, wchar_t f);
int testEcall2(struct struct_t a, enum enum_t b, enum enum_t c, enum enum_t d, union union_t u);
int testEcall3(int a[2], int b[2], int c[2]);
int testEcall4(char* s1, const char* s2, char* s3);
int testOcallSimple(char dummy);
int testEcallNested1(int level, int a[2], int b[2]);
int testEcallNested2(int level, int a[2], int b[2]);
int testEcallRecursive(int level, int a[2], int b[2]);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall0(void);
sgx_status_t SGX_CDECL ocall1(int* retval, char a, int b, float c, double d, size_t e, wchar_t f);
sgx_status_t SGX_CDECL ocall2(int* retval, struct struct_t a, enum enum_t b, enum enum_t c, enum enum_t d, union union_t u);
sgx_status_t SGX_CDECL ocall3(int* retval, int a[2], int b[2], int c[2]);
sgx_status_t SGX_CDECL testOcallNested1(int* retval, int level, int a[2], int b[2]);
sgx_status_t SGX_CDECL testOcallNested2(int* retval, int level, int a[2], int b[2]);
sgx_status_t SGX_CDECL testOcallRecursive(int* retval, int level, int a[2], int b[2]);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
