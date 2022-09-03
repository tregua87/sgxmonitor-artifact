/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include "sgx_trts_exception.h"
#include "sgx_trts.h"


// #define CHECK(ret_code, msg) {if (ret_code != SGX_SUCCESS) {\
//                                 printf("[Error] %s: %x\n", msg, ret_code);\
//                                 return;\
//                               }\
//                               else {\
//                                 printf("[OK!] %s: %x\n", msg, ret_code);\
//                               }}
//

/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */

int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}


int a(int x) __attribute__((annotate("toTrace"))) {return x*5;}
int b(int x) __attribute__((annotate("toTrace"))) {return x*3;}

void hello1(int y)
{
  int (*fun_ptr)(int) = NULL;

  for (int i = 1;i <= 2;i++) {

    if (i % 2 == 0)
      fun_ptr = a;
    else
      fun_ptr = b;

    int x = fun_ptr(i);

    if (x == 1)
      printf("first print [%d]!\n", x);
    else
      printf("%d print [%d]!\n", i, x);
  }
}

void hello2() {
  printf("second test\n");
}


int n = 0;

int divide_by_zero_handler(sgx_exception_info_t* info) {

    n = 10; // fix the exception
    return EXCEPTION_CONTINUE_EXECUTION;
}


int test_exception(int i) {

  if (sgx_register_exception_handler(1, divide_by_zero_handler) == NULL) {
      printf("register failed\n");
  } else {
      printf("register success\n");
  }

  printf("result %d!\n", i);

  return i/n;
}
