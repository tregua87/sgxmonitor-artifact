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


int a(int x) __attribute__((annotate("toTrace"))) {return x*10;}
int b(int x) __attribute__((annotate("toTrace"))) {return x*10;}

void hello1(int y) __attribute__((annotate("toTrace")))
{
  printf("a string!\n");

  // int (*fun_ptr)(int) = NULL;
  //
  // for (int i = 1;i <= 2000;i++) {
  //
  //   if (y % 2 == 0)
  //     fun_ptr = a;
  //   else
  //     fun_ptr = b;
  //
  //   int x = fun_ptr(y);
  //   // int x = i;
  //
  //   if (x == 1)
  //     printf("1 bacione x []!\n", x);
  //   else
  //     printf("%d bacioni!\n", i, x);
  // }
}
