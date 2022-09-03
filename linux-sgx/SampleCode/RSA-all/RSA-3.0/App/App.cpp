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


#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <ctime>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#include "Utility.h"

#include <iostream>
using namespace std;

unsigned long getEnclaveBaseAddress(void);

// socket of the monitor
int sockfd;

int maxCycle;

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    ret = rsa_init(global_eid);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    double sumEncTime = 0;
    double sumDecTime = 0;

    int i;
    // double elapsed_secs;
    clock_t begin, end;
    for (i = 0; i < maxCycle; i++) {

      begin = clock();
      ret = rsa_enc(global_eid);
      if (ret != SGX_SUCCESS) {
          print_error_message(ret);
          return -1;
      }
      end = clock();
      sumEncTime += double(end - begin) / CLOCKS_PER_SEC;

      begin = clock();
      ret = rsa_dec(global_eid);
      if (ret != SGX_SUCCESS) {
          print_error_message(ret);
          return -1;
      }
      end = clock();
      sumDecTime += double(end - begin) / CLOCKS_PER_SEC;

    }

    cout << "N. of test: " << maxCycle << endl;
    cout << "Avg. enc time [s]: " << fixed << (sumEncTime/(double)maxCycle) << endl;
    cout << "Avg. dec time [s]: " << fixed << (sumDecTime/(double)maxCycle) << endl;

    sgx_destroy_enclave(global_eid);

    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    // (void)(argc);
    // (void)(argv);

    if (argc == 2)
      maxCycle = atoi(argv[1]);
    else
      maxCycle = 1000;

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
      cout << "Enter a character before exit ..." << endl;
      getchar();
      return -1;
    }

    return 0;
}
