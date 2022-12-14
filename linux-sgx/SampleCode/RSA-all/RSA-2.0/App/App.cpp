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

    return 0;
}

#define REF_N_SIZE_IN_BYTES    384
#define REF_E_SIZE_IN_BYTES    4
#define REF_N_SIZE_IN_UINT     REF_N_SIZE_IN_BYTES/sizeof(unsigned int)
#define REF_E_SIZE_IN_UINT     REF_E_SIZE_IN_BYTES/sizeof(unsigned int)
unsigned int n[REF_N_SIZE_IN_UINT];
unsigned int e[REF_E_SIZE_IN_UINT];

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
    (void)(argc);
    (void)(argv);

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
      cout << "Enter a character before exit ..." << endl;
      getchar();
      return -1;
    }

    unsigned char ct2[384] = { 0 };
    size_t ct_len2 = 0;
    unsigned char ct[384] = { 0 };
    size_t ct_len = 0;
    const unsigned char pt[13] = "Ciao Pirata!";
    size_t pt_len = 13;

    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    ret = rsa_make_public(global_eid, n, e);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    // printf("[INFO] n value (outside the enclave):\n");
    // for (unsigned long i = 0; i < REF_N_SIZE_IN_UINT; i++)
    //   printf("%u ", n[i]);
    // printf("\n");
    // printf("[INFO] e value (outside the enclave):\n");
    // for (unsigned long i = 0; i < REF_E_SIZE_IN_UINT; i++)
    //   printf("%u ", e[i]);
    // printf("\n");

    ret = rsa_import_emit(global_eid, n, e, ct2, &ct_len2);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    printf("[INFO] ct_len2: %d\n", ct_len2);

    ret = rsa_read_decrypt(global_eid, ct2, ct_len2);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    // printf("[INFO] encrypted text (outside the enclave) (2):\n");
    // for (unsigned long i = 0; i < ct_len2; i++)
    //   printf("%02x ", ct2[i]);
    // printf("\n");

    printf("END");

    sgx_destroy_enclave(global_eid);

    return 0;
}
