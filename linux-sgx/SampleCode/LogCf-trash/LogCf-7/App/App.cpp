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

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include "Sock.h"
#include "Utility.h"

#include "async_bucket.h"
#include <pthread.h>

#include <iostream>
using namespace std;

unsigned long getEnclaveBaseAddress(void);

// socket of the monitor
int sockfd;

// PUBLIC bucket for asnyc communication
static bucket b;

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

// initilize the client socket
int initialize_client(void)
{
    /* fd for the socket */
    sockfd = socket(AF_INET,      /* versus AF_LOCAL */
                      SOCK_STREAM,  /* reliable, bidirectional */
                      0);           /* system picks protocol (TCP) */
    if (sockfd < 0) {
      printf("Error Socket\n");
      return -1;
    }

    /* get the address of the host */
    struct hostent* hptr = gethostbyname(Host); /* localhost: 127.0.0.1 */
    if (!hptr) {
      printf("Error Hostname\n");
      return -1;
    }
    if (hptr->h_addrtype != AF_INET) {       /* versus AF_LOCAL */
      printf("bad address family\n");
      return -1;
    }

    /* connect to the server: configure server's address 1st */
    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = ((struct in_addr*) hptr->h_addr_list[0])->s_addr;
    saddr.sin_port = htons(PortNumber); /* port number in big-endian */

    if (connect(sockfd, (struct sockaddr*) &saddr, sizeof(saddr)) < 0) {
      printf("connect\n");
      return -1;
    }
    return 0;
}

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

void ocall_monitorgatewayu(const char *strI, size_t lenI,
                           char *strO, size_t lenO)
{
  // cout << "[INFO] sync" << endl;
  /* Write some stuff and read the echoes. */
  if (write(sockfd, strI, lenI) > 0) {
    /* get confirmation echoed from server and print */
    char buffer[BuffSize + 1];
    memset(buffer, '\0', sizeof(buffer));
    if (read(sockfd, buffer, sizeof(buffer)) < 0) {
      printf("Error echo");
      exit(-1);
    }
    #define PRINT_ARR(msg,obj,len) {printf("%s", msg);\
                                for (unsigned long i = 0; i < len; i++)\
                                  printf("%u ", obj[i]); \
                                printf("\n");}
    // PRINT_ARR("[INFO] buffer received:\n", buffer, strlen(buffer));
    if (strO && lenO) {
      memcpy(strO, buffer, lenO);
    }
  }
}

int ret;
double nap_time = 0.01;
void *send_client(void *arg) {
  // I know this sucks..

  unsigned long i = 0;
  while(1) {
    // sleep(nap_time);
    if (b.entries[i].status == RED) {
      ocall_monitorgatewayu((const char*)(b.entries[i].buf), ENTRY_SIZE, NULL, NULL);
      cout << "[INFO] close the socket " << endl;
      close(sockfd);
      pthread_exit(&ret);
    }
    if (b.entries[i].status == BLACK) {
      ocall_monitorgatewayu((const char*)(b.entries[i].buf), ENTRY_SIZE, NULL, NULL);
      // memset(b.entries[i].buf, 0, ENTRY_SIZE);
      b.entries[i].status = WHITE;

      // increase read counter
      i = (i + 1) % BUCKET_SIZE;
    }
    if (b.entries[i].status == WHITE || b.entries[i].status == GRAY)
      continue;
  }
}

// guide for LLVM http://llvm.org/docs/WritingAnLLVMPass.html

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);

    if(initialize_client() < 0) {
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

    if(initilize_ra() < 0) {
      cout << "Enter a character before exit ..." << endl;
      getchar();
      return -1;
    }

    unsigned long bA = getEnclaveBaseAddress();

    printf("BA: 0x%lx\n",bA);

    setBA(global_eid, bA);

    INIT_BUCKET(b);

    pthread_t sender;
    if (USE_BUFFER) {
      ret = pthread_create(&sender, NULL, send_client, NULL);
      if (ret) {
         cout << "Error:unable to create thread," << ret << endl;
         exit(-1);
      }
    }
    setBucket(global_eid, &b);

    hello1(global_eid);

    printf("[INFO] SampleEnclave successfully returned.\n");

    // unsigned char msg[384];
    // makeEndMsg(global_eid, msg, sizeof(msg));
    makeEndMsg(global_eid);
    // if (write(sockfd, msg, sizeof(msg)) > 0)
    if (!USE_BUFFER)
      close(sockfd); /* close the connection */

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    // clean up all the threads
    pthread_exit(NULL);
    void *rett;
    pthread_join(sender, &rett);

    return 0;
}

unsigned long getEnclaveBaseAddress() {
  FILE * fp;
  char * line = NULL;
  size_t len = 0;
  ssize_t read;

  pid_t p = getpid();

  char fPath[100] = { 0 };
  //printf("PID = %d\n", p);

  snprintf(fPath, 100, "/proc/%d/maps", p);

  //printf("map file: %s\n", fPath);

  fp = fopen(fPath, "r");
  if (fp == NULL) {
      printf("fail opening: %s\n", fPath);
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
    // printf("There is at least an enclave\n");
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
    exit(EXIT_FAILURE);
  }

  exit(EXIT_SUCCESS);
}
