// THIS HEADER CONTAINS THE STUFFS FOR INCLUDING A LOCAL MONITOR
// (a one that does not rely on socket)

#ifndef __MONITORLOCAL_H_
#define __MONITORLOCAL_H_

#include "Async_Bucket.h"
#include <pthread.h>

#include "sgx_urts.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "Utility2.h"
#include "crypto_utils.h"
#include "Sock.h"

#define TOKEN_MONITOR_FILENAME   "enclavem.token"
#define ENCLAVE_MONITOR_FILENAME "enclavem.signed.so"


extern "C" void ocall_monitorgatewayu(const char*, size_t, char*, size_t);
void closeMonitorAndPrintModel(void);
int initialize_monitorlocal(void);
void *send_client(void *arg);

#endif
