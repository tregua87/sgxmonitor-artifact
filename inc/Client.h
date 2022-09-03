// THIS HEADER CONTAINS THE STUFFS FOR SOCKET AND NETWORK COMMUNIATIONS

#ifndef __CLIENT_H_
#define __CLIENT_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

# include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include "Sock.h"

#include "Async_Bucket.h"
#include <pthread.h>

// int initialize_client(short);
void send_entry(const unsigned char*, short);

#pragma once
#ifdef __cplusplus
extern "C" {
#endif
void ocall_monitorgatewayu(const char*, size_t, char*, size_t);
int initialize_client(short);
#ifdef __cplusplus
}
#endif

void close_client(void);
void *send_client(void*);

#endif
