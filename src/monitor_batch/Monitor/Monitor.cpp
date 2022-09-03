#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "Sock.h"
#include "Utility.h"

#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */
#include "sgx_urts.h"
#include "sgx_uae_service.h"
#include "Enclave_u.h"
#include <errno.h>

#include "crypto_utils.h"

#include "Async_Bucket.h"
#include <pthread.h>

// PUBLIC bucket for asnyc communication
static bucket_t pub_bucket;

# define TOKEN_FILENAME   "enclavem.token"
# define ENCLAVE_FILENAME "enclavem.signed.so"

sgx_enclave_id_t global_eid;    /* global enclave */

#include <string>
#include <iostream>

using namespace std;

int ret;
double nap_time = 0.01;
short exit_loop = false;
void *receiver_client(void *arg) {
  // I know this sucks..

  cout << "Receiver client" << endl;

  sgx_enclave_id_t eid = (sgx_enclave_id_t)arg;

  // the thread is handled inside the enclae
  sgx_status_t r = startConsumer(eid);
  if (r != SGX_SUCCESS)
    print_error_message(r);
  pthread_exit(&ret);
}

void ocall_print_string(const char *str) {printf("%s", str);} // OCALL to print

void makeInitMessage(char* buffer, size_t buffer_len, unsigned char* k,
                      size_t k_len, unsigned char* nonce, size_t nonce_len) {

    // buffer = n|e

    memset(buffer, 0, buffer_len);

    memcpy(buffer, k, k_len);
    memcpy(buffer + k_len, nonce, nonce_len);

    // printf("Buffer:\n");
    // for (int i = 0; i < nc_len + ec_len; i++)
    //   printf("%x ", buffer[i]);
    // printf("\n");

    // exit(0);

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

void report(const char* msg, int terminate) {
  cerr << msg << endl;
  if (terminate) exit(-1); /* failure */
}

void dumpEdges(long msgs) {
  cout << "MSGS: " << msgs << endl;
}

#define WAITING 'W'
#define RECEDGE 'R'

char monitor_status = WAITING;
buffer_t buff;

void printModel();

int readExactSize(int socket, void* buff, size_t sizeToRead) {

  size_t remainingSize = sizeToRead;

  while (remainingSize > 0) {
    ssize_t count = read(socket, buff, remainingSize);
    if (count < 0) {
      // report("read waiting 2", 0);
      printf("errno %s\n", strerror(errno));
      return -1;
      // continue;
    }
    if (count == 0) {
      if (remainingSize == 0) {
        // printf("RETURN 0\n");
        return 0;
      }
      if (remainingSize == sizeToRead) {
        // printf("RETURN -2\n");
        return -2; // successfully break
      }
      // printf("RETURN -1\n");
      return -1;
    }
    remainingSize -= count;
    buff = (void*)((unsigned long)buff + (unsigned long)count);
  }
  return 0;
}

int main() {

  /* Initialize the enclave */
  if (initialize_enclave() < 0) {
    cout << "Enter a character before exit ..." << endl;
    getchar();
    return -1;
  }

  INIT_BUCKET(pub_bucket);
  setBucket(global_eid, &pub_bucket, &exit_loop);

  pthread_t receiver;
  ret = pthread_create(&receiver, NULL, receiver_client, (void *)global_eid);
  if (ret) {
     cout << "Error:unable to create thread," << ret << endl;
     exit(-1);
  }

  int fd = socket(AF_INET,     /* network versus AF_LOCAL */
                  SOCK_STREAM, /* reliable, bidirectional, arbitrary payload size */
                  0);          /* system picks underlying protocol (TCP) */
  if (fd < 0) report("socket", 1); /* terminate */

  /* bind the server's local address in memory */
  struct sockaddr_in saddr;
  memset(&saddr, 0, sizeof(saddr));          /* clear the bytes */
  saddr.sin_family = AF_INET;                /* versus AF_LOCAL */
  saddr.sin_addr.s_addr = htonl(INADDR_ANY); /* host-to-network endian */
  saddr.sin_port = htons(PortNumber);        /* for listening */

  if (bind(fd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0)
    report("bind", 1); /* terminate */

  /* listen to the socket */
  if (listen(fd, MaxConnects) < 0) /* listen for clients, up to MaxConnects */
    report("listen", 1); /* terminate */

  cout << "Listening on port " << PortNumber << "  for clients..." << endl;
  struct sockaddr_in caddr; /* client address */
  socklen_t len = sizeof(caddr);  /* address length could change */

  int client_fd = accept(fd, (struct sockaddr*) &caddr, &len);  /* accept blocks */
  if (client_fd < 0)
    report("accept", 1);

  // int val = 1;
  // if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val)) < 0)
  //     perror("setsockopt(2) error");

  /* read from client */
  int i, cntmsg = 0;
  // string pK("");
  while(!exit_loop) {
    char buffer[BuffSize + 1] = { 0 };
    // char msg[384];
    // memset(buffer, '\0', sizeof(buffer));
      // puts(buffer);

    if (monitor_status == WAITING) {

      int count = read(client_fd, buffer, sizeof(buffer));
      if (count <= 0) report("read waiting 1", 0);

      cout  << "(Input, Status) = (" << string(buffer)
            << "," << monitor_status << ")" << endl;

      // BINIT => the Traget Enclave inits itself by asking for the public key (n,e)
      //          and the nonce.
      // TODO: add the remote attestation somewhere
      if (strcmp(buffer,"BINIT") == 0) {
        cout << "I send keys/nonce" << endl;
        // make public/private keys + nonce

        unsigned char k[OPT_KEY_SIZE_BYTE];
        unsigned char nonce[REF_NONCE_SIZE];
        if (SGX_SUCCESS != generateSecrets(global_eid, k, nonce)) {
          cout << "Error secret generation..." << endl;
          getchar();
          return -1;
        }

        // PRINT_ARR("[INFO] k:\n", k, OPT_KEY_SIZE_BYTE);
        // PRINT_ARR("[INFO] nonce:\n", nonce, REF_NONCE_SIZE);
        makeInitMessage(buffer, sizeof(buffer), k, OPT_KEY_SIZE_BYTE,
                                                nonce, REF_NONCE_SIZE);

        // return things
        write(client_fd, buffer, sizeof(buffer));

        monitor_status = RECEDGE;
      }
      else {
        report(buffer, 1);
      }
    }
    else {
      cntmsg++;
      // cout << "c: " << cntmsg << endl;

      // int count = read(client_fd, buffer, sizeof(buffer));
      int readResult = readExactSize(client_fd, &buff, sizeof(buff));
      if (readResult == -1)
        break;
      if (readResult == -2)
        continue;
      // ssize_t count = read(client_fd, &buff, sizeof(buff));
      // if (count <= 0) {
      //   report("read waiting 2", 0);
      //   printf("errno %s\n", strerror(errno));
      // }
      // else {
      //   printf("read is correct\n");
      // }
      //
      // if (count != sizeof(buff)) {
      //   printf("size is not ok\n");
      //   printf("count: %lu\n", count);
      //   printf(" sizeof(buff): %lu\n",  sizeof(buff));
      // }

      // cout << "get buff" << endl;

      // move buff to bucket
      for (int x = 0; x < BUFFER_SIZE; x++) {
        while (pub_bucket.entries[pub_bucket.idx].status != WHITE);
        // {
          // cout << "bucket[" << pub_bucket.idx << "] is " << pub_bucket.entries[pub_bucket.idx].status << endl;
          // sleep(1);
        // }

        // printf("[INFO] (monitor) crypted buff receiver:\n");
        // for (int i = 0; i < ENTRY_SIZE; i++)
        //   printf("%02X ", buff.entries[x].buf[i]);
        // printf("\n");

        pub_bucket.entries[pub_bucket.idx].status = GRAY;
        // OLD NOT WORKING
        // memcpy(pub_bucket.entries[pub_bucket.idx].buf, &buff.entries[x], ENTRY_SIZE);
        memcpy(pub_bucket.entries[pub_bucket.idx].buf, buff.entries[x].buf, ENTRY_SIZE);
        // usually BLACK, that's RED when the ecall ends
        // cout << "status: " << buff.entries[x].status << endl;
        if (buff.entries[x].status == RED) {
          // cout << "Found a red" << endl;
          pub_bucket.entries[pub_bucket.idx].status = RED;
          // exit_loop = true;
          // break;
        }
        else {
          // cout << "Found a black" << endl;
          pub_bucket.entries[pub_bucket.idx].status = BLACK;
        }
        pub_bucket.idx = (pub_bucket.idx + 1) % BUCKET_SIZE;
      }

      // check flag
      if (exit_loop)
        break;

      // echo!
      // char b2[] = {0};
      // write(client_fd, b2, sizeof(b2)); /* echo as confirmation */
    }
  }
  close(client_fd); /* break connection */

  printModel(global_eid);

  pthread_exit(NULL);
  void *rett;
  pthread_join(receiver, &rett);

  sgx_destroy_enclave(global_eid);

  cout << "I received " << cntmsg << " messages" << endl;

  return 0;
}
