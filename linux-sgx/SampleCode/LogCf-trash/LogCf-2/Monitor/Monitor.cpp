#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "Sock.h"
#include "Utility.h"

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */
#include "sgx_urts.h"
#include "sgx_uae_service.h"
#include "Enclave_u.h"

#include "crypto_utils.h"

# define TOKEN_FILENAME   "enclavem.token"
# define ENCLAVE_FILENAME "enclavem.signed.so"

sgx_enclave_id_t global_eid;    /* global enclave */

#include <string>
#include <iostream>

using namespace std;

void ocall_print_string(const char *str) {printf("%s", str);} // OCALL to print

void makeInitMessage(char* buffer, size_t buffer_len, unsigned int* n,
                      size_t n_len, unsigned int* e, size_t e_len,
                      unsigned char* nonce, size_t nonce_len) {

    // buffer = n|e

    memset(buffer, 0, buffer_len);

    unsigned char *nc = (unsigned char*)n;
    size_t nc_len = n_len * sizeof(unsigned int); // I need a length in bytes

    unsigned char *ec = (unsigned char*)e;
    size_t ec_len = e_len * sizeof(unsigned int); // I need a length in bytes

    memcpy(buffer, nc, nc_len);
    memcpy(buffer + nc_len, ec, ec_len);
    memcpy(buffer + nc_len + ec_len, nonce, nonce_len);

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

#define WAITING 'W'
#define RECEDGE 'R'

char monitor_status = WAITING;

void printModel();

int main() {

  /* Initialize the enclave */
  if(initialize_enclave() < 0){
    cout << "Enter a character before exit ..." << endl;
    getchar();
    return -1;
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

  /* read from client */
  int i;
  // string pK("");
  while(1) {
    char buffer[BuffSize + 1];
    char msg[384];
    memset(buffer, '\0', sizeof(buffer));
    int count = read(client_fd, buffer, sizeof(buffer));
    if (count > 0) {
      // puts(buffer);

      if (monitor_status == WAITING) {
        cout  << "(Input, Status) = (" << string(buffer)
              << "," << monitor_status << ")" << endl;

        // BINIT => the Traget Enclave inits itself by asking for the public key (n,e)
        //          and the nonce.
        // TODO: add the remote attestation somewhere
        if (strcmp(buffer,"BINIT") == 0) {
          cout << "I send keys/nonce" << endl;
          // make public/private keys + nonce

          // I just send (n,e) in string format, manual parsing
          unsigned int n[REF_N_SIZE_IN_UINT];
          unsigned int e[REF_E_SIZE_IN_UINT];
          unsigned char nonce[REF_NONCE_SIZE];
          if (SGX_SUCCESS != generateSecrets(global_eid, n, e, nonce)) {
            cout << "Error secret generation..." << endl;
            getchar();
            return -1;
          }

          // PRINT_ARR("[INFO] n value (outside the enclave):\n", n, REF_N_SIZE_IN_UINT);
          // PRINT_ARR("[INFO] e value (outside the enclave):\n", e, REF_E_SIZE_IN_UINT);
          makeInitMessage(buffer, sizeof(buffer), n, REF_N_SIZE_IN_UINT,
                                                  e, REF_E_SIZE_IN_UINT,
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

        char res;
        sgx_status_t ret_code = decrypt(global_eid, (unsigned char*)buffer, count, &res);
        if (ret_code != SGX_SUCCESS) break;

        // B means break!
        if (res == 'B')
          break;
        else if (res == 'X') {
          cout << "Unpredictable error" << endl;
          break;
        }
        write(client_fd, buffer, sizeof(buffer)); /* echo as confirmation */
      }

    }
  }
  close(client_fd); /* break connection */

  // cout << "Printing model:" << endl;
  // printModel();
  printModel(global_eid);

  sgx_destroy_enclave(global_eid);

  return 0;
}
