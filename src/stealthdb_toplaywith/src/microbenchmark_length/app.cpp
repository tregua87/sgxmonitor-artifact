#include "sgx_urts.h"
#include "enclave_u.h"

#include "app/App.h"

#include <fcntl.h>

#include "defs.h"

#include <fstream>
#include <iostream>
#include <unistd.h>
#include <pwd.h>

#include "Dump.h"
#include "Client.h"
#include "Async_Bucket.h"

#define MODE "traced_length"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
extern bucket_t bucket;
int actionCounter;

int initilize_ra() {

  // for the fucking remote attestation!
  // https://github.com/intel/sgx-ra-sample

  // other peoples with my problems:
  // https://software.intel.com/en-us/forums/intel-software-guard-extensions-intel-sgx/topic/814779

  bootSecureCommunication(global_eid);

  return 0;
}


using namespace std;


int main(int argc, char** argv) {

	sgx_launch_token_t token = {0};
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  int updated;

  // 0 -> single entries fashion
  if(initialize_client(0) < 0) {
    cout << "Enter a character before exit ..." << endl;
    getchar();
    return -1;
  }

	cout << "Enclave file: " << ENCLAVE_FILENAME << endl;
  ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
  if (ret != SGX_SUCCESS) {
    cout << "Error enclave creation\nEnter a character before exit ..." << endl;
		cout << "Errocode: " << hex << ret << endl;
    getchar();
    return -1;
  }

  if(initilize_ra() < 0) {
    cout << "Enter a character before exit ..." << endl;
    getchar();
    return -1;
  }

  setActionCounter(global_eid, &actionCounter);
  setBucket(global_eid, &bucket);

  printf("[INFO] Start warmup!\n");


  int resp_enclave2;
	uint8_t* sealed_key_b_X = new uint8_t[SEALED_KEY_LENGTH];

  generateKeyEnclave(global_eid, &resp_enclave2, sealed_key_b_X, SEALED_KEY_LENGTH);
  dumpLen(MODE, "generateKeyEnclave", &actionCounter);
  loadKeyEnclave(global_eid, &resp_enclave2, sealed_key_b_X, SEALED_KEY_LENGTH);
  dumpLen(MODE, "loadKeyEnclave", &actionCounter);

  printf("[INFO] StealthDB successfully returned.\n");

  makeEndMsg(global_eid);

  /* Destroy the enclave */
  sgx_destroy_enclave(global_eid);

  // cout << "Close POC" << endl;
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