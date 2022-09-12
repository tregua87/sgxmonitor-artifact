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

#define MODE "vanilla"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
extern bucket_t bucket;
int actionCounter;

using namespace std;


int main(int argc, char** argv) {

	sgx_launch_token_t token = {0};
  sgx_status_t ret = SGX_ERROR_UNEXPECTED;
  int updated;

	cout << "Enclave file: " << ENCLAVE_FILENAME << endl;
  ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
  if (ret != SGX_SUCCESS) {
    cout << "Error enclave creation\nEnter a character before exit ..." << endl;
		cout << "Errocode: " << hex << ret << endl;
    getchar();
    return -1;
  }

  printf("[INFO] Start warmup!\n");


  int resp_enclave2;
	uint8_t* sealed_key_b_X = new uint8_t[SEALED_KEY_LENGTH];

  // WARMUP
  for (int i = 0; i < MAX_WARM_UP; i++)
  {
    generateKeyEnclave(global_eid, &resp_enclave2, sealed_key_b_X, SEALED_KEY_LENGTH);
    loadKeyEnclave(global_eid, &resp_enclave2, sealed_key_b_X, SEALED_KEY_LENGTH);
  }

  for (int i = 0; i < MAX_TEST; i++) {
    RUN_AND_DUMP(MODE, "generateKeyEnclave", generateKeyEnclave(global_eid, &resp_enclave2, sealed_key_b_X, SEALED_KEY_LENGTH))
    RUN_AND_DUMP(MODE, "loadKeyEnclave", loadKeyEnclave(global_eid, &resp_enclave2, sealed_key_b_X, SEALED_KEY_LENGTH))
  }

  printf("[INFO] StealthDB successfully returned.\n");

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