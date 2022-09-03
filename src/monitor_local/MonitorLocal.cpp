#include "MonitorLocal.h"

#include "EnclaveM_u.h"

bucket_t bucket;
pthread_t sender;
sgx_enclave_id_t global_eid_monitor = 0;
short exit_loop = false;
int rret;

int initialize_monitorlocal(void) {

  sgx_status_t ret = sgx_create_enclave(ENCLAVE_MONITOR_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid_monitor, NULL);
  if (ret != SGX_SUCCESS) {
      print_error_message2(ret);
      return -1;
  }

  INIT_BUCKET(bucket);
  rret = pthread_create(&sender, NULL, send_client, (void *)global_eid_monitor);
  if (ret) {
     printf("Error:unable to create thread\n");
     exit(-1);
  }

  setBucketM(global_eid_monitor, &bucket, &exit_loop);

  return 0;
}

void ocall_monitorgatewayu(const char *strI, size_t lenI,
                           char *strO, size_t lenO)
{
  // cout << "[INFO] sync" << endl;
  /* Write some stuff and read the echoes. */
  char buffer[BuffSize + 1] = { 0 };
  unsigned char k[OPT_KEY_SIZE_BYTE];
  unsigned char nonce[REF_NONCE_SIZE];
  if (SGX_SUCCESS != generateSecrets(global_eid_monitor, k, nonce)) {
    printf("Error secret generation...\n");
    getchar();
    return;
  }

  // makeInitMessage(char* buffer, size_t buffer_len, unsigned char* k, size_t k_len, unsigned char* nonce, size_t nonce_len)

  memset(buffer, 0, sizeof(buffer));

  memcpy(buffer, k, OPT_KEY_SIZE_BYTE);
  memcpy(buffer + OPT_KEY_SIZE_BYTE, nonce, REF_NONCE_SIZE);

  if (strO && lenO) {
    memcpy(strO, buffer, lenO);
  }
}

void *send_client(void *arg) {
  // I know this sucks..

  printf("Receiver client\n");

  sgx_enclave_id_t eid = (sgx_enclave_id_t)arg;

  // the thread is handled inside the enclae
  sgx_status_t r = startConsumer(eid);


  // sgx_destroy_enclave(global_eid_monitor);
  if (r != SGX_SUCCESS)
    print_error_message2(r);
  pthread_exit(&rret);
}

void closeMonitorAndPrintModel(void) {

  printModel(global_eid_monitor);

  // clean up all the threads
  pthread_exit(NULL);
  void *rett;
  pthread_join(sender, &rett);

  sgx_destroy_enclave(global_eid_monitor);

}
