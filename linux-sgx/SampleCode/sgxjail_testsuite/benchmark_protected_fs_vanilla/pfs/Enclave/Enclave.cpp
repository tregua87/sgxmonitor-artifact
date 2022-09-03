#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <sgx_tseal.h>
#include <sgx_utils.h>
#include <sgx_tcrypto.h>
#include <stdlib.h>
#include "sgx_trts.h"
#include "Enclave_t.h"

char payload[PAYLOAD_SIZE] = {0};
const char fn[] = "SGX_FILE.txt";
const char m[] = "w+";

void ecall_prepare_ocalls(size_t amount_of_bytes)
{
  (void)amount_of_bytes;
  memset(payload, 0xA5, sizeof(payload));
}

void ecall_write_ocalls(size_t number_of_chunks, size_t amount_of_bytes)
{
  (void)amount_of_bytes;
  size_t chunk_size = PAYLOAD_SIZE / number_of_chunks;

  SGX_FILE* file;
  file = sgx_fopen_auto_key(fn, m);
  payload[PAYLOAD_SIZE - 1] = '\0';
  for(size_t chunk = 0; chunk < PAYLOAD_SIZE; chunk += chunk_size)
  {
    sgx_fwrite((const char*)&(payload[chunk]), sizeof(char), chunk_size, file);
  }
  sgx_fclose(file);
}

SGX_FILE* ecall_file_open(const char* filename, const char* mode)
{
  return sgx_fopen_auto_key(filename, mode);
}

uint64_t ecall_file_get_file_size(SGX_FILE * fp)
{
  uint64_t file_size = 0;
  sgx_fseek(fp, 0, SEEK_END);
  file_size = sgx_ftell(fp);
  return file_size;
}

size_t ecall_file_write(SGX_FILE* fp, char* data, size_t len)
{
  return sgx_fwrite(data, sizeof(char), len, fp);
}

size_t ecall_file_read(SGX_FILE* fp, char* readData, uint64_t size)
{
  (void)size;

  char *data;
  uint64_t startN = 1;
  sgx_fseek(fp, 0, SEEK_END);
  uint64_t finalN = sgx_ftell(fp);
  sgx_fseek(fp, 0, SEEK_SET);
  //printf("file size%d\n", finalN);
  data = (char*)malloc(sizeof(char)*finalN);
  memset(data, 0, sizeof(char)*finalN);

  size_t sizeofRead = sgx_fread(data, startN, finalN, fp);

  //size_t len = (size_t)strlen(data);
  memcpy(readData, data, sizeofRead);
  memset(readData+sizeofRead, '\0', 1);
  //printf("%s\n", readData);
  return sizeofRead;
}

int32_t ecall_file_close(SGX_FILE* fp)
{
  int32_t a;
  a = sgx_fclose(fp);
  return a;
}
