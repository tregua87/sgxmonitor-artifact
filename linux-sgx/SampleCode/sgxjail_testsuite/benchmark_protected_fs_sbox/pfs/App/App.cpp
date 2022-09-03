#include "sgx_urts.h"
#include "sgx_uae_service.h"
#include "Enclave_u.h"
#include <cstdio>
#include <unistd.h>
#include <time.h>
#include <pwd.h>
#include <math.h>
//MAX is for the constant for mod operations and amount calculation
#define MAX 10000000
#define MAX_WARM_UP 10000
#define OCALLS_TESTS_PER_LOOP 16
#define ENCLAVE_FILE "enclave.signed.so"
#ifndef PAYLOAD_SIZE
# define PAYLOAD_SIZE 1024 * 1024
#endif
#define PLOAD_FILE_NAME "payload.txt"
#define PFS_FILE_NAME "SGX_File_Protection_System.txt"
#define MAX_PATH FILENAME_MAX

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h" /* sgx_enclave_id_t */

#ifdef OCALL_COUNTER
extern "C" long sgx_read_ocall_counter();
#endif

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

typedef struct{
size_t time;
size_t amount;
}benchmark;

sgx_enclave_id_t eid = 0;
int updated = 0;

benchmark* benchmark_array;
size_t bench_size = 0;

sgx_status_t enclave_init()
{
  sgx_launch_token_t token = { 0 };
  return sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated , &eid, NULL);
}

void printArrayToStdOut(void* type)
{
  printf("TIME,%s,PAYLOAD\n", ((char*)type));
  for(size_t i = 0; i < bench_size; i++)
    printf("%lu,%lu,%lu\n", benchmark_array[i].time, benchmark_array[i].amount, (long unsigned int)PAYLOAD_SIZE);

  free(benchmark_array);
}

size_t initBenchmarkStructure(size_t amount_of_entries, void* type)
{
  size_t amount_in_bytes = 0;

  if(strcmp((const char*)type, "WRITE") == 0)
    amount_in_bytes = sizeof(benchmark) * amount_of_entries;
  //for further adaptions a new statement
  else if(strcmp((const char*)type, "OWRITE") == 0)
    amount_in_bytes = sizeof(benchmark) * amount_of_entries;
  else
    return 0;

  if(amount_in_bytes == 0) return 0;

  bench_size = amount_in_bytes/sizeof(benchmark);

  benchmark_array = (benchmark*)malloc(amount_in_bytes);

  for(int i = 0; i < 10; i++)
    memset(benchmark_array, i, amount_in_bytes);

  return 1;
}

size_t getRdtsc()
{
  size_t hi;
  size_t lo;
  __asm__ volatile("mfence");
  __asm__("rdtsc"
      :"=a"(lo),"=d"(hi)  // a -> eax d -> edx
      );
  size_t tmp = hi;
  size_t timestamp = (tmp << 32) | lo;
  __asm__ volatile("mfence");
  return timestamp;
}

size_t benchmarkOcallWrite(size_t number_of_chunks, size_t amount_of_calls, size_t amount_of_bytes)
{
  size_t rdtsc_val = 0;
  benchmark tmp = {0, number_of_chunks};
  size_t benchmark_index = 0;
  ecall_prepare_ocalls(eid, amount_of_bytes);

  for(size_t i = 0; i < 100; i++)
  {
    unlink("SGX_FILE.txt");
    ecall_write_ocalls(eid, number_of_chunks, amount_of_bytes);
  }

  for(size_t i = 0; i < amount_of_calls; i++)
  {
    unlink("SGX_FILE.txt");
    sync();
#ifdef OCALL_COUNTER
    long ocalls_start = sgx_read_ocall_counter();
#endif
    rdtsc_val = getRdtsc();
    ecall_write_ocalls(eid, number_of_chunks, amount_of_bytes);
    tmp.time = getRdtsc() - rdtsc_val;
    benchmark_array[benchmark_index++] = tmp; 
#ifdef OCALL_COUNTER
    fprintf(stderr, "ecall_write_ocalls: %d\n", sgx_read_ocall_counter() - ocalls_start);
#endif
  }

  return 0;
}


size_t benchmarkWrite(size_t amount_of_chunks, size_t amount_of_tests, size_t payload_size)
{
  //Benchmark variables
  size_t rdtsc_val = 0;
  benchmark tmp = {0,0};
  size_t benchmark_index = 0;
  size_t steps = payload_size/amount_of_chunks;

  //PFS/FS variables
  FILE* payloadfp = fopen(PLOAD_FILE_NAME, "r");
  int payloadfd = fileno(payloadfp);
  char* payload = (char*)malloc(payload_size + 1);

  //Get Payload to write into SGX_FILE
  for(size_t chunk = 0; chunk < payload_size;)
  {
    size_t read = 0;
    lseek(payloadfd, 0, SEEK_SET);
    if((payload_size - chunk) < PAYLOAD_SIZE)
    {
      read = (payload_size - chunk);
    }
    else
    {
      read = PAYLOAD_SIZE;
    }

    if((fgets(&(payload[chunk]), (int)read, payloadfp) == NULL))
    {
      free(payload);
      return -1;
    }

    chunk += read;
  }

  payload[payload_size - 1] = '\0';

  tmp.amount = amount_of_chunks;

  for(size_t amount = 0; amount < amount_of_tests; amount++)
  {
    SGX_FILE* fp;
    uint64_t file_size = 0;
    const char* filename = PFS_FILE_NAME;
    const char* mode = "w+";
    size_t bytes_read_from_file = 0;
    int32_t fileHandle;

    //Open SGX-PFS FILE
    if(ecall_file_open(eid, &fp, filename, mode) != 0)
    {
      printf("Error opening file\n %lu %p %s %s\n", eid, fp, filename, mode);
    }
    rdtsc_val = getRdtsc();
    for(size_t chunk = 0; chunk < payload_size; chunk+=steps)
    {
      size_t bytes_written_to_file = 0;
      size_t ree = ecall_file_write(eid, &bytes_written_to_file, fp, &(payload[chunk]), steps);
      if(ree != 0)
      {
        printf("Error writing to SGX FILE %lu %lu %lu %lu %lu\n", chunk, steps, bytes_written_to_file, payload_size, ree);
        return -1;
      }
    }
    //saving benchmarks
    tmp.time = getRdtsc() - rdtsc_val;
    benchmark_array[benchmark_index++] = tmp;

    //resetting payload buffer
    memset(payload, 0, payload_size);

    if(ecall_file_get_file_size(eid, &file_size, fp) != 0)
    {
      printf("Error getting size of SGX FILE\n");
      return -1;
    }

    //keeeep this + 1 with size otherwise free generates Illegal Instruction.
    size_t reee = ecall_file_read(eid, &bytes_read_from_file, fp, payload, file_size + 1);

    if(reee != 0)
    {
      printf("Error reading from SGX FILE\n");
      return -1;
    }

    if(ecall_file_close(eid, &fileHandle, fp) != 0)
    {
      printf("Error closing SGX FILE\n");
      return -1;
    }
  }

  //Closing payload file
  free(payload);
  return close(payloadfd);
}

void printError()
{
  printf("Wrong amount parameters\n");
  printf("./app <type of test> <amount of calls> <number of chunks> <size of payload>\n");
  printf("<type of test> = WRITE or OWRITE\n");
  printf("<amount of calls> = greater than 0\n");
  printf("<number of chunks> has to be a number of power of two!\n");
  printf("<size of payload> between 1 and 512 only for WRITE relevant\n");
}

int main(int argc, char** argv)
{
  size_t write_cmp;
  size_t owrite_cmp;
  size_t payload_size = PAYLOAD_SIZE;
  if(argc >= 4)
  {
    write_cmp = strcmp((const char*)argv[1], "WRITE");
    owrite_cmp = strcmp((const char*)argv[1], "OWRITE");
  }
  else
  {
    printError();
    return -1;
  }

  if(((write_cmp == 0) && (argc != 5)) || ((owrite_cmp == 0)&& (argc != 4)))
  {
    printError();
    return -1;
  }
  else if(write_cmp != 0 && owrite_cmp != 0)
  {
    printError();
    return -1;
  }

  size_t amount_of_calls = atol((const char*)argv[2]);
  size_t number_of_chunks = atol((const char*)argv[3]);

  if(!write_cmp)
    payload_size = atol((const char*)argv[4]) * 1024UL;

  if(!((number_of_chunks > 0) && ((number_of_chunks & (number_of_chunks -1)) == 0)))
  {
    printf("<number of chunks> not power of 2!\n");
    return -1;
  }
  if(!(amount_of_calls > 0))
  {
    printf("<amount of calls> has to be greater than 0!\n");
    return -1;
  }
  if((!(payload_size > 0) || payload_size > 1024 * 512) && (strcmp((const char*)argv[1], "WRITE") == 0))
  {
    printf("<size of payload in KB> has to be between 1 and 512KB ");
    printf("only relevant for <type of test> = WRITE\n");
    return -1;
  }

  if(!initBenchmarkStructure(amount_of_calls, argv[1]))
  {
    printf("Benchmark Structure could not have been initialized");
    return -1;
  }

  if (SGX_SUCCESS != enclave_init()) {
    printf("Unable to initialize enclave\n");
    return -1;
  }

  if(!write_cmp)
  {
    benchmarkWrite(number_of_chunks, amount_of_calls, payload_size);
  }
  else if(!owrite_cmp)
  {
    benchmarkOcallWrite(number_of_chunks, amount_of_calls, payload_size);
  }
  else
  {
    printf("<type of test> has to be WRITE or OWRITE\n");
    sgx_destroy_enclave(eid);
    return -1;
  }

  printArrayToStdOut(argv[1]);
  sgx_destroy_enclave(eid);

  return 0;
}

