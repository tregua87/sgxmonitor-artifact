#include <cstdio>

#include "sgx_urts.h"
#include "Enclave_u.h"
#include <unistd.h>
#include <time.h>
#include <math.h>
//MAX is for the constant for mod operations and amount calculation
#define MAX 100000000UL
#define MAX_WARM_UP 10000
#define OCALLS_TESTS_PER_LOOP 16
#define ENCLAVE_FILE "enclave.signed.so"

#ifdef OCALL_COUNTER
extern "C" long sgx_read_ocall_counter();
#endif

typedef struct {
  size_t time;
  size_t amount;
} benchmark;

sgx_enclave_id_t eid;
int updated;

benchmark* benchmark_array;
size_t bench_size = 0;

sgx_status_t enclave_init()
{
  sgx_launch_token_t token = { 0 };
  return sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated , &eid, NULL);
}

size_t initBenchmarkStructure(size_t amount_of_entries, void* type)
{
  size_t amount_in_bytes;

  if(strcmp((const char*)type, "ECALLS") == 0 ||
     strcmp((const char*)type, "OCALLSSingle") == 0 ||
     strcmp((const char*)type, "OCALLSBaseline") == 0) {
    amount_in_bytes = sizeof(benchmark) * amount_of_entries;
  } else if(strcmp((const char*)type, "OCALLS") == 0) {
    amount_in_bytes = sizeof(benchmark) * OCALLS_TESTS_PER_LOOP * amount_of_entries;
  } else {
    return 0;
  }

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
  asm volatile("mfence");
  asm("rdtsc"
      :"=a"(lo),"=d"(hi)  // a -> eax d -> edx
      );
  size_t tmp = hi;
  size_t timestamp = (tmp << 32) | lo;
  asm volatile("mfence");
  return timestamp;
}

/* Baseline for benchmarkOcalls latency (ECALL + for-loop without any OCALL) */
void benchmarkOcallsBaseline(size_t amount_of_tests)
{
  // Warmup phase
  testOcalls(eid, 1000, 1000 * MAX_WARM_UP);

  size_t benchmark_index = 0;
  for(size_t i = 0; i < amount_of_tests; i++)
  {
    benchmark tmp = {0,0};
    size_t rdtsc_val = getRdtsc();
    testOcalls(eid, MAX+1, MAX); /* If the modulus is > MAX, no OCALL occurs */
    tmp.time = getRdtsc() - rdtsc_val;
    benchmark_array[benchmark_index++] = tmp;
  }

  printf("TIME,OCALLS,MAX\n");
  for(size_t i = 0; i < bench_size; i++)
    printf("%lu,%lu,%lu\n", benchmark_array[i].time, benchmark_array[i].amount, MAX);
}

/* Synthetic OCALL benchmark with a for-loop counting till MAX.
 * It issues a configurable number of OCALLs during this benchmark */
void benchmarkOcalls(size_t amount_of_tests)
{
  // Warmup phase
  testOcalls(eid, 1000, 1000 * MAX_WARM_UP);

  size_t benchmark_index = 0;
  for(size_t i = 0; i < amount_of_tests; i++)
  {
    size_t multiplikator[] = {1,2,5};
    size_t rdtsc_val = 0;
    size_t index_y = 1;
    size_t size = 10;
    benchmark tmp = {0,0};

    size_t index_x;
    for(size_t index = 0; index < OCALLS_TESTS_PER_LOOP; index++)
    {
      index_x = index % 3;
      size = 10 * (multiplikator[index_x] * index_y);

      if(index_x == 2)
        index_y *= 10;

      rdtsc_val = getRdtsc();
      testOcalls(eid, (MAX/size), MAX);

      tmp.time = getRdtsc() - rdtsc_val;

      tmp.amount = MAX/(MAX/size);

      benchmark_array[benchmark_index++] = tmp;
    }
  }

  printf("TIME,OCALLS,MAX\n");
  for(size_t i = 0; i < bench_size; i++)
    printf("%lu,%lu,%lu\n", benchmark_array[i].time, benchmark_array[i].amount, MAX);
}

void benchmarkEcalls(size_t amount_of_ecalls)
{
  benchmark tmp = {0, amount_of_ecalls};
  size_t rdtsc_val = 0;

  // Warmup phase
  for(int i = 0; i < MAX_WARM_UP; i++)
    testEcalls(eid, 0);

  for(size_t index = 0; index < amount_of_ecalls; index++)
  {
    rdtsc_val = getRdtsc();
    testEcalls(eid, 0);
    tmp.time = getRdtsc() - rdtsc_val;
    benchmark_array[index] = tmp;
  }

  printf("TIME,ECALLS\n");
  for(size_t i = 0; i < bench_size; i++)
    printf("%lu,%lu\n", benchmark_array[i].time, benchmark_array[i].amount);
}

void benchmarkOcallsSingle(size_t amount_of_ocalls)
{
  benchmark tmp = {0, amount_of_ocalls};
  size_t rdtsc_val = 0;

  // Warmup phase
  for(int i = 0; i < MAX_WARM_UP; i++)
    testOcallsSingle(eid, 0);
#ifdef OCALL_COUNTER
  long ocall_counter = sgx_read_ocall_counter();
#endif
  for(size_t index = 0; index < amount_of_ocalls; index++)
  {
    rdtsc_val = getRdtsc();
    testOcallsSingle(eid, 0);
    tmp.time = getRdtsc() - rdtsc_val;
    benchmark_array[index] = tmp;
  }
#ifdef OCALL_COUNTER
  fprintf(stderr, "ocall_counter: %d\n", sgx_read_ocall_counter() - ocall_counter);
#endif
  printf("TIME,OCALLS\n");
  for(size_t i = 0; i < bench_size; i++)
    printf("%lu,%lu\n", benchmark_array[i].time, benchmark_array[i].amount);
}

void testOcall(int dummy)
{
  (void)dummy;
}

void printHelp(const char* prog) {
  printf("Usage:\n%s ECALLS|OCALLS|OCALLSSingle|OCALLSBaseline <no-calls>\n", prog);
}

int main(int argc, char** argv)
{
  int ret = 0;
  if (argc != 3) {
    printHelp(argv[0]);
    return -1;
  }

  size_t amount_of_calls = atol((const char*)argv[2]);

  if(!(amount_of_calls > 0))
  {
    printf("amount of calls have to be greater than 0\n");
    return -1;
  }

  if(!initBenchmarkStructure(amount_of_calls, argv[1]))
  {
    printf("initialization of Benchmark Structure was not possible\n");
    return -1;
  }

  if (SGX_SUCCESS != enclave_init()) {
    printf("Unable to initialize enclave\n");
    return -1;
  }

  if (strcmp((const char*)argv[1], "ECALLS") == 0) {
    benchmarkEcalls(amount_of_calls);
  } else if(strcmp((const char*)argv[1], "OCALLS") == 0) {
    benchmarkOcalls(amount_of_calls);
  } else if(strcmp((const char*)argv[1], "OCALLSSingle") == 0) {
    benchmarkOcallsSingle(amount_of_calls);
  } else if(strcmp((const char*)argv[1], "OCALLSBaseline") == 0) {
    benchmarkOcallsBaseline(amount_of_calls);
  } else {
    printHelp(argv[0]);
    ret = -1;
    goto cleanup;
  }

cleanup:
  free(benchmark_array);
  sgx_destroy_enclave(eid);
  return ret;
}
