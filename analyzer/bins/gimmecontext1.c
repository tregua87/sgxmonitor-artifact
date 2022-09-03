#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

struct thread_data_
{
   int32_t base_addr;
   int32_t size;
   int32_t active;
} thread_data;


int a(void) {

  if (thread_data.base_addr < 0)
    return -1;

  if (thread_data.base_addr + thread_data.size >= 100)
    return -2;

  if (thread_data.active != 1)
    return -3;

  return 0;
}

int main(int argc, char** argv) {

  if (argc != 4) {
    printf("usage: %s <base_addr> <size> <active>\n", argv[0]);
    return 0;
  }

  thread_data.base_addr = atoi(argv[1]);
  thread_data.size = atoi(argv[2]);
  thread_data.active = atoi(argv[3]);

  int x = a();

  printf("x = %d\n", x);

  return 0;
}
