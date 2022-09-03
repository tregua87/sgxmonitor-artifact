#include<stdio.h>


// the worst way to instrument a module ever! :) open to suggestion...
void* __NOT_INSTRUMENT_THIS = 0;

int main(int argc, char** argv) {
  printf("Hi!\n");
  return 0;
}
