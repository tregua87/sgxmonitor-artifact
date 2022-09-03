#include "Enclave_t.h"
#include "sgx_trts.h"
#include <cstring>
#include <stdio.h>
#include <limits.h>

void testOcalls(size_t mod, size_t max)
{
  for(size_t i = 0; i < max; i++)
  {
    if((i % mod) == 0) 
    {
      testOcall(1);
    }
  }
}

void testEcalls(int i)
{
}

void testOcallsSingle(int i)
{
  testOcall(1);
}
