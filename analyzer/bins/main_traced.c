#include <stdio.h>
#include <stdlib.h>

void traceedgec(void *ptr) {
  void *bb = __builtin_return_address(0);
  printf("edg: (%p,%p)\n", bb, ptr);
}

void traceassigmentf(void* addr, void* val) {
  printf("fun: (%p,%p)\n", addr, val);
}

void traceframe(void* addr) {
  printf("frame: (%p)\n", addr);
}

void traceptr(void* obj, void* vtbl) {
  printf("vtbl: (%p,%p)\n", obj, vtbl);
}

int c(int a) {
  traceframe(__builtin_frame_address(0));

  for (int i = 0; i < 10; i++)
    a += a;

  traceedgec(__builtin_return_address(0));
  return a+1;
}


int b(int a) {
  traceframe(__builtin_frame_address(0));

  int x = 0;
  if (a == 0)
    x = 10;
  else
    x = a * a;

  traceedgec(__builtin_return_address(0));
  return x;
}

int a(int arg) {
  traceframe(__builtin_frame_address(0));

  int (*fun_ptr)(int) = NULL;

  if (arg % 2 == 0) {
    traceassigmentf(&fun_ptr, &b);
    fun_ptr = &b;
  }
  else{
    traceassigmentf(&fun_ptr, &b);
    fun_ptr = &c;
  }

  int (*fun_ptr2)(int) = NULL;

  if (arg % 3 == 0) {
    traceptr(&fun_ptr2, (void*)0x5);
    fun_ptr2 = (void*)0x5;
  }
  else {
    traceptr(&fun_ptr2, (void*)0xb);
    fun_ptr2 = (void*)0xb;
  }

  traceedgec(fun_ptr);
  int x = fun_ptr(arg);

  traceedgec(__builtin_return_address(0));
  return x;
}

int main(int argc, char** argv) {

  if (argc != 2) {
    printf("two fucking args\n");
    return -1;
  }

  printf("wow: %d\n", a(atoi(argv[1])));

  return 0;
}
