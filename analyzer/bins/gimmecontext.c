#include<stdio.h>
#include<stdlib.h>

int g;

int a(void) {

  int x = 0;
  if (g % 2 == 0)
    x = 1;
  else
    x = 2;

  return x;

}

int main(int argc, char** argv) {

  if (argc != 2) {
    printf("usage: %s <number>\n", argv[0]);
    return 0;
  }

  g = atoi(argv[1]);

  int x = a();

  printf("x = %d\n", x);

  return 0;
}
