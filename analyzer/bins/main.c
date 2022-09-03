#include <stdio.h>
#include <stdlib.h>

int b(int a) {
  if (a == 0)
    return 10;

  return a * a;
}

int a(int c) {
  int y = 0;
  if (c > 10) {
    y += c + 10;
  }

  if (c < 30) {
    y += c * 3;
  }

  if (y % 2 == 0) {
    y -= b(y);
  }

  return y;
}

int main(int argc, char** argv) {

  if (argc != 2) {
    printf("two fucking args\n");
    return -1;
  }

  printf("wow: %d\n", a(atoi(argv[1])));

  return 0;
}
