#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#define BENCHMARK_FILE "../../benchmark.txt"
#define LENFUNCTION_FILE "../../len_function.txt"

extern void dump(const char* mode ,char* secretfunction, uint64_t t) {
    FILE *pFile = fopen(BENCHMARK_FILE, "a");
    fprintf(pFile, "%s|%s|%lu\n",mode,secretfunction,t);
    fclose(pFile);
}

extern void dumpLen(const char* mode ,char* secretfunction, int *cnt) {
    FILE *pFile = fopen(LENFUNCTION_FILE, "a");
    fprintf(pFile, "%s|%s|%d\n",mode,secretfunction,*cnt);
    fclose(pFile);
    (*cnt) = 0;
}
