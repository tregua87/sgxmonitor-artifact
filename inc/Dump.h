#include <sys/time.h>

void dump(const char* mode ,char* secretfunction, uint64_t time);
void dumpLen(const char* mode ,char* secretfunction, int *cnt);

#define RUN_AND_DUMP(m, f, t) do {struct timeval stop, start; uint64_t dt; \
                            gettimeofday(&start, NULL); \
                            t; \
                            gettimeofday(&stop, NULL); \
                            dt = (uint64_t)((stop.tv_sec - start.tv_sec) * 1000000 + stop.tv_usec - start.tv_usec); \
                            dump(m, f, dt); \
                            printf("[INFO] %s: %lu us\n", f, dt); \
                          } while(0);

#define RUN(f, t) do {t; \
                        printf("[INFO] %s\n", f); \
                      } while(0);

#define MAX_WARM_UP 1000
#define MAX_TEST    1000
