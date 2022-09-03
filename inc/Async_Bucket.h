// THIS HEADER CONTAINS THE STRUCTURE USED TO EXCHANGE INFO BETWEEN TRUSTED
// AND UNTRUSTED LIBRARY

#ifndef __ASYNC_BUCKET_H_
#define __ASYNC_BUCKET_H_

#include <stddef.h>

// #define BUCKET_SIZE 1024
#define BUCKET_SIZE 4096
// #define BUCKET_SIZE 40960
#define ENTRY_SIZE 30 // each entry is exactly long as the opt key
// #define ENTRY_SIZE 384

#define BUFFER_SIZE 50
// #define BUFFER_SIZE (1)

typedef enum _entry_status {WHITE, GRAY, BLACK, RED} entry_status_t;

typedef struct _bucket_entry {
  entry_status_t status;
  unsigned char buf[ENTRY_SIZE];
} bucket_entry_t;

typedef struct _bucket {
  unsigned long idx; // index of the current bucket entry
  size_t size; // bucket size
  bucket_entry_t entries[BUCKET_SIZE];
} bucket_t;

typedef struct _buffer {
  bucket_entry_t entries[BUFFER_SIZE];
} buffer_t;


#define INIT_BUCKET(b)  {b.idx = 0; \
                        b.size = BUCKET_SIZE; \
                        for (unsigned int i = 0; i < b.size; i++) \
                          b.entries[i].status = WHITE;}

#endif
