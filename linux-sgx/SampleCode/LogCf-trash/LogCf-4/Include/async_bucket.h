// THIS HEADER CONTAINS THE STRUCTURE USED TO EXCHANGE INFO BETWEEN TRUSTED
// AND UNTRUSTED LIBRARY

#ifndef __ASYNC_BUCKET_H_
#define __ASYNC_BUCKET_H_

#define USE_BUFFER false

#define BUCKET_SIZE 1024
#define ENTRY_SIZE 384

typedef enum _entry_status {WHITE, GRAY, BLACK, RED} entry_status;

typedef struct _bucket_entry {
  entry_status status;
  unsigned char buf[ENTRY_SIZE];
} bucket_entry;

typedef struct _bucket {
  unsigned long idx; // index of the current bucket entry
  size_t size; // bucket size
  bucket_entry entries[BUCKET_SIZE];
} bucket;


#endif
