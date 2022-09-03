// THIS HEADER CONTAINS THE STRUCTURE USED TO EXCHANGE INFO BETWEEN TRUSTED
// AND UNTRUSTED LIBRARY

#ifndef __ASYNC_BUCKET_H_
#define __ASYNC_BUCKET_H_

#define SENDER_USE_BUFFER (1)
#define RECEIVER_USE_BUFFER (1)

#define BUCKET_SIZE 1024
#define ENTRY_SIZE 30 // each entry is exactly long as the opt key
// #define ENTRY_SIZE 384

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


#define INIT_BUCKET(b)  {b.idx = 0; \
                        b.size = BUCKET_SIZE; \
                        for (int i = 0; i < b.size; i++) \
                          b.entries[i].status = WHITE;}

#endif
