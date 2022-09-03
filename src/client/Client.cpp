#include "Client.h"

#include <assert.h>


#include <unistd.h>
#include <time.h>

// PUBLIC bucket for asnyc communication
bucket_t bucket;
pthread_t sender;
int sockfd;
int ret;
short isBatch = 0;

// initilize the client socketisBatch
int initialize_client(short pIsBatch)
{
    isBatch = pIsBatch;

    /* fd for the socket */
    sockfd = socket(AF_INET,      /* versus AF_LOCAL */
                      SOCK_STREAM,  /* reliable, bidirectional */
                      0);           /* system picks protocol (TCP) */
    if (sockfd < 0) {
      printf("Error Socket\n");
      return -1;
    }

    /* get the address of the host */
    struct hostent* hptr = gethostbyname(Host); /* localhost: 127.0.0.1 */
    if (!hptr) {
      printf("Error Hostname\n");
      return -1;
    }
    if (hptr->h_addrtype != AF_INET) {       /* versus AF_LOCAL */
      printf("bad address family\n");
      return -1;
    }

    /* connect to the server: configure server's address 1st */
    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = ((struct in_addr*) hptr->h_addr_list[0])->s_addr;
    saddr.sin_port = htons(PortNumber); /* port number in big-endian */

    if (connect(sockfd, (struct sockaddr*) &saddr, sizeof(saddr)) < 0) {
      printf("connect\n");
      return -1;
    }

    // int val = 1;
    // if (setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val)) < 0)
    //   perror("setsockopt(2) error");

    ret = pthread_create(&sender, NULL, send_client, NULL);
    if (ret)
    {
      printf("Error:unable to create thread %d\n", ret);
      return -1;
    }

    INIT_BUCKET(bucket);

    return 0;
}

int empy_loops = 0;
#define MAX_EMPTY_LOOPS 400

void *send_client(void *arg) {
  // I know this sucks..

  struct timespec req;
  struct timespec rem;

  req.tv_sec = 0;
  req.tv_nsec = 1;

  unsigned long i = 0;
  while(1) {
    // printf("[INFO] is batch %d\n", isBatch);
    // sleep(nap_time);
    if (bucket.entries[i].status == RED) {
      if (isBatch)
        send_entry(bucket.entries[i].buf, 1);
      else
        ocall_monitorgatewayu((const char*)(bucket.entries[i].buf), ENTRY_SIZE, NULL, NULL);
      printf("[INFO] close the socket\n");
      close(sockfd);
      pthread_exit(&ret);
    }
    if (bucket.entries[i].status == BLACK) {
      if (isBatch)
        send_entry(bucket.entries[i].buf, 0);
      else
        ocall_monitorgatewayu((const char*)(bucket.entries[i].buf), ENTRY_SIZE, NULL, NULL);

      bucket.entries[i].status = WHITE;

      // increase read counter
      i = (i + 1) % BUCKET_SIZE;
    }
    // if (empy_loops >= MAX_EMPTY_LOOPS) {
    //   nanosleep(&req, &rem);
    //   empy_loops = 0;
    // }
    // empy_loops++;
    if (bucket.entries[i].status == WHITE || bucket.entries[i].status == GRAY)
      continue;
  }
}

buffer_t buff_client;
int el_buff = 0;

void send_entry(const unsigned char *strI, short flush) {

  // printf("[INFO] crypted buff_client sent:\n");
  // for (int i = 0; i < ENTRY_SIZE; i++)
  //   printf("%02X ", strI[i]);
  // printf("\n");

  memcpy(&buff_client.entries[el_buff].buf, strI, ENTRY_SIZE);
  if (flush) {
    buff_client.entries[el_buff].status = RED;
  }
  else {
    // cout << "Sending normal msgs" << endl;
    buff_client.entries[el_buff].status = BLACK;
  }

  el_buff++;

  if (el_buff >= BUFFER_SIZE || flush) {
      ocall_monitorgatewayu((const char*)&buff_client, sizeof(buffer_t), NULL, 0);
      memset(&buff_client, '\0', sizeof(buff_client));
      el_buff = 0;
  }
}

void ocall_monitorgatewayu(const char *strI, size_t lenI,
                           char *strO, size_t lenO)
{
  /* Write some stuff and read the echoes. */
  ssize_t x = write(sockfd, strI, lenI);
  if (x > 0) {

    assert(x == lenI);

    char buffer[BuffSize + 1];
    memset(buffer, '\0', sizeof(buffer));


    if (strO && lenO) {
      if (read(sockfd, buffer, sizeof(buffer)) < 0) {
        // printf("Error echo");
        exit(-1);
      }
      memcpy(strO, buffer, lenO);
    }
  }
}

void close_client(void) {
  // clean up all the threads
  pthread_exit(NULL);
  void *rett;
  pthread_join(sender, &rett);
}
