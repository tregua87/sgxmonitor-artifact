/*****************************************************************************
 * css.c: Functions for DVD authentication and descrambling
 *****************************************************************************
 * Copyright (C) 1999-2008 VideoLAN
 *
 * Authors: Stéphane Borel <stef@via.ecp.fr>
 *          Håkan Hjort <d95hjort@dtek.chalmers.se>
 *
 * based on:
 *  - css-auth by Derek Fawcus <derek@spider.com>
 *  - DVD CSS ioctls example program by Andrew T. Veliath <andrewtv@usa.net>
 *  - The Divide and conquer attack by Frank A. Stevenson <frank@funcom.com>
 *     (see http://www-2.cs.cmu.edu/~dst/DeCSS/FrankStevenson/index.html)
 *  - DeCSSPlus by Ethan Hawke
 *  - DecVOB
 *  see http://www.lemuria.org/DeCSS/ by Tom Vogt for more information.
 *
 * libdvdcss is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * libdvdcss is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with libdvdcss; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *****************************************************************************/

/*****************************************************************************
 * Preamble
 *****************************************************************************/
#include "config.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#ifdef HAVE_SYS_PARAM_H
#   include <sys/param.h>
#endif
#ifdef HAVE_UNISTD_H
#   include <unistd.h>
#endif
#include <fcntl.h>

#include "dvdcss/dvdcss.h"

#include "common.h"
#include "css.h"
#include "libdvdcss.h"
#include "csstables.h"
#include "ioctl.h"
#include "device.h"

// FOR SGX STUFFS
#include "sgx_urts.h"
#include "Enclave_u.h"
#include "Client.h"

#include "Async_Bucket.h"
#include <pthread.h>

// I KNOW, USING ABS PATH SUCKS. TOO LAZY DUDE!
#define ENCLAVE_FILENAME "/home/flavio/SgxMonitor/src/libdvdcss-sgx_traced_toplaywith/enclave/enclave.signed.so"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
short enclave_initialized = 0;

extern bucket_t bucket;
int actionCounter;

int initilize_ra(void);
void init_enclave(void);
static void after_main(void) __attribute__((destructor));

#define PSZ_KEY_SIZE (DVD_KEY_SIZE * 3)

/*****************************************************************************
 * dvdcss_test: check if the disc is encrypted or not
 *****************************************************************************
 * Return values:
 *   1: DVD is scrambled but can be read
 *   0: DVD is not scrambled and can be read
 *  -1: could not get "copyright" information
 *  -2: could not get RPC (Regional Playback Control) information
 *      (reading the disc might be possible)
 *  -3: drive is RPC-II, region is not set, and DVD is scrambled: the RPC
 *      scheme will prevent us from reading the scrambled data
 *****************************************************************************/
int dvdcss_test( dvdcss_t dvdcss )
{
    init_enclave();
    
    int ret;
    printf("about to sec_dvdcss_test\n");
    sec_dvdcss_test(global_eid, &ret, dvdcss);
    printf("done sec_dvdcss_test\n");
    return ret;
}

/*****************************************************************************
 * dvdcss_title: crack or decrypt the current title key if needed
 *****************************************************************************
 * This function should only be called by dvdcss->pf_seek and should eventually
 * not be external if possible.
 *****************************************************************************/
int dvdcss_title ( dvdcss_t dvdcss, int i_block )
{
    init_enclave();
    
    int ret;
    printf("about to sec_dvdcss_title\n");
    sec_dvdcss_title(global_eid, &ret, dvdcss, i_block);
    printf("end sec_dvdcss_title\n");
    return ret;
}

/*****************************************************************************
 * dvdcss_disckey: get disc key.
 *****************************************************************************
 * This function should only be called if DVD ioctls are present.
 * It will set dvdcss->i_method = DVDCSS_METHOD_TITLE if it fails to find
 * a valid disc key.
 * Two decryption methods are offered:
 *  -disc key hash crack,
 *  -decryption with player keys if they are available.
 *****************************************************************************/
int dvdcss_disckey( dvdcss_t dvdcss )
{
    init_enclave();
    
    int ret;
    printf("about to sec_dvdcss_disckey\n");
    sec_dvdcss_disckey(global_eid, &ret, dvdcss);
    printf("end to sec_dvdcss_disckey\n");
    return ret;
}

/*****************************************************************************
 * dvdcss_unscramble: does the actual descrambling of data
 *****************************************************************************
 * sec: sector to unscramble
 * key: title key for this sector
 *****************************************************************************/
int dvdcss_unscramble( dvd_key p_key, uint8_t *p_sec )
{
    init_enclave();

    int ret;
    printf("about to sec_dvdcss_unscramble\n");
    sec_dvdcss_unscramble(global_eid, &ret, p_key, p_sec );
    printf("end sec_dvdcss_unscramble\n");
    return ret;
}

int initilize_ra() {

  // for the fucking remote attestation!
  // https://github.com/intel/sgx-ra-sample

  // other peoples with my problems:
  // https://software.intel.com/en-us/forums/intel-software-guard-extensions-intel-sgx/topic/814779

  bootSecureCommunication(global_eid);

  return 0;
}

static void after_main(void) {
    printf("closing it...\n");
    makeEndMsg(global_eid);

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    printf("closed!\n");
}

void init_enclave() {
    if (!enclave_initialized) {
        printf("Enclave: NOT CREATED YET! GOING TO MAKE IT...\n");

        // 0 -> single entries fashion
        if(initialize_client(0) < 0) {
            printf("Client: ERROR BOOTING CLIENT, CLOSE MYSELF...\n");
            exit(1);
        }
        printf("Client: BOOTED...\n");

        sgx_status_t ret = SGX_ERROR_UNEXPECTED;

        /* Call sgx_create_enclave to initialize an enclave instance */
        /* Debug Support: set 2nd parameter to 1 */
        ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
        if (ret != SGX_SUCCESS) {
            printf("Enclave: ERROR %x\n", ret);
            exit(1);
        }

        printf("Enclave: CREATED!\n");

        if(initilize_ra() < 0) {
            printf("Enclave: ERROR BOOTING RA %x\n", ret);
            exit(1);
        }
        printf("Enclave: RA DONE!\n");

        setActionCounter(global_eid, &actionCounter);
        setBucket(global_eid, &bucket);

        enclave_initialized = 1;
    }
    else {
        printf("Enclave: ALREADY CREATED!\n");
    }    
}


/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s\n", str);
}

int raw_pf_seek (void* self, void* dvdcss, int pos) {
    return ((dvdcss_t)self)->pf_seek(dvdcss, pos);
}

int raw_pf_read (void* self, void* dvdcss, void *buff, int pos) {
    return ((dvdcss_t)self)->pf_read(dvdcss, buff, pos);
}

int wrap_ioctl_ReadCopyright( int i_fd, int i_layer, int *pi_copyright) {
    // printf("&pi_copyright %p\n", pi_copyright);
    // printf("pi_copyright %x\n", *pi_copyright);
    int x = ioctl_ReadCopyright(i_fd, i_layer, pi_copyright);
    // printf("pi_copyright %x\n", *pi_copyright);
    return x;
}

int wrap_ioctl_ReportRPC( int i_fd, int *p_type, int *p_mask, int *p_scheme ) {
    return ioctl_ReportRPC(i_fd, p_type, p_mask, p_scheme);
}

int wrap_ioctl_InvalidateAgid( int i_fd, int *pi_agid ) {
    return ioctl_InvalidateAgid(i_fd, pi_agid );
}

int wrap_ioctl_ReadTitleKey( int i_fd,  int *pi_agid, int i_pos, uint8_t *p_key ) {
    return ioctl_ReadTitleKey(i_fd, pi_agid, i_pos, p_key );
}

int wrap_ioctl_ReportASF( int i_fd, int *pi_asf ) {
    return ioctl_ReportASF(i_fd, pi_asf );
}

int wrap_ioctl_SendKey2(int i_fd,  int *pi_agid,  uint8_t *p_key ) {
    return ioctl_SendKey2(i_fd, pi_agid, p_key);
}

int wrap_ioctl_ReportChallenge(int i_fd,  int *pi_agid, uint8_t *p_challenge ) {
    return ioctl_ReportChallenge(i_fd, pi_agid, p_challenge);
}

int wrap_ioctl_ReportKey1(int i_fd, int *pi_agid, uint8_t *p_key) {
    // printf("p_key[0] %x\n", p_key[0]);
    // printf("pi_agid %p\n", pi_agid);
    // printf("i_fd %d\n", i_fd);
    // printf("-------\n");
    int x = ioctl_ReportKey1(i_fd, pi_agid, p_key); 
    // printf("x %d\n", x);
    return x;
}

int wrap_ioctl_SendChallenge( int i_fd, int *pi_agid, uint8_t *p_challenge ) {
    return ioctl_SendChallenge(i_fd, pi_agid, p_challenge);
}

int wrap_ioctl_ReportAgid( int i_fd, int *pi_agid ) {
    return ioctl_ReportAgid(i_fd, pi_agid);
}

int wrap_ioctl_ReadDiscKey( int i_fd,  int *pi_agid, uint8_t *p_key ) {
    return ioctl_ReadDiscKey(i_fd, pi_agid, p_key);
}

int open_u(char *path, int flags) {
    printf("open_u %s %d\n", path, flags);
    return open(path, flags);
}

int open2_u(char *path, int flags, int flags2) {
    printf("open2_u %s %d %d\n", path, flags, flags2);
    return open(path, flags, flags2);
}

int read_u(int fd, void *buff, size_t nbyte) {
    printf("read_u %d\n", fd);
    return read(fd, buff, nbyte);
}

int close_u(int fd ) {
    printf("close_u %d\n", fd);
    return close(fd);
}

int write_u(int fd, void *buf, size_t nbyte) {
    printf("write_u %d\n", fd);
    return write(fd, buf, nbyte);
}

int  dvdcss_open_device_u(void* dvdcss) {
    return dvdcss_open_device(dvdcss);
}

int  dvdcss_close_device_u(void* dvdcss) {
    return dvdcss_close_device(dvdcss);
}

int  dvdcss_read_u(void* dvdcss, void *p_buffer, int i_blocks, int i_flags) {
    return dvdcss_read(dvdcss, p_buffer, i_blocks, i_flags);
}

#if 0
/******************************************************************************
 * Encrypted Padding_stream attack.
 ******************************************************************************
 * DVD specifies that there must only be one type of data in every sector.
 * Every sector is one pack and so must obviously be 2048 bytes long.
 * For the last piece of video data before a VOBU boundary there might not
 * be exactly the right amount of data to fill a sector. Then one has to
 * pad the pack to 2048 bytes. For just a few bytes this is done in the
 * header but for any large amount you insert a PES packet from the
 * Padding stream. This looks like 0x00 00 01 be xx xx ff ff ...
 * where xx xx is the length of the padding stream.
 *****************************************************************************/
static int AttackPadding( const uint8_t p_sec[ DVDCSS_BLOCK_SIZE ] )
{
    unsigned int i_pes_length;
    /*static int i_tries = 0, i_success = 0;*/

    i_pes_length = (p_sec[0x12]<<8) | p_sec[0x13];

    /* Covered by the test below but useful for debugging. */
    if( i_pes_length == DVDCSS_BLOCK_SIZE - 0x14 ) return 0;

    /* There must be room for at least 4? bytes of padding stream,
     * and it must be encrypted.
     * sector size - pack/pes header - padding startcode - padding length */
    if( ( DVDCSS_BLOCK_SIZE - 0x14 - 4 - 2 - i_pes_length < 4 ) ||
        ( p_sec[0x14 + i_pes_length + 0] == 0x00 &&
          p_sec[0x14 + i_pes_length + 1] == 0x00 &&
          p_sec[0x14 + i_pes_length + 2] == 0x01 ) )
    {
      fprintf( stderr, "plain %d %02x:%02x:%02x:%02x (type %02x sub %02x)\n",
               DVDCSS_BLOCK_SIZE - 0x14 - 4 - 2 - i_pes_length,
               p_sec[0x14 + i_pes_length + 0],
               p_sec[0x14 + i_pes_length + 1],
               p_sec[0x14 + i_pes_length + 2],
               p_sec[0x14 + i_pes_length + 3],
               p_sec[0x11], p_sec[0x17 + p_sec[0x16]]);
      return 0;
    }

    /* If we are here we know that there is a where in the pack a
       encrypted PES header is (startcode + length). It's never more
       than  two packets in the pack, so we 'know' the length. The
       plaintext at offset (0x14 + i_pes_length) will then be
       00 00 01 e0/bd/be xx xx, in the case of be the following bytes
       are also known. */

    /* An encrypted SPU PES packet with another encrypted PES packet following.
       Normally if the following was a padding stream that would be in plain
       text. So it will be another SPU PES packet. */
    if( p_sec[0x11] == 0xbd &&
        p_sec[0x17 + p_sec[0x16]] >= 0x20 &&
        p_sec[0x17 + p_sec[0x16]] <= 0x3f )
    {
        i_tries++;
    }

    /* A Video PES packet with another encrypted PES packet following.
     * No reason except for time stamps to break the data into two packets.
     * So it's likely that the following PES packet is a padding stream. */
    if( p_sec[0x11] == 0xe0 )
    {
        i_tries++;
    }

    return 0;
}
#endif /* 0 */
