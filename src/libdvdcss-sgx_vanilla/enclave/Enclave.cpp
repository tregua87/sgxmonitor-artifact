/*
 * Copyright (C) 2011-2019 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <stdlib.h>
#include <string.h>

#include <ctype.h>

#include "sgx_trts_exception.h"
#include "sgx_trts.h"

#include "libdvdcss.h"
#include "csstables.h"

/* USED TO HANDLE FILE OPERATIONS - START */
#define	O_RDONLY	0x0000		/* open for reading only */
#define	O_WRONLY	0x0001		/* open for writing only */
#define	O_RDWR		0x0002		/* open for reading and writing */
#define	O_ACCMODE	0x0003		/* mask for above modes */
/* USED TO HANDLE FILE OPERATIONS - END */
#define	O_CREAT		0x0200		/* create if nonexistant */
#define	O_TRUNC		0x0400		/* truncate to zero length */
#define	O_EXCL		0x0800		/* error if already exists */

// #include <cstdio.h>

// #define CHECK(ret_code, msg) {if (ret_code != SGX_SUCCESS) {\
//                                 printf("[Error] %s: %x\n", msg, ret_code);\
//                                 return;\
//                               }\
//                               else {\
//                                 printf("[OK!] %s: %x\n", msg, ret_code);\
//                               }}
//

/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
 
static void PrintKey        ( dvdcss_s*, const char *, const uint8_t * );

static int  GetBusKey       ( dvdcss_s* );
static int  GetASF          ( dvdcss_s* );

static void CryptKey        ( int, int, const uint8_t *, uint8_t * );
static void DecryptKey      ( uint8_t,
                              const uint8_t *, const uint8_t *, uint8_t * );

static int  DecryptDiscKey  ( dvdcss_s*, const uint8_t *, dvd_key );
static int  CrackDiscKey    ( uint8_t * );

static void DecryptTitleKey ( dvd_key, dvd_key );
static int  RecoverTitleKey ( int, const uint8_t *,
                              const uint8_t *, const uint8_t *, uint8_t * );
static int  CrackTitleKey   ( dvdcss_s*, int, int, dvd_key );

static int  AttackPattern   ( const uint8_t[], uint8_t * );

static int  dvdcss_titlekey ( dvdcss_s*, int, dvd_key );

static int dvdcss_disckey( dvdcss_s* dvdcss );

int sscanf(const char *str, const char *format, ...);

int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

void print_debug(dvdcss_s* dvdcss, const char* fmt, ...) {
    if( dvdcss->b_debug )
    {
      va_list args;
      va_start( args, fmt );
      printf(fmt, args);
      va_end( args );
    }
}

void print_error(dvdcss_s* dvdcss, const char* fmt, ...) {
    if( dvdcss->b_errors )
    {
      va_list args;
      va_start( args, fmt );
      printf(fmt, args);
      va_end( args );
    }
    dvdcss->psz_error = fmt;
}

void hello()
{
  printf("Hi!\n");
}

int sec_dvdcss_test(void* x ) {
    dvdcss_s* dvdcss = (dvdcss_s*)x;
    const char *psz_type, *psz_rpc;
    char psz_region[17];
    char *p_region = psz_region;
    int i_ret, i_copyright, i_type, i_mask, i_rpc, i_region;

    wrap_ioctl_ReadCopyright(&i_ret, dvdcss->i_fd, 0 /* i_layer */, &i_copyright );
    // printf("x i_ret %d\n", i_ret);
    if( i_ret < 0 )
    {
#ifdef _WIN32
        /* Maybe we didn't have enough privileges to read the copyright
         * (see ioctl_ReadCopyright comments).
         * Apparently, on unencrypted DVDs dvdcss_disckey() always fails, so
         * we can check this as a workaround. */
        if( dvdcss_disckey( dvdcss ) < 0 )
        {
            i_copyright = 0;
        }
        else
        {
            i_copyright = 1;
        }
#else
        /* Since it's the first ioctl we try to issue, we add a notice */
        print_error( dvdcss, "CSS error: could not get \"copyright\""
                     " information, make sure there is a DVD in the drive,"
                     " and that you have used the correct device node." );

        return -1;
#endif /* _WIN32 */
    }

    print_debug( dvdcss, "disc reports copyright information 0x%x",
                         i_copyright );

    wrap_ioctl_ReportRPC(&i_ret, dvdcss->i_fd, &i_type, &i_mask, &i_rpc);

    if( i_ret < 0 )
    {
        print_error( dvdcss, "CSS error: could not get RPC (Regional Playback "
                     "Control) status. Assuming RPC-I drive." );
        i_type = i_mask = i_rpc = 0;
    }

    switch( i_rpc )
    {
        case 0: psz_rpc = "RPC-I"; break;
        case 1: psz_rpc = "RPC-II"; break;
        default: psz_rpc = "unknown RPC (Regional Playback Control) scheme"; break;
    }

    switch( i_type )
    {
        case 0: psz_type = "no region code set"; break;
        case 1: psz_type = "region code set"; break;
        case 2: psz_type = "one region change remaining"; break;
        case 3: psz_type = "region code set permanently"; break;
        default: psz_type = "unknown status"; break;
    }

    *p_region = '\0';
    for( i_region = 0; i_region < 8; i_region++ )
    {
        if( !( i_mask & ( 1 << i_region ) ) )
        {
            snprintf(p_region, 17, " %d", i_region + 1);
            p_region += 2;
        }
    }

    print_debug( dvdcss, "drive region(s)%s, region mask 0x%x, %s, %s",
                 psz_region, i_mask, psz_rpc, psz_type );

    if( i_copyright && i_rpc == 1 && i_type == 0 )
    {
        print_error( dvdcss, "CSS error: drive will prevent access to "
                             "scrambled data" );
        return -3;
    }

    return i_copyright ? 1 : 0;
}

int sec_dvdcss_title ( void *x, int i_block ) {

    dvdcss_s* dvdcss = (dvdcss_s*)x;

    struct dvd_title *p_title;
    struct dvd_title *p_newtitle;
    dvd_key p_title_key;
    int fakeret;
    int i_fd, i_ret = -1, b_cache = 0;

    if( ! dvdcss->b_scrambled )
    {
        return 0;
    }

    /* Check if we've already cracked this key */
    p_title = dvdcss->p_titles;
    while( p_title != NULL
            && p_title->p_next != NULL
            && p_title->p_next->i_startlb <= i_block )
    {
        p_title = p_title->p_next;
    }

    if( p_title != NULL
         && p_title->i_startlb == i_block )
    {
        /* We've already cracked this key, nothing to do */
        memcpy( dvdcss->css.p_title_key, p_title->p_key, sizeof(p_title->p_key) );
        return 0;
    }

    /* Check whether the key is in our disk cache */
    if( dvdcss->psz_cachefile[0] )
    {
        /* XXX: be careful, we use sprintf and not snprintf */
        snprintf( dvdcss->psz_block, 1024, "%." CACHE_FILENAME_LENGTH_STRING "x",
                 i_block );
        open_u( &i_fd,dvdcss->psz_cachefile, O_RDONLY );
        b_cache = 1;

        if( i_fd >= 0 )
        {
            char psz_key[PSZ_KEY_SIZE];
            unsigned int k0, k1, k2, k3, k4;

            psz_key[PSZ_KEY_SIZE - 1] = '\0';

            int byte_read;
            read_u(&byte_read, i_fd, psz_key, PSZ_KEY_SIZE - 1 );
            if( byte_read == PSZ_KEY_SIZE - 1
                 && sscanf( psz_key, "%x:%x:%x:%x:%x",
                            &k0, &k1, &k2, &k3, &k4 ) == 5 )
            {
                p_title_key[0] = k0;
                p_title_key[1] = k1;
                p_title_key[2] = k2;
                p_title_key[3] = k3;
                p_title_key[4] = k4;
                PrintKey( dvdcss, "title key found in cache ", p_title_key );

                /* Don't try to save it again */
                b_cache = 0;
                i_ret = 1;
            }

            close_u(&fakeret, i_fd );
        }
    }

    /* Crack or decrypt Content Scrambling System (CSS) title key
     * for current Video Title Set (VTS). */
    if( i_ret < 0 )
    {
        i_ret = dvdcss_titlekey( dvdcss, i_block, p_title_key );

        if( i_ret < 0 )
        {
            print_error( dvdcss, "fatal error in Video Title Set (VTS) "
                                 "Content Scrambling System (CSS) key" );
            return i_ret;
        }

        if( i_ret == 0 )
        {
            print_debug( dvdcss, "unencrypted title" );
            /* We cache this anyway, so we don't need to check again. */
        }
    }

    /* Key is valid, we store it on disk. */
    if( dvdcss->psz_cachefile[0] && b_cache )
    {
        open2_u(&i_fd, dvdcss->psz_cachefile, O_RDWR|O_CREAT, 0644 );
        if( i_fd >= 0 )
        {
            char psz_key[PSZ_KEY_SIZE + 2];

            snprintf( psz_key, PSZ_KEY_SIZE,"%02x:%02x:%02x:%02x:%02x\r\n",
                              p_title_key[0], p_title_key[1], p_title_key[2],
                              p_title_key[3], p_title_key[4] );

            write_u( &fakeret, i_fd, psz_key, PSZ_KEY_SIZE + 1 );
            if( fakeret < PSZ_KEY_SIZE + 1 )
            {
                print_error( dvdcss,
                             "Error caching key on disk, continuing..\n" );
            }
            close_u( &fakeret, i_fd );
        }
    }

    /* Find our spot in the list */
    p_newtitle = NULL;
    p_title = dvdcss->p_titles;
    while( ( p_title != NULL ) && ( p_title->i_startlb < i_block ) )
    {
        p_newtitle = p_title;
        p_title = p_title->p_next;
    }

    /* Save the found title */
    p_title = p_newtitle;

    /* Write in the new title and its key */
    p_newtitle = (struct dvd_title *)malloc( sizeof( *p_newtitle ) );
    if( p_newtitle == NULL )
    {
        return -1;
    }
    p_newtitle->i_startlb = i_block;
    memcpy( p_newtitle->p_key, p_title_key, DVD_KEY_SIZE );

    /* Link it at the head of the (possibly empty) list */
    if( p_title == NULL )
    {
        p_newtitle->p_next = dvdcss->p_titles;
        dvdcss->p_titles = p_newtitle;
    }
    /* Link the new title inside the list */
    else
    {
        p_newtitle->p_next = p_title->p_next;
        p_title->p_next = p_newtitle;
    }

    memcpy( dvdcss->css.p_title_key, p_title_key, DVD_KEY_SIZE );
    return 0;
}


int sec_dvdcss_unscramble( uint8_t *x, uint8_t *p_sec ) {

    dvd_key p_key;
    memcpy(p_key, x, DVD_KEY_SIZE);

    unsigned int    i_t1, i_t2, i_t3, i_t4, i_t5, i_t6;
    uint8_t        *p_end = p_sec + DVDCSS_BLOCK_SIZE;

    /* PES_scrambling_control */
    if( !(p_sec[0x14] & 0x30) )
    {
        return 0;
    }

    i_t1 = (p_key[0] ^ p_sec[0x54]) | 0x100;
    i_t2 = p_key[1] ^ p_sec[0x55];
    i_t3 = (p_key[2] | (p_key[3] << 8) |
            (p_key[4] << 16)) ^ (p_sec[0x56] |
            (p_sec[0x57] << 8) | (p_sec[0x58] << 16));
    i_t4 = i_t3 & 7;
    i_t3 = i_t3 * 2 + 8 - i_t4;
    p_sec += 0x80;
    i_t5 = 0;

    while( p_sec != p_end )
    {
        i_t4 = p_css_tab2[i_t2] ^ p_css_tab3[i_t1];
        i_t2 = i_t1>>1;
        i_t1 = ( ( i_t1 & 1 ) << 8 ) ^ i_t4;
        i_t4 = p_css_tab5[i_t4];
        i_t6 = ((((((( i_t3 >> 3 ) ^ i_t3 ) >> 1 ) ^
                                      i_t3 ) >> 8 ) ^ i_t3 ) >> 5 ) & 0xff;
        i_t3 = (i_t3 << 8 ) | i_t6;
        i_t6 = p_css_tab4[i_t6];
        i_t5 += i_t6 + i_t4;
        *p_sec = p_css_tab1[*p_sec] ^ ( i_t5 & 0xff );
        p_sec++;
        i_t5 >>= 8;
    }

    return 0;


}

/*****************************************************************************
 * GetBusKey: Go through the Content Scrambling System (CSS) authentication process
 *****************************************************************************
 * It simulates the mutual authentication between logical unit and host,
 * and stops when a session key (called bus key) has been established.
 * Always do the full auth sequence. Some drives seem to lie and always
 * respond with ASF=1. For instance the old DVD-ROMs on Compaq Armada say
 * that ASF=1 from the start and then later fail with a 'read of scrambled
 * block without authentication' error.
 *****************************************************************************/
static int GetBusKey( dvdcss_s* dvdcss )
{
    uint8_t   p_buffer[10];
    uint8_t   p_challenge[2 * DVD_KEY_SIZE];
    dvd_key   p_key1;
    dvd_key   p_key2;
    dvd_key   p_key_check;
    uint8_t   i_variant = 0;
    int       i_ret = -1, i_ret2;
    int       i;

    print_debug( dvdcss, "requesting authentication grant ID (AGID)" );
    wrap_ioctl_ReportAgid(&i_ret, dvdcss->i_fd, &dvdcss->css.i_agid );

    /* We might have to reset hung authentication processes in the drive
     * by invalidating the corresponding authentication grant ID (AGID)'.
     * As long as we haven't got an AGID, invalidate one (in sequence)
     * and try again. */
    for( i = 0; i_ret == -1 && i < 4 ; ++i )
    {
        print_debug( dvdcss, "ioctl ReportAgid failed, invalidating "
                             "authentication grant ID (AGID) %d", i );

        /* This is really _not good_, should be handled by the OS.
         * Invalidating an AGID could make another process fail somewhere
         * in its authentication process. */
        dvdcss->css.i_agid = i;
        wrap_ioctl_InvalidateAgid(&i_ret2, dvdcss->i_fd, &dvdcss->css.i_agid );

        print_debug( dvdcss, "requesting authentication grant ID (AGID)" );
        wrap_ioctl_ReportAgid(&i_ret, dvdcss->i_fd, &dvdcss->css.i_agid );
    }

    /* Unable to authenticate without AGID */
    if( i_ret == -1 )
    {
        print_error( dvdcss, "ioctl ReportAgid failed, fatal" );
        return -1;
    }

    /* Setup a challenge, any values should work */
    for( i = 0 ; i < 10; ++i )
    {
        p_challenge[i] = i;
    }

    /* Get challenge from host */
    for( i = 0 ; i < 10 ; ++i )
    {
        p_buffer[9-i] = p_challenge[i];
    }

    /* Send challenge to LU */
    wrap_ioctl_SendChallenge(&i_ret, dvdcss->i_fd, &dvdcss->css.i_agid, p_buffer );
    if( i_ret < 0 )
    {
        print_error( dvdcss, "ioctl SendChallenge failed" );
        wrap_ioctl_InvalidateAgid(&i_ret2, dvdcss->i_fd, &dvdcss->css.i_agid );
        return -1;
    }

    printf("p_buffer[0] %x\n", p_buffer[0]);
    printf("&dvdcss->css.i_agid %p\n", &dvdcss->css.i_agid);
    printf("vdcss->i_fd %d\n", dvdcss->i_fd);
    printf("-------\n");

    /* Get key1 from LU */
    wrap_ioctl_ReportKey1(&i_ret, dvdcss->i_fd, &dvdcss->css.i_agid, p_buffer );
    if( i_ret < 0)
    {
        print_error( dvdcss, "ioctl ReportKey1 failed" );
        wrap_ioctl_InvalidateAgid(&i_ret2, dvdcss->i_fd, &dvdcss->css.i_agid );
        return -1;
    }

    /* Send key1 to host */
    for( i = 0 ; i < DVD_KEY_SIZE ; i++ )
    {
        p_key1[i] = p_buffer[4-i];
    }

    for( i = 0 ; i < 32 ; ++i )
    {
        CryptKey( 0, i, p_challenge, p_key_check );

        if( memcmp( p_key_check, p_key1, DVD_KEY_SIZE ) == 0 )
        {
            print_debug( dvdcss, "drive authenticated, using variant %d", i );
            i_variant = i;
            break;
        }
    }

    if( i == 32 )
    {
        print_error( dvdcss, "drive would not authenticate" );
        wrap_ioctl_InvalidateAgid(&i_ret2, dvdcss->i_fd, &dvdcss->css.i_agid );
        return -1;
    }

    /* Get challenge from LU */
    wrap_ioctl_ReportChallenge(&i_ret, dvdcss->i_fd, &dvdcss->css.i_agid, p_buffer );
    if( i_ret < 0 )
    {
        print_error( dvdcss, "ioctl ReportKeyChallenge failed" );
        wrap_ioctl_InvalidateAgid(&i_ret2, dvdcss->i_fd, &dvdcss->css.i_agid );
        return -1;
    }

    /* Send challenge to host */
    for( i = 0 ; i < 10 ; ++i )
    {
        p_challenge[i] = p_buffer[9-i];
    }

    CryptKey( 1, i_variant, p_challenge, p_key2 );

    /* Get key2 from host */
    for( i = 0 ; i < DVD_KEY_SIZE ; ++i )
    {
        p_buffer[4-i] = p_key2[i];
    }

    /* Send key2 to LU */
    wrap_ioctl_SendKey2(&i_ret, dvdcss->i_fd, &dvdcss->css.i_agid, p_buffer );
    if( i_ret < 0 )
    {
        print_error( dvdcss, "ioctl SendKey2 failed" );
        wrap_ioctl_InvalidateAgid(&i_ret2, dvdcss->i_fd, &dvdcss->css.i_agid );
        return -1;
    }

    /* The drive has accepted us as authentic. */
    print_debug( dvdcss, "authentication established" );

    memcpy( p_challenge, p_key1, DVD_KEY_SIZE );
    memcpy( p_challenge + DVD_KEY_SIZE, p_key2, DVD_KEY_SIZE );

    CryptKey( 2, i_variant, p_challenge, dvdcss->css.p_bus_key );

    return 0;
}

/*****************************************************************************
 * PrintKey: debug function that dumps a key value
 *****************************************************************************/
static void PrintKey( dvdcss_s* dvdcss, const char *prefix, const uint8_t *data )
{
    print_debug( dvdcss, "%s%02x:%02x:%02x:%02x:%02x", prefix,
                 data[0], data[1], data[2], data[3], data[4] );
}


/*****************************************************************************
 * GetASF: Get authentication success flag (ASF)
 *****************************************************************************
 * Returns:
 *  -1 on ioctl error,
 *  0 if the device needs to be authenticated,
 *  1 either.
 *****************************************************************************/
static int GetASF( dvdcss_s* dvdcss )
{
    int i_asf = 0;
    int i_ret;

    wrap_ioctl_ReportASF(&i_ret, dvdcss->i_fd, &i_asf);
    if( i_ret != 0 )
    {
        /* The ioctl process has failed */
        print_error( dvdcss, "GetASF fatal error" );
        return -1;
    }

    if( i_asf )
    {
        print_debug( dvdcss, "authentication success flag set, ASF=1" );
    }
    else
    {
        print_debug( dvdcss, "authentication success flag not set, ASF=0" );
    }

    return i_asf;
}

/*****************************************************************************
 * CryptKey: shuffle bits and decrypt keys.
 *****************************************************************************
 * Used during authentication and disc key negotiation in GetBusKey.
 * i_key_type: 0->key1, 1->key2, 2->buskey.
 * i_variant: between 0 and 31.
 *****************************************************************************/
static void CryptKey( int i_key_type, int i_variant,
                      const uint8_t *p_challenge, uint8_t *p_key )
{
    /* Permutation table for challenge */
    static const uint8_t pp_perm_challenge[3][10] =
            { { 1, 3, 0, 7, 5, 2, 9, 6, 4, 8 },
              { 6, 1, 9, 3, 8, 5, 7, 4, 0, 2 },
              { 4, 0, 3, 5, 7, 2, 8, 6, 1, 9 } };

    /* Permutation table for variant table for key2 and buskey */
    static const uint8_t pp_perm_variant[2][32] =
            { { 0x0a, 0x08, 0x0e, 0x0c, 0x0b, 0x09, 0x0f, 0x0d,
                0x1a, 0x18, 0x1e, 0x1c, 0x1b, 0x19, 0x1f, 0x1d,
                0x02, 0x00, 0x06, 0x04, 0x03, 0x01, 0x07, 0x05,
                0x12, 0x10, 0x16, 0x14, 0x13, 0x11, 0x17, 0x15 },
              { 0x12, 0x1a, 0x16, 0x1e, 0x02, 0x0a, 0x06, 0x0e,
                0x10, 0x18, 0x14, 0x1c, 0x00, 0x08, 0x04, 0x0c,
                0x13, 0x1b, 0x17, 0x1f, 0x03, 0x0b, 0x07, 0x0f,
                0x11, 0x19, 0x15, 0x1d, 0x01, 0x09, 0x05, 0x0d } };

    static const uint8_t p_variants[32] =
            {   0xB7, 0x74, 0x85, 0xD0, 0xCC, 0xDB, 0xCA, 0x73,
                0x03, 0xFE, 0x31, 0x03, 0x52, 0xE0, 0xB7, 0x42,
                0x63, 0x16, 0xF2, 0x2A, 0x79, 0x52, 0xFF, 0x1B,
                0x7A, 0x11, 0xCA, 0x1A, 0x9B, 0x40, 0xAD, 0x01 };

    /* The "secret" key */
    static const uint8_t p_secret[5] = { 0x55, 0xD6, 0xC4, 0xC5, 0x28 };

    uint8_t p_bits[30], p_scratch[10], p_tmp1[5], p_tmp2[5];
    uint8_t i_lfsr0_o;  /* 1 bit used */
    uint8_t i_lfsr1_o;  /* 1 bit used */
    uint8_t i_css_variant, i_cse, i_index, i_combined, i_carry;
    uint8_t i_val = 0;
    uint32_t i_lfsr0, i_lfsr1;
    int i_term = 0;
    int i_bit;
    int i;

    for (i = 9; i >= 0; --i)
        p_scratch[i] = p_challenge[pp_perm_challenge[i_key_type][i]];

    i_css_variant = ( i_key_type == 0 ) ? i_variant :
                    pp_perm_variant[i_key_type-1][i_variant];

    /*
     * This encryption engine implements one of 32 variations
     * one the same theme depending upon the choice in the
     * variant parameter (0 - 31).
     *
     * The algorithm itself manipulates a 40 bit input into
     * a 40 bit output.
     * The parameter 'input' is 80 bits.  It consists of
     * the 40 bit input value that is to be encrypted followed
     * by a 40 bit seed value for the pseudo random number
     * generators.
     */

    /* Feed the secret into the input values such that
     * we alter the seed to the LFSR's used above,  then
     * generate the bits to play with.
     */
    for( i = 5 ; --i >= 0 ; )
    {
        p_tmp1[i] = p_scratch[5 + i] ^ p_secret[i] ^ p_crypt_tab2[i];
    }

    /*
     * We use two LFSR's (seeded from some of the input data bytes) to
     * generate two streams of pseudo-random bits.  These two bit streams
     * are then combined by simply adding with carry to generate a final
     * sequence of pseudo-random bits which is stored in the buffer that
     * 'output' points to the end of - len is the size of this buffer.
     *
     * The first LFSR is of degree 25,  and has a polynomial of:
     * x^13 + x^5 + x^4 + x^1 + 1
     *
     * The second LFSR is of degree 17,  and has a (primitive) polynomial of:
     * x^15 + x^1 + 1
     *
     * I don't know if these polynomials are primitive modulo 2,  and thus
     * represent maximal-period LFSR's.
     *
     *
     * Note that we take the output of each LFSR from the new shifted in
     * bit,  not the old shifted out bit.  Thus for ease of use the LFSR's
     * are implemented in bit reversed order.
     *
     */

    /* In order to ensure that the LFSR works we need to ensure that the
     * initial values are non-zero.  Thus when we initialize them from
     * the seed,  we ensure that a bit is set.
     */
    i_lfsr0 = ( p_tmp1[0] << 17 ) | ( p_tmp1[1] << 9 ) |
              (( p_tmp1[2] & ~7 ) << 1 ) | 8 | ( p_tmp1[2] & 7 );
    i_lfsr1 = ( p_tmp1[3] << 9 ) | 0x100 | p_tmp1[4];

    i_index = sizeof(p_bits);
    i_carry = 0;

    do
    {
        for( i_bit = 0, i_val = 0 ; i_bit < 8 ; ++i_bit )
        {

            i_lfsr0_o = ( ( i_lfsr0 >> 24 ) ^ ( i_lfsr0 >> 21 ) ^
                        ( i_lfsr0 >> 20 ) ^ ( i_lfsr0 >> 12 ) ) & 1;
            i_lfsr0 = ( i_lfsr0 << 1 ) | i_lfsr0_o;

            i_lfsr1_o = ( ( i_lfsr1 >> 16 ) ^ ( i_lfsr1 >> 2 ) ) & 1;
            i_lfsr1 = ( i_lfsr1 << 1 ) | i_lfsr1_o;

            i_combined = !i_lfsr1_o + i_carry + !i_lfsr0_o;
            /* taking bit 1 */
            i_carry = ( i_combined >> 1 ) & 1;
            i_val |= ( i_combined & 1 ) << i_bit;
        }

        p_bits[--i_index] = i_val;
    } while( i_index > 0 );

    /* This term is used throughout the following to
     * select one of 32 different variations on the
     * algorithm.
     */
    i_cse = p_variants[i_css_variant] ^ p_crypt_tab2[i_css_variant];

    /* Now the actual blocks doing the encryption.  Each
     * of these works on 40 bits at a time and are quite
     * similar.
     */
    i_index = 0;
    for( i = 5, i_term = 0 ; --i >= 0 ; i_term = p_scratch[i] )
    {
        i_index = p_bits[25 + i] ^ p_scratch[i];
        i_index = p_crypt_tab1[i_index] ^ ~p_crypt_tab2[i_index] ^ i_cse;

        p_tmp1[i] = p_crypt_tab2[i_index] ^ p_crypt_tab3[i_index] ^ i_term;
    }
    p_tmp1[4] ^= p_tmp1[0];

    for( i = 5, i_term = 0 ; --i >= 0 ; i_term = p_tmp1[i] )
    {
        i_index = p_bits[20 + i] ^ p_tmp1[i];
        i_index = p_crypt_tab1[i_index] ^ ~p_crypt_tab2[i_index] ^ i_cse;

        p_tmp2[i] = p_crypt_tab2[i_index] ^ p_crypt_tab3[i_index] ^ i_term;
    }
    p_tmp2[4] ^= p_tmp2[0];

    for( i = 5, i_term = 0 ; --i >= 0 ; i_term = p_tmp2[i] )
    {
        i_index = p_bits[15 + i] ^ p_tmp2[i];
        i_index = p_crypt_tab1[i_index] ^ ~p_crypt_tab2[i_index] ^ i_cse;
        i_index = p_crypt_tab2[i_index] ^ p_crypt_tab3[i_index] ^ i_term;

        p_tmp1[i] = p_crypt_tab0[i_index] ^ p_crypt_tab2[i_index];
    }
    p_tmp1[4] ^= p_tmp1[0];

    for( i = 5, i_term = 0 ; --i >= 0 ; i_term = p_tmp1[i] )
    {
        i_index = p_bits[10 + i] ^ p_tmp1[i];
        i_index = p_crypt_tab1[i_index] ^ ~p_crypt_tab2[i_index] ^ i_cse;

        i_index = p_crypt_tab2[i_index] ^ p_crypt_tab3[i_index] ^ i_term;

        p_tmp2[i] = p_crypt_tab0[i_index] ^ p_crypt_tab2[i_index];
    }
    p_tmp2[4] ^= p_tmp2[0];

    for( i = 5, i_term = 0 ; --i >= 0 ; i_term = p_tmp2[i] )
    {
        i_index = p_bits[5 + i] ^ p_tmp2[i];
        i_index = p_crypt_tab1[i_index] ^ ~p_crypt_tab2[i_index] ^ i_cse;

        p_tmp1[i] = p_crypt_tab2[i_index] ^ p_crypt_tab3[i_index] ^ i_term;
    }
    p_tmp1[4] ^= p_tmp1[0];

    for(i = 5, i_term = 0 ; --i >= 0 ; i_term = p_tmp1[i] )
    {
        i_index = p_bits[i] ^ p_tmp1[i];
        i_index = p_crypt_tab1[i_index] ^ ~p_crypt_tab2[i_index] ^ i_cse;

        p_key[i] = p_crypt_tab2[i_index] ^ p_crypt_tab3[i_index] ^ i_term;
    }

    return;
}


/*****************************************************************************
 * DecryptKey: decrypt p_crypted with p_key.
 *****************************************************************************
 * Used to decrypt the disc key, with a player key, after requesting it
 * in dvdcss_disckey and to decrypt title keys, with a disc key, requested
 * in dvdcss_titlekey.
 * The player keys and the resulting disc key are only used as KEKs
 * (key encryption keys).
 * Decryption is slightly dependent on the type of key:
 *  -for disc key, invert is 0x00,
 *  -for title key, invert if 0xff.
 *****************************************************************************/
static void DecryptKey( uint8_t invert, const uint8_t *p_key,
                        const uint8_t *p_crypted, uint8_t *p_result )
{
    unsigned int    i_lfsr1_lo;
    unsigned int    i_lfsr1_hi;
    unsigned int    i_lfsr0;
    unsigned int    i_combined;
    uint8_t         o_lfsr0;
    uint8_t         o_lfsr1;
    uint8_t         k[5];
    int             i;

    i_lfsr1_lo = p_key[0] | 0x100;
    i_lfsr1_hi = p_key[1];

    i_lfsr0    = ( ( p_key[4] << 17 )
                 | ( p_key[3] << 9 )
                 | ( p_key[2] << 1 ) )
                 + 8 - ( p_key[2] & 7 );
    i_lfsr0    = ( p_css_tab4[i_lfsr0 & 0xff] << 24 ) |
                 ( p_css_tab4[( i_lfsr0 >> 8 ) & 0xff] << 16 ) |
                 ( p_css_tab4[( i_lfsr0 >> 16 ) & 0xff] << 8 ) |
                   p_css_tab4[( i_lfsr0 >> 24 ) & 0xff];

    i_combined = 0;
    for( i = 0 ; i < DVD_KEY_SIZE ; ++i )
    {
        o_lfsr1     = p_css_tab2[i_lfsr1_hi] ^ p_css_tab3[i_lfsr1_lo];
        i_lfsr1_hi  = i_lfsr1_lo >> 1;
        i_lfsr1_lo  = ( ( i_lfsr1_lo & 1 ) << 8 ) ^ o_lfsr1;
        o_lfsr1     = p_css_tab4[o_lfsr1];

        o_lfsr0 = ((((((( i_lfsr0 >> 8 ) ^ i_lfsr0 ) >> 1 )
                        ^ i_lfsr0 ) >> 3 ) ^ i_lfsr0 ) >> 7 );
        i_lfsr0 = ( i_lfsr0 >> 8 ) | ( o_lfsr0 << 24 );

        i_combined += ( o_lfsr0 ^ invert ) + o_lfsr1;
        k[i] = i_combined & 0xff;
        i_combined >>= 8;
    }

    p_result[4] = k[4] ^ p_css_tab1[p_crypted[4]] ^ p_crypted[3];
    p_result[3] = k[3] ^ p_css_tab1[p_crypted[3]] ^ p_crypted[2];
    p_result[2] = k[2] ^ p_css_tab1[p_crypted[2]] ^ p_crypted[1];
    p_result[1] = k[1] ^ p_css_tab1[p_crypted[1]] ^ p_crypted[0];
    p_result[0] = k[0] ^ p_css_tab1[p_crypted[0]] ^ p_result[4];

    p_result[4] = k[4] ^ p_css_tab1[p_result[4]] ^ p_result[3];
    p_result[3] = k[3] ^ p_css_tab1[p_result[3]] ^ p_result[2];
    p_result[2] = k[2] ^ p_css_tab1[p_result[2]] ^ p_result[1];
    p_result[1] = k[1] ^ p_css_tab1[p_result[1]] ^ p_result[0];
    p_result[0] = k[0] ^ p_css_tab1[p_result[0]];

    return;
}

/*****************************************************************************
 * player_keys: alternate DVD player keys
 *****************************************************************************
 * These player keys were generated using Frank A. Stevenson's PlayerKey
 * cracker. A copy of his article can be found here:
 * http://www-2.cs.cmu.edu/~dst/DeCSS/FrankStevenson/mail2.txt
 *****************************************************************************/
static const dvd_key player_keys[] =
{
    { 0x01, 0xaf, 0xe3, 0x12, 0x80 },
    { 0x12, 0x11, 0xca, 0x04, 0x3b },
    { 0x14, 0x0c, 0x9e, 0xd0, 0x09 },
    { 0x14, 0x71, 0x35, 0xba, 0xe2 },
    { 0x1a, 0xa4, 0x33, 0x21, 0xa6 },
    { 0x26, 0xec, 0xc4, 0xa7, 0x4e },
    { 0x2c, 0xb2, 0xc1, 0x09, 0xee },
    { 0x2f, 0x25, 0x9e, 0x96, 0xdd },
    { 0x33, 0x2f, 0x49, 0x6c, 0xe0 },
    { 0x35, 0x5b, 0xc1, 0x31, 0x0f },
    { 0x36, 0x67, 0xb2, 0xe3, 0x85 },
    { 0x39, 0x3d, 0xf1, 0xf1, 0xbd },
    { 0x3b, 0x31, 0x34, 0x0d, 0x91 },
    { 0x45, 0xed, 0x28, 0xeb, 0xd3 },
    { 0x48, 0xb7, 0x6c, 0xce, 0x69 },
    { 0x4b, 0x65, 0x0d, 0xc1, 0xee },
    { 0x4c, 0xbb, 0xf5, 0x5b, 0x23 },
    { 0x51, 0x67, 0x67, 0xc5, 0xe0 },
    { 0x53, 0x94, 0xe1, 0x75, 0xbf },
    { 0x57, 0x2c, 0x8b, 0x31, 0xae },
    { 0x63, 0xdb, 0x4c, 0x5b, 0x4a },
    { 0x7b, 0x1e, 0x5e, 0x2b, 0x57 },
    { 0x85, 0xf3, 0x85, 0xa0, 0xe0 },
    { 0xab, 0x1e, 0xe7, 0x7b, 0x72 },
    { 0xab, 0x36, 0xe3, 0xeb, 0x76 },
    { 0xb1, 0xb8, 0xf9, 0x38, 0x03 },
    { 0xb8, 0x5d, 0xd8, 0x53, 0xbd },
    { 0xbf, 0x92, 0xc3, 0xb0, 0xe2 },
    { 0xcf, 0x1a, 0xb2, 0xf8, 0x0a },
    { 0xec, 0xa0, 0xcf, 0xb3, 0xff },
    { 0xfc, 0x95, 0xa9, 0x87, 0x35 }
};

/*****************************************************************************
 * DecryptDiscKey
 *****************************************************************************
 * Decryption of the disc key with player keys: try to decrypt the disc key
 * from every position with every player key.
 * p_struct_disckey: the 2048 byte DVD_STRUCT_DISCKEY data
 * p_disc_key: result, the 5 byte disc key
 *****************************************************************************/
static int DecryptDiscKey( dvdcss_s* dvdcss, const uint8_t *p_struct_disckey,
                           dvd_key p_disc_key )
{
    uint8_t p_verify[DVD_KEY_SIZE];
    unsigned int i, n = 0;

    /* Decrypt disc key with the above player keys */
    for( n = 0; n < sizeof(player_keys) / sizeof(*player_keys); n++ )
    {
        PrintKey( dvdcss, "trying player key ", player_keys[n] );

        for( i = 1; i < 409; i++ )
        {
            /* Check if player key n is the right key for position i. */
            DecryptKey( 0, player_keys[n], p_struct_disckey + 5 * i,
                        p_disc_key );

            /* The first part in the struct_disckey block is the
             * 'disc key' encrypted with itself.  Using this we
             * can check if we decrypted the correct key. */
            DecryptKey( 0, p_disc_key, p_struct_disckey, p_verify );

            /* If the position / player key pair worked then return. */
            if( memcmp( p_disc_key, p_verify, DVD_KEY_SIZE ) == 0 )
            {
                return 0;
            }
        }
    }

    /* Have tried all combinations of positions and keys,
     * and we still didn't succeed. */
    memset( p_disc_key, 0, DVD_KEY_SIZE );
    return -1;
}

/*****************************************************************************
 * DecryptTitleKey
 *****************************************************************************
 * Decrypt the title key using the disc key.
 * p_disc_key: result, the 5 byte disc key
 * p_titlekey: the encrypted title key, gets overwritten by the decrypted key
 *****************************************************************************/
static void DecryptTitleKey( dvd_key p_disc_key, dvd_key p_titlekey )
{
    DecryptKey( 0xff, p_disc_key, p_titlekey, p_titlekey );
}

/*****************************************************************************
 * CrackDiscKey: brute force disc key
 * CSS hash reversal function designed by Frank Stevenson
 *****************************************************************************
 * This function uses a big amount of memory to crack the disc key from the
 * disc key hash, if player keys are not available.
 *****************************************************************************/
#define K1TABLESIZE  65536
#define K1TABLEWIDTH 10

#define BIGTABLESIZE 16777216

/*
 * Simple function to test if a candidate key produces the given hash
 */
static int investigate( unsigned char *hash, unsigned char *ckey )
{
    unsigned char key[DVD_KEY_SIZE];

    DecryptKey( 0, ckey, hash, key );

    return memcmp( key, ckey, DVD_KEY_SIZE );
}

static int CrackDiscKey( uint8_t *p_disc_key )
{
    unsigned char B[5] = { 0,0,0,0,0 }; /* Second Stage of mangle cipher */
    unsigned char C[5] = { 0,0,0,0,0 }; /* Output Stage of mangle cipher
                                         * IntermediateKey */
    unsigned char k[5] = { 0,0,0,0,0 }; /* Mangling cipher key
                                         * Also output from CSS( C ) */
    unsigned char out1[5];              /* five first output bytes of LFSR1 */
    unsigned char out2[5];              /* five first output bytes of LFSR2 */
    unsigned int lfsr1a;                /* upper 9 bits of LFSR1 */
    unsigned int lfsr1b;                /* lower 8 bits of LFSR1 */
    unsigned int tmp, tmp2, tmp3, tmp4,tmp5;
    int i, j, ret = 0;
    unsigned int nStepA;        /* iterator for LFSR1 start state */
    unsigned int nStepB;        /* iterator for possible B[0]     */
    unsigned int nTry;          /* iterator for K[1] possibilities */
    unsigned int nPossibleK1;   /* #of possible K[1] values */
    unsigned char* K1table;     /* Lookup table for possible K[1] */
    unsigned int*  BigTable;    /* LFSR2 startstate indexed by
                                 * 1,2,5 output byte */

    /*
     * Prepare tables for hash reversal
     */

    /* initialize lookup tables for k[1] */
    K1table = (unsigned char*)calloc( K1TABLESIZE, K1TABLEWIDTH );
    if( K1table == NULL )
    {
        return -1;
    }

    tmp = p_disc_key[0] ^ p_css_tab1[ p_disc_key[1] ];
    for( i = 0 ; i < 256 ; i++ ) /* k[1] */
    {
        tmp2 = p_css_tab1[ tmp ^ i ]; /* p_css_tab1[ B[1] ]*/

        for( j = 0 ; j < 256 ; j++ ) /* B[0] */
        {
            tmp3 = j ^ tmp2 ^ i; /* C[1] */
            tmp4 = K1table[ K1TABLEWIDTH * ( 256 * j + tmp3 ) ]; /* count of entries  here */
            tmp4++;
            if( tmp4 < K1TABLEWIDTH )
            {
                K1table[ K1TABLEWIDTH * ( 256 * j + tmp3 ) +    tmp4 ] = i;
            }
            K1table[ K1TABLEWIDTH * ( 256 * j + tmp3 ) ] = tmp4;
        }
    }

    /* Initializing our really big table */
    BigTable = (unsigned int*)calloc( BIGTABLESIZE, sizeof(*BigTable) );
    if( BigTable == NULL )
    {
        free( K1table );
        return -1;
    }

    tmp3 = 0;

    for( i = 0 ; i < BIGTABLESIZE ; i++ )
    {
        tmp = (( i + i ) & 0x1fffff0 ) | 0x8 | ( i & 0x7 );

        for( j = 0 ; j < 5 ; j++ )
        {
            tmp2=((((((( tmp >> 3 ) ^ tmp ) >> 1 ) ^ tmp ) >> 8 )
                                    ^ tmp ) >> 5 ) & 0xff;
            tmp = ( tmp << 8) | tmp2;
            out2[j] = p_css_tab4[ tmp2 ];
        }

        j = ( out2[0] << 16 ) | ( out2[1] << 8 ) | out2[4];
        if ( j >= BIGTABLESIZE )
        {
            ret = -1;
            goto error;
        }
        BigTable[j] = i;
    }

    /*
     * We are done initializing, now reverse hash
     */
    tmp5 = p_disc_key[0] ^ p_css_tab1[ p_disc_key[1] ];

    for( nStepA = 0 ; nStepA < K1TABLESIZE ; nStepA ++ )
    {
        lfsr1a = 0x100 | ( nStepA >> 8 );
        lfsr1b = nStepA & 0xff;

        /* Generate 5 first output bytes from lfsr1 */
        for( i = 0 ; i < 5 ; i++ )
        {
            tmp = p_css_tab2[ lfsr1b ] ^ p_css_tab3[ lfsr1a ];
            lfsr1b = lfsr1a >> 1;
            lfsr1a = ((lfsr1a&1)<<8) ^ tmp;
            out1[ i ] = p_css_tab4[ tmp ];
        }

        /* compute and cache some variables */
        C[0] = nStepA >> 8;
        C[1] = nStepA & 0xff;
        tmp = p_disc_key[3] ^ p_css_tab1[ p_disc_key[4] ];
        tmp2 = p_css_tab1[ p_disc_key[0] ];

        /* Search through all possible B[0] */
        for( nStepB = 0 ; nStepB < 256 ; nStepB++ )
        {
            /* reverse parts of the mangling cipher */
            B[0] = nStepB;
            k[0] = p_css_tab1[ B[0] ] ^ C[0];
            B[4] = B[0] ^ k[0] ^ tmp2;
            k[4] = B[4] ^ tmp;
            nPossibleK1 = K1table[ K1TABLEWIDTH * (256 * B[0] + C[1]) ];

            /* Try out all possible values for k[1] */
            for( nTry = 0 ; nTry < nPossibleK1 ; nTry++ )
            {
                k[1] = K1table[ K1TABLEWIDTH * (256 * B[0] + C[1]) + nTry + 1 ];
                B[1] = tmp5 ^ k[1];

                /* reconstruct output from LFSR2 */
                tmp3 = ( 0x100 + k[0] - out1[0] );
                out2[0] = tmp3 & 0xff;
                tmp3 = tmp3 & 0x100 ? 0x100 : 0xff;
                tmp3 = ( tmp3 + k[1] - out1[1] );
                out2[1] = tmp3 & 0xff;
                tmp3 = ( 0x100 + k[4] - out1[4] );
                out2[4] = tmp3 & 0xff;  /* Can be 1 off  */

                /* test first possible out2[4] */
                tmp4 = ( out2[0] << 16 ) | ( out2[1] << 8 ) | out2[4];
                if ( tmp4 >= BIGTABLESIZE )
                {
                    ret = -1;
                    goto error;
                }
                tmp4 = BigTable[ tmp4 ];
                C[2] = tmp4 & 0xff;
                C[3] = ( tmp4 >> 8 ) & 0xff;
                C[4] = ( tmp4 >> 16 ) & 0xff;
                B[3] = p_css_tab1[ B[4] ] ^ k[4] ^ C[4];
                k[3] = p_disc_key[2] ^ p_css_tab1[ p_disc_key[3] ] ^ B[3];
                B[2] = p_css_tab1[ B[3] ] ^ k[3] ^ C[3];
                k[2] = p_disc_key[1] ^ p_css_tab1[ p_disc_key[2] ] ^ B[2];

                if( ( B[1] ^ p_css_tab1[ B[2] ] ^ k[ 2 ]  ) == C[ 2 ] )
                {
                    if( ! investigate( &p_disc_key[0] , &C[0] ) )
                    {
                        goto end;
                    }
                }

                /* Test second possible out2[4] */
                out2[4] = ( out2[4] + 0xff ) & 0xff;
                tmp4 = ( out2[0] << 16 ) | ( out2[1] << 8 ) | out2[4];
                if ( tmp4 >= BIGTABLESIZE )
                {
                    ret = -1;
                    goto error;
                }
                tmp4 = BigTable[ tmp4 ];
                C[2] = tmp4 & 0xff;
                C[3] = ( tmp4 >> 8 ) & 0xff;
                C[4] = ( tmp4 >> 16 ) & 0xff;
                B[3] = p_css_tab1[ B[4] ] ^ k[4] ^ C[4];
                k[3] = p_disc_key[2] ^ p_css_tab1[ p_disc_key[3] ] ^ B[3];
                B[2] = p_css_tab1[ B[3] ] ^ k[3] ^ C[3];
                k[2] = p_disc_key[1] ^ p_css_tab1[ p_disc_key[2] ] ^ B[2];

                if( ( B[1] ^ p_css_tab1[ B[2] ] ^ k[ 2 ]  ) == C[ 2 ] )
                {
                    if( ! investigate( &p_disc_key[0] , &C[0] ) )
                    {
                        goto end;
                    }
                }
            }
        }
    }

end:
    memcpy( p_disc_key, &C[0], DVD_KEY_SIZE );

error:
    free( K1table );
    free( BigTable );

    return ret;
}

/*****************************************************************************
 * RecoverTitleKey: (title) key recovery from cipher and plain text
 * Function designed by Frank Stevenson
 *****************************************************************************
 * Called from Attack* which are in turn called by CrackTitleKey.  Given
 * a guessed(?) plain text and the cipher text.  Returns -1 on failure.
 *****************************************************************************/
static int RecoverTitleKey( int i_start, const uint8_t *p_crypted,
                            const uint8_t *p_decrypted,
                            const uint8_t *p_sector_seed, uint8_t *p_key )
{
    uint8_t p_buffer[10];
    unsigned int i_t1, i_t2, i_t3, i_t4, i_t5, i_t6;
    unsigned int i_try;
    unsigned int i_candidate;
    unsigned int i, j;
    int i_exit = -1;

    for( i = 0 ; i < 10 ; i++ )
    {
        p_buffer[i] = p_css_tab1[p_crypted[i]] ^ p_decrypted[i];
    }

    for( i_try = i_start ; i_try < 0x10000 ; i_try++ )
    {
        i_t1 = i_try >> 8 | 0x100;
        i_t2 = i_try & 0xff;
        i_t3 = 0;               /* not needed */
        i_t5 = 0;

        /* iterate cipher 4 times to reconstruct LFSR2 */
        for( i = 0 ; i < 4 ; i++ )
        {
            /* advance LFSR1 normally */
            i_t4 = p_css_tab2[i_t2] ^ p_css_tab3[i_t1];
            i_t2 = i_t1 >> 1;
            i_t1 = ( ( i_t1 & 1 ) << 8 ) ^ i_t4;
            i_t4 = p_css_tab5[i_t4];
            /* deduce i_t6 & i_t5 */
            i_t6 = p_buffer[i];
            if( i_t5 )
            {
                i_t6 = ( i_t6 + 0xff ) & 0x0ff;
            }
            if( i_t6 < i_t4 )
            {
                i_t6 += 0x100;
            }
            i_t6 -= i_t4;
            i_t5 += i_t6 + i_t4;
            i_t6 = p_css_tab4[ i_t6 ];
            /* feed / advance i_t3 / i_t5 */
            i_t3 = ( i_t3 << 8 ) | i_t6;
            i_t5 >>= 8;
        }

        i_candidate = i_t3;

        /* iterate 6 more times to validate candidate key */
        for( ; i < 10 ; i++ )
        {
            i_t4 = p_css_tab2[i_t2] ^ p_css_tab3[i_t1];
            i_t2 = i_t1 >> 1;
            i_t1 = ( ( i_t1 & 1 ) << 8 ) ^ i_t4;
            i_t4 = p_css_tab5[i_t4];
            i_t6 = ((((((( i_t3 >> 3 ) ^ i_t3 ) >> 1 ) ^
                                         i_t3 ) >> 8 ) ^ i_t3 ) >> 5 ) & 0xff;
            i_t3 = ( i_t3 << 8 ) | i_t6;
            i_t6 = p_css_tab4[i_t6];
            i_t5 += i_t6 + i_t4;
            if( ( i_t5 & 0xff ) != p_buffer[i] )
            {
                break;
            }

            i_t5 >>= 8;
        }

        if( i == 10 )
        {
            /* Do 4 backwards steps of iterating t3 to deduce initial state */
            i_t3 = i_candidate;
            for( i = 0 ; i < 4 ; i++ )
            {
                i_t1 = i_t3 & 0xff;
                i_t3 = ( i_t3 >> 8 );
                /* easy to code, and fast enough brute-force
                 * search for byte shifted in */
                for( j = 0 ; j < 256 ; j++ )
                {
                    i_t3 = ( i_t3 & 0x1ffff ) | ( j << 17 );
                    i_t6 = ((((((( i_t3 >> 3 ) ^ i_t3 ) >> 1 ) ^
                                   i_t3 ) >> 8 ) ^ i_t3 ) >> 5 ) & 0xff;
                    if( i_t6 == i_t1 )
                    {
                        break;
                    }
                }
            }

            i_t4 = ( i_t3 >> 1 ) - 4;
            for( i_t5 = 0 ; i_t5 < 8; i_t5++ )
            {
                if( ( ( i_t4 + i_t5 ) * 2 + 8 - ( (i_t4 + i_t5 ) & 7 ) )
                                                                      == i_t3 )
                {
                    p_key[0] = i_try>>8;
                    p_key[1] = i_try & 0xFF;
                    p_key[2] = ( ( i_t4 + i_t5 ) >> 0 ) & 0xFF;
                    p_key[3] = ( ( i_t4 + i_t5 ) >> 8 ) & 0xFF;
                    p_key[4] = ( ( i_t4 + i_t5 ) >> 16 ) & 0xFF;
                    i_exit = i_try + 1;
                }
            }
        }
    }

    if( i_exit >= 0 )
    {
        p_key[0] ^= p_sector_seed[0];
        p_key[1] ^= p_sector_seed[1];
        p_key[2] ^= p_sector_seed[2];
        p_key[3] ^= p_sector_seed[3];
        p_key[4] ^= p_sector_seed[4];
    }

    return i_exit;
}


/******************************************************************************
 * Various pieces for the title crack engine.
 ******************************************************************************
 * The length of the PES packet is located at 0x12-0x13.
 * The the copyright protection bits are located at 0x14 (bits 0x20 and 0x10).
 * The data of the PES packet begins at 0x15 (if there isn't any PTS/DTS)
 * or at 0x?? if there are both PTS and DTS's.
 * The seed value used with the unscrambling key is the 5 bytes at 0x54-0x58.
 * The scrambled part of a sector begins at 0x80.
 *****************************************************************************/

/* Statistics */
static int i_tries = 0, i_success = 0;

/*****************************************************************************
 * CrackTitleKey: try to crack title key from the contents of a VOB.
 *****************************************************************************
 * This function is called by dvdcss_s*itlekey to find a title key, if we've
 * chosen to crack title key instead of decrypting it with the disc key.
 * The DVD should have been opened and be in an authenticated state.
 * i_pos is the starting sector, i_len is the maximum number of sectors to read
 *****************************************************************************/
static int CrackTitleKey( dvdcss_s* dvdcss, int i_pos, int i_len,
                          dvd_key p_titlekey )
{
    uint8_t       p_buf[ DVDCSS_BLOCK_SIZE ];
    const uint8_t p_packstart[4] = { 0x00, 0x00, 0x01, 0xba };
    int i_reads = 0;
    int i_encrypted = 0;
    int b_stop_scanning = 0;
    int b_read_error = 0;
    int i_ret;
    int i_ret2;

    print_debug( dvdcss, "cracking title key at block %i", i_pos );

    i_tries = 0;
    i_success = 0;

    do
    {
        // i_ret = dvdcss->pf_seek( dvdcss, i_pos );
        raw_pf_seek(&i_ret, dvdcss, dvdcss, i_pos );

        if( i_ret != i_pos )
        {
            print_error( dvdcss, "seek failed" );
        }

        dvdcss_read_u(&i_ret, dvdcss, p_buf, 1, DVDCSS_NOFLAGS );

        /* Either we are at the end of the physical device or the auth
         * have failed / were not done and we got a read error. */
        if( i_ret <= 0 )
        {
            if( i_ret == 0 )
            {
                print_debug( dvdcss, "read returned 0 (end of device?)" );
            }
            else if( !b_read_error )
            {
                print_debug( dvdcss, "read error at block %i, resorting to "
                                     "arcane secrets to recover", i_pos );

                /* Reset the drive before trying to continue */
                dvdcss_close_device_u( &i_ret2, dvdcss );
                dvdcss_open_device_u( &i_ret2, dvdcss );

                b_read_error = 1;
                continue;
            }
            break;
        }

        /* Stop when we find a non-MPEG stream block.
         * (We must have reached the end of the stream).
         * For now, allow all blocks that begin with a start code. */
        if( memcmp( p_buf, p_packstart, 3 ) )
        {
            print_debug( dvdcss, "block %i is a non-MPEG block "
                                 "(end of title)", i_pos );
            break;
        }

        if( p_buf[0x0d] & 0x07 )
            print_debug( dvdcss, "stuffing in pack header" );

        /* PES_scrambling_control does not exist in a system_header,
         * a padding_stream or a private_stream2 (and others?). */
        if( p_buf[0x14] & 0x30  && ! ( p_buf[0x11] == 0xbb
                                       || p_buf[0x11] == 0xbe
                                       || p_buf[0x11] == 0xbf ) )
        {
            i_encrypted++;

            if( AttackPattern( p_buf, p_titlekey ) > 0 )
            {
                b_stop_scanning = 1;
            }
#if 0
            if( AttackPadding( p_buf ) > 0 )
            {
                b_stop_scanning = 1;
            }
#endif /* 0 */
        }

        i_pos++;
        i_len--;
        i_reads++;

        /* Emit a progress indication now and then. */
        if( !( i_reads & 0xfff ) )
        {
            print_debug( dvdcss, "at block %i, still cracking...", i_pos );
        }

        /* Stop after 2000 blocks if we haven't seen any encrypted blocks. */
        if( i_reads >= 2000 && i_encrypted == 0 ) break;

    } while( !b_stop_scanning && i_len > 0);

    if( !b_stop_scanning )
    {
        print_debug( dvdcss, "end of title reached" );
    }

    /* Print some statistics. */
    print_debug( dvdcss, "successful attempts %d/%d, scrambled blocks %d/%d",
                         i_success, i_tries, i_encrypted, i_reads );

    if( i_success > 0 /* b_stop_scanning */ )
    {
        print_debug( dvdcss, "Video Title Set (VTS) key initialized" );
        return 1;
    }

    if( i_encrypted == 0 && i_reads > 0 )
    {
        memset( p_titlekey, 0, DVD_KEY_SIZE );
        print_debug( dvdcss, "no scrambled sectors found" );
        return 0;
    }

    memset( p_titlekey, 0, DVD_KEY_SIZE );
    return -1;
}


/******************************************************************************
 * The original Ethan Hawke (DeCSSPlus) attack (modified).
 ******************************************************************************
 * Tries to find a repeating pattern just before the encrypted part starts.
 * Then it guesses that the plain text for first encrypted bytes are
 * a continuation of that pattern.
 *****************************************************************************/
static int AttackPattern( const uint8_t p_sec[ DVDCSS_BLOCK_SIZE ],
                          uint8_t *p_key )
{
    unsigned int i_best_plen = 0;
    unsigned int i_best_p = 0;
    unsigned int i, j;

    /* For all cycle length from 2 to 48 */
    for( i = 2 ; i < 0x30 ; i++ )
    {
        /* Find the number of bytes that repeats in cycles. */
        for( j = i + 1;
             j < 0x80 && ( p_sec[0x7F - (j%i)] == p_sec[0x7F - j] );
             j++ )
        {
            /* We have found j repeating bytes with a cycle length i. */
            if( j > i_best_plen )
            {
                i_best_plen = j;
                i_best_p = i;
            }
        }
    }

    /* We need at most 10 plain text bytes?, so a make sure that we
     * have at least 20 repeated bytes and that they have cycled at
     * least one time.  */
    if( ( i_best_plen > 3 ) && ( i_best_plen / i_best_p >= 2) )
    {
        int res;

        i_tries++;
        memset( p_key, 0, DVD_KEY_SIZE );
        res = RecoverTitleKey( 0,  &p_sec[0x80],
                      &p_sec[ 0x80 - (i_best_plen / i_best_p) * i_best_p ],
                      &p_sec[0x54] /* key_seed */, p_key );
        i_success += ( res >= 0 );
        return ( res >= 0 );
    }

    return 0;
}

/*****************************************************************************
 * dvdcss_titlekey: get title key.
 *****************************************************************************/
static int dvdcss_titlekey( dvdcss_s* dvdcss, int i_pos, dvd_key p_title_key )
{
    static uint8_t p_garbage[ DVDCSS_BLOCK_SIZE ];  /* we never read it back */
    uint8_t p_key[DVD_KEY_SIZE];
    int i, i_ret = 0, i_ret2;

    if( dvdcss->b_ioctls && ( dvdcss->i_method == DVDCSS_METHOD_KEY ||
                              dvdcss->i_method == DVDCSS_METHOD_DISC ) )
    {
        /* We have a decrypted Disc key and the ioctls are available,
         * read the title key and decrypt it.
         */

        print_debug( dvdcss, "getting title key at block %i the classic way",
                             i_pos );

        /* We need to authenticate again every time to get a new session key */
        if( GetBusKey( dvdcss ) < 0 )
        {
            i_ret = -1;
        }

        /* Get encrypted title key */
        wrap_ioctl_ReadTitleKey(&i_ret2, dvdcss->i_fd, &dvdcss->css.i_agid, i_pos, p_key );
        if( i_ret2 < 0 )
        {
            print_debug( dvdcss,
                         "ioctl ReadTitleKey failed (region mismatch?)" );
            i_ret = -1;
        }

        /* Test ASF, it will be reset to 0 if we got a Region error */
        switch( GetASF( dvdcss ) )
        {
            case -1:
                /* An error getting the ASF status, something must be wrong. */
                print_debug( dvdcss, "lost authentication success flag (ASF), requesting title key" );
                wrap_ioctl_InvalidateAgid( &i_ret2, dvdcss->i_fd, &dvdcss->css.i_agid );
                i_ret = -1;
                break;

            case 0:
                /* This might either be a title that has no key,
                 * or we encountered a region error. */
                print_debug( dvdcss, "lost authentication success flag (ASF), requesting title key" );
                break;

            case 1:
                /* Drive status is OK. */
                /* If the title key request failed, but we did not lose ASF,
                 * we might still have the AGID.  Other code assumes that we
                 * will not after this so invalidate it(?). */
                if( i_ret < 0 )
                {
                    wrap_ioctl_InvalidateAgid(&i_ret2, dvdcss->i_fd, &dvdcss->css.i_agid );
                }
                break;
        }

        if( !( i_ret < 0 ) )
        {
            /* Decrypt title key using the bus key */
            for( i = 0 ; i < DVD_KEY_SIZE ; i++ )
            {
                p_key[i] ^= dvdcss->css.p_bus_key[4 - (i % DVD_KEY_SIZE)];
            }

            /* If p_key is all zero then there really wasn't any key present
             * even though we got to read it without an error. */
            if( !( p_key[0] | p_key[1] | p_key[2] | p_key[3] | p_key[4] ) )
            {
                i_ret = 0;
            }
            else
            {
                PrintKey( dvdcss, "initial disc key ", dvdcss->css.p_disc_key );
                DecryptTitleKey( dvdcss->css.p_disc_key, p_key );
                PrintKey( dvdcss, "decrypted title key ", p_key );
                i_ret = 1;
            }

            /* All went well either there wasn't a key or we have it now. */
            memcpy( p_title_key, p_key, DVD_KEY_SIZE );
            PrintKey( dvdcss, "title key is ", p_title_key );

            return i_ret;
        }

        /* The title key request failed */
        print_debug( dvdcss, "resetting drive and cracking title key" );

        /* Read an unscrambled sector and reset the drive */
        // dvdcss->pf_seek( dvdcss, 0 );
        raw_pf_seek(&i_ret2, dvdcss, dvdcss, 0 );
        // dvdcss->pf_read( dvdcss, p_garbage, 1 );
        raw_pf_read(&i_ret2, dvdcss, dvdcss, p_garbage, 1 );
        // dvdcss->pf_seek( dvdcss, 0 );
        raw_pf_seek(&i_ret2, dvdcss, dvdcss, 0 );
        dvdcss_disckey(dvdcss);

        /* Fallback */
    }

    /* METHOD is TITLE, we can't use the ioctls or requesting the title key
     * failed above.  For these cases we try to crack the key instead. */

    /* For now, the read limit is 9GB / 2048 =  4718592 sectors. */
    i_ret = CrackTitleKey( dvdcss, i_pos, 4718592, p_key );

    memcpy( p_title_key, p_key, DVD_KEY_SIZE );
    PrintKey( dvdcss, "title key is ", p_title_key );

    return i_ret;
}

int sec_dvdcss_disckey(void* dvdcss) {
  return dvdcss_disckey((dvdcss_s* )dvdcss);
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
int dvdcss_disckey( dvdcss_s* dvdcss )
{
    unsigned char p_buffer[ DVD_DISCKEY_SIZE ];
    dvd_key p_disc_key;
    int i, i_ret2;

    if( GetBusKey( dvdcss ) < 0 )
    {
        return -1;
    }

    /* Get encrypted disc key */
    wrap_ioctl_ReadDiscKey(&i_ret2, dvdcss->i_fd, &dvdcss->css.i_agid, p_buffer );
    if( i_ret2 < 0 )
    {
        print_error( dvdcss, "ioctl ReadDiscKey failed" );
        return -1;
    }

    /* This should have invalidated the AGID and got us ASF=1. */
    if( GetASF( dvdcss ) != 1 )
    {
        /* Region mismatch (or region not set) is the most likely source. */
        print_error( dvdcss, "authentication success flag (ASF) not 1 after "
                             "reading disc key (region mismatch?)" );
        wrap_ioctl_InvalidateAgid(&i_ret2, dvdcss->i_fd, &dvdcss->css.i_agid );
        return -1;
    }

    /* Shuffle disc key using bus key */
    for( i = 0 ; i < DVD_DISCKEY_SIZE ; i++ )
    {
        p_buffer[i] ^= dvdcss->css.p_bus_key[4 - (i % DVD_KEY_SIZE)];
    }

    /* Decrypt disc key */
    switch( dvdcss->i_method )
    {
        case DVDCSS_METHOD_KEY:

            /* Decrypt disc key with player key. */
            PrintKey( dvdcss, "decrypting disc key ", p_buffer );
            if( ! DecryptDiscKey( dvdcss, p_buffer, p_disc_key ) )
            {
                PrintKey( dvdcss, "decrypted disc key is ", p_disc_key );
                break;
            }
            print_debug( dvdcss, "failed to decrypt the disc key, "
                                 "faulty drive/kernel? "
                                 "cracking title keys instead" );

            /* Fallback, but not to DISC as the disc key might be faulty */
            memset( p_disc_key, 0, DVD_KEY_SIZE );
            dvdcss->i_method = DVDCSS_METHOD_TITLE;
            break;

        case DVDCSS_METHOD_DISC:

            /* Crack Disc key to be able to use it */
            memcpy( p_disc_key, p_buffer, DVD_KEY_SIZE );
            PrintKey( dvdcss, "cracking disc key ", p_disc_key );
            if( ! CrackDiscKey( p_disc_key ) )
            {
                PrintKey( dvdcss, "cracked disc key is ", p_disc_key );
                break;
            }
            print_debug( dvdcss, "failed to crack the disc key" );
            memset( p_disc_key, 0, DVD_KEY_SIZE );
            dvdcss->i_method = DVDCSS_METHOD_TITLE;
            break;

        default:

            print_debug( dvdcss, "disc key does not need to be decrypted" );
            memset( p_disc_key, 0, DVD_KEY_SIZE );
            break;
    }

    memcpy( dvdcss->css.p_disc_key, p_disc_key, DVD_KEY_SIZE );

    return 0;
}

int sscanf(const char *str, const char *format, ...)
{
	const char *start = str;
	va_list args;
	
	va_start(args, format);
	for ( ; *format != '\0'; format++) {
		if (*format == '%' && format[1] == 'd') {
			int positive;
			int value;
			int *valp;
			
			if (*str == '-') {
				positive = 0;
				str++;
			} else
				positive = 1;
			if (!isdigit(*str))
				break;
			value = 0;
			do {
				value = (value * 10) - (*str - '0');
				str++;
			} while (isdigit(*str));
			if (positive)
				value = -value;
			valp = va_arg(args, int *);
			*valp = value;
			format++;
		} else if (*format == *str) {
			str++;
		} else
			break;
	}
	va_end(args);
	return str - start;
}