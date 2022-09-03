/*****************************************************************************
 * libdvdcss.h: private DVD reading library data
 *****************************************************************************
 * Copyright (C) 1998-2001 VideoLAN
 *
 * Authors: Stéphane Borel <stef@via.ecp.fr>
 *          Sam Hocevar <sam@zoy.org>
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

#ifndef DVDCSS_LIBDVDCSS_H
#define DVDCSS_LIBDVDCSS_H

// #include <limits.h>

// #include "css.h"
// #include "device.h"

/** Set of callbacks to access DVDs in custom ways. */
typedef struct dvdcss_stream_cb
{
    /** custom seek callback */
    int ( *pf_seek )  ( void *p_stream, uint64_t i_pos);
    /** custom read callback */
    int ( *pf_read )  ( void *p_stream, void *buffer, int i_read);
    /** custom vectored read callback */
    int ( *pf_readv ) ( void *p_stream, const void *p_iovec, int i_blocks);
} dvdcss_stream_cb;

#define CACHE_FILENAME_LENGTH_STRING "10"

#define DVD_KEY_SIZE 5

#define PSZ_KEY_SIZE (DVD_KEY_SIZE * 3)

#define PATH_MAX 2048

#define DVDCSS_BLOCK_SIZE 2048

/** The default flag to be used by \e libdvdcss functions. */
#define DVDCSS_NOFLAGS         0

/** Flag to ask dvdcss_read() to decrypt the data it reads. */
#define DVDCSS_READ_DECRYPT    (1 << 0)

/** Flag to tell dvdcss_seek() it is seeking in MPEG data. */
#define DVDCSS_SEEK_MPEG       (1 << 0)

/** Flag to ask dvdcss_seek() to check the current title key. */
#define DVDCSS_SEEK_KEY        (1 << 1)

#define DVD_DISCKEY_SIZE 2048

typedef uint8_t dvd_key[DVD_KEY_SIZE];

typedef struct dvd_title
{
    int               i_startlb;
    dvd_key           p_key;
    struct dvd_title *p_next;
} dvd_title;

typedef struct css
{
    int             i_agid;      /* Current Authentication Grant ID. */
    dvd_key         p_bus_key;   /* Current session key. */
    dvd_key         p_disc_key;  /* This DVD disc's key. */
    dvd_key         p_title_key; /* Current title key. */
} css;

/*****************************************************************************
 * libdvdcss method: used like init flags
 *****************************************************************************/
enum dvdcss_method {
    DVDCSS_METHOD_KEY,
    DVDCSS_METHOD_DISC,
    DVDCSS_METHOD_TITLE,
};
/*****************************************************************************
 * The libdvdcss structure
 *****************************************************************************/
struct dvdcss_s
{
    /* File descriptor */
    char * psz_device;
    int    i_fd;
    int    i_pos;

    /* File handling */
    int ( * pf_seek )  ( dvdcss_s*, int );
    int ( * pf_read )  ( dvdcss_s*, void *, int );
    int ( * pf_readv ) ( dvdcss_s*, const struct iovec *, int );

    /* Decryption stuff */
    enum dvdcss_method i_method;
    struct css   css;
    int          b_ioctls;
    int          b_scrambled;
    struct dvd_title *p_titles;

    /* Key cache directory and pointer to the filename */
    char   psz_cachefile[PATH_MAX];
    char * psz_block;

    /* Error management */
    const char *psz_error;
    int    b_errors;
    int    b_debug;

#ifdef _WIN32
    int    b_file;
    char * p_readv_buffer;
    int    i_readv_buf_size;
#endif /* _WIN32 */

    void                *p_stream;
    dvdcss_stream_cb    *p_stream_cb;
};

/*****************************************************************************
 * Functions used across the library
 *****************************************************************************/
void print_error ( dvdcss_s*, const char *, ... );
void print_debug ( const dvdcss_s*, const char *, ... );

#endif /* DVDCSS_LIBDVDCSS_H */
