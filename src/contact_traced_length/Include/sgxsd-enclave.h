/*
 * Copyright (C) 2017 Open Whisper Systems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @author Jeff Griffin
 */
#ifndef _SGXSD_ENCLAVE_H
#define _SGXSD_ENCLAVE_H

#include "sgx_error.h"

#include "sgxsd.h"

typedef struct sgxsd_msg_buf {
    uint8_t *data;
    uint32_t size;
} sgxsd_msg_buf_t;

typedef struct sgxsd_msg_from {
    sgxsd_msg_tag_t tag;
    sgxsd_aes_gcm_key_t server_key;
} sgxsd_msg_from_t;

//
// callbacks
//

// the incomplete type sgxsd_server_state doesn't necessarily need to be defined
typedef struct sgxsd_server_state sgxsd_server_state_t;

/* the incomplete types sgxsd_server_{init,handle_call,terminate}_args must be defined and included before sgxsd APIs
   in the .edl file */
typedef struct sgxsd_server_init_args sgxsd_server_init_args_t;
typedef struct sgxsd_server_handle_call_args sgxsd_server_handle_call_args_t;
typedef struct sgxsd_server_terminate_args sgxsd_server_terminate_args_t;

// the callbacks sgxsd_enclave_server_{init,handle_call,terminate} handle sgxsd_enclave_server_{start,call,stop} calls
sgx_status_t sgxsd_enclave_server_init(const sgxsd_server_init_args_t *p_args, sgxsd_server_state_t **pp_state);
sgx_status_t sgxsd_enclave_server_handle_call(const sgxsd_server_handle_call_args_t *p_args, sgxsd_msg_buf_t msg, sgxsd_msg_from_t from, sgxsd_server_state_t **pp_state);
sgx_status_t sgxsd_enclave_server_terminate(const sgxsd_server_terminate_args_t *p_args, sgxsd_server_state_t *p_state);

//
// public api
//

// sgxsd_enclave_server_reply sends a reply to the message corresponding to the given sgxsd_msg_from from handle_call
sgx_status_t sgxsd_enclave_server_reply(sgxsd_msg_buf_t reply_buf, sgxsd_msg_from_t from);

//
// public utility apis
//

sgx_status_t sgxsd_aes_gcm_encrypt(const sgxsd_aes_gcm_key_t *p_key,
				   const void *p_src, uint32_t src_len, void *p_dst,
				   const sgxsd_aes_gcm_iv_t *p_iv,
                                   const void *p_aad, uint32_t aad_len,
                                   sgxsd_aes_gcm_mac_t *p_out_mac);

sgx_status_t sgxsd_aes_gcm_decrypt(const sgxsd_aes_gcm_key_t *p_key,
				   const void *p_src, uint32_t src_len, void *p_dst,
				   const sgxsd_aes_gcm_iv_t *p_iv,
                                   const void *p_aad, uint32_t aad_len,
                                   const sgxsd_aes_gcm_mac_t *p_in_mac);

//
// internal definitions
//

typedef struct sgxsd_curve25519_private_key {
    uint8_t x[SGXSD_CURVE25519_KEY_SIZE];
} sgxsd_curve25519_private_key_t;

typedef struct sgxsd_curve25519_key_pair {
    sgxsd_curve25519_private_key_t privkey;
    sgxsd_curve25519_public_key_t pubkey;
} sgxsd_curve25519_key_pair_t;

#endif
