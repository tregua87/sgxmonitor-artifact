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


#ifndef _ECP_INTERFACE_H
#define _ECP_INTERFACE_H

#include "sgx_ecp_types.h"
#include "sgx_tcrypto.h"

//Key Derivation Function ID : 0x0001  AES-CMAC Entropy Extraction and Key Expansion
const uint16_t AES_CMAC_KDF_ID = 0x0001;

sgx_status_t derive_key(
    const sgx_ec256_dh_shared_t* shared_key,
    const char* label,
    uint32_t label_length,
    sgx_ec_key_128bit_t* derived_key);

#ifndef INTERNAL_SGX_ERROR_CODE_CONVERTOR
#define INTERNAL_SGX_ERROR_CODE_CONVERTOR(x) if(x != SGX_ERROR_OUT_OF_MEMORY){x = SGX_ERROR_UNEXPECTED;}
#endif

#endif
