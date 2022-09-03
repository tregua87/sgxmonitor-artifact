/*
* Copyright (c) 2017, Intel Corporation
*
* Redistribution and use in source and binary forms, with or without modification,
* are permitted provided that the following conditions are met:

* 1. Redistributions of source code must retain the above copyright notice,
*    this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
* 3. Neither the name of the copyright holder nor the names of its contributors
*    may be used to endorse or promote products derived from this software
*    without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
* THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
* BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
* OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
* OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
* OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
* WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
* OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
* EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/


#include "ByteOperands.h"

namespace intel { namespace sgx { namespace qvl {

uint16_t swapBytes(uint16_t val)
{
    return static_cast<uint16_t>( (val << 8) | (val >> 8) );
}

uint32_t swapBytes(uint32_t val)
{
    return (
            ((val << 24) & 0xff000000) |
            ((val <<  8) & 0x00ff0000) |
            ((val >>  8) & 0x0000ff00) |
            ((val >> 24) & 0x000000ff)
          );
}

uint16_t toUint16(uint8_t leftMostByte, uint8_t rightMostByte)
{
    uint16_t ret = 0;
    ret |= static_cast<uint16_t>(rightMostByte);
    ret |= (static_cast<uint16_t>(leftMostByte) << 8) & 0xff00;
    return ret;
}

uint32_t toUint32(uint16_t msBytes, uint16_t lsBytes)
{
    uint32_t ret = 0;
    
    ret |= static_cast<uint32_t>(lsBytes);
    ret |= (static_cast<uint32_t>(msBytes) << 16) & 0xffff0000;

    return ret;
}
uint32_t toUint32(uint8_t leftMostByte, uint8_t leftByte, uint8_t rightByte, uint8_t rightMostByte)
{
    return toUint32(toUint16(leftMostByte, leftByte), toUint16(rightByte, rightMostByte));
}

std::array<uint8_t,2> toArray(uint16_t val)
{
    return {{ static_cast<uint8_t>(val >> 8), static_cast<uint8_t>(val) }};
}
std::array<uint8_t,4> toArray(uint32_t val)
{
    return {{
        static_cast<uint8_t>((val >> 24) & 0x000000FF),
        static_cast<uint8_t>((val >> 16) & 0x000000FF),
        static_cast<uint8_t>((val >> 8) & 0x000000FF),
        static_cast<uint8_t>(val & 0x000000FF),
    }};
}

}}} // namespace intel { namespace sgx { namespace qvl {
