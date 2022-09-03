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

#include <AESGXGetExtendedEpidGroupIdRequest.h>
#include <AESGXGetExtendedEpidGroupIdResponse.h>
#include <IAESMLogic.h>
#include <stdlib.h>
#include <limits.h>
#include <IAEMessage.h>

AESGXGetExtendedEpidGroupIdRequest::AESGXGetExtendedEpidGroupIdRequest(const aesm::message::Request::SGXGetExtendedEpidGroupIdRequest& request) :
    m_request(NULL)
{
    m_request = new aesm::message::Request::SGXGetExtendedEpidGroupIdRequest();
    m_request->CopyFrom(request);
}

AESGXGetExtendedEpidGroupIdRequest::AESGXGetExtendedEpidGroupIdRequest(uint32_t timeout)
    :m_request(NULL)
{
    m_request = new aesm::message::Request::SGXGetExtendedEpidGroupIdRequest();
    m_request->set_timeout(timeout);
}

AESGXGetExtendedEpidGroupIdRequest::AESGXGetExtendedEpidGroupIdRequest(const AESGXGetExtendedEpidGroupIdRequest& other)
    : m_request(NULL)
{
    if (other.m_request != NULL)
        m_request = new aesm::message::Request::SGXGetExtendedEpidGroupIdRequest(*other.m_request);
}

AESGXGetExtendedEpidGroupIdRequest::~AESGXGetExtendedEpidGroupIdRequest()
{
    if (m_request != NULL)
        delete m_request;
}



AEMessage* AESGXGetExtendedEpidGroupIdRequest::serialize()
{
    AEMessage *ae_msg = NULL;
    aesm::message::Request msg;
    if (check())
    {
        aesm::message::Request::SGXGetExtendedEpidGroupIdRequest* mutableReq = msg.mutable_sgxgetextendedepidgroupidreq();
        mutableReq->CopyFrom(*m_request);

        if (msg.ByteSize() <= INT_MAX) {
            ae_msg = new AEMessage;
            ae_msg->size = (unsigned int)msg.ByteSize();
            ae_msg->data = new char[ae_msg->size];
            msg.SerializeToArray(ae_msg->data, ae_msg->size);
        }
    }
    return ae_msg;
}

IAERequest::RequestClass AESGXGetExtendedEpidGroupIdRequest::getRequestClass() {
    return QUOTING_CLASS;
}


AESGXGetExtendedEpidGroupIdRequest& AESGXGetExtendedEpidGroupIdRequest::operator=(const AESGXGetExtendedEpidGroupIdRequest& other)
{
    if (this == &other)
        return *this;
    if (m_request != NULL)
    {
        delete m_request;
        m_request = NULL;
    }
    if (other.m_request != NULL)
        m_request = new aesm::message::Request::SGXGetExtendedEpidGroupIdRequest(*other.m_request);
    return *this;
}

bool AESGXGetExtendedEpidGroupIdRequest::check()
{
    if (m_request == NULL)
        return false;
    return m_request->IsInitialized();
}

IAEResponse* AESGXGetExtendedEpidGroupIdRequest::execute(IAESMLogic* aesmLogic)
{
    aesm_error_t result = AESM_UNEXPECTED_ERROR;
    uint32_t extended_group_id = 0;

    if (check())
    {
        result = aesmLogic->sgxGetExtendedEpidGroupId(&extended_group_id);
    }

    AESGXGetExtendedEpidGroupIdResponse * response = new AESGXGetExtendedEpidGroupIdResponse((uint32_t)result, extended_group_id);

    return response;
}
