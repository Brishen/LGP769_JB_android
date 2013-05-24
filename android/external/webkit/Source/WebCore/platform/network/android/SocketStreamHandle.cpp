/*
 * Copyright (C) 2009 Brent Fulgham.  All rights reserved.
 * Copyright (C) 2009 Google Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
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
 */

#include "config.h"

#include "SocketStreamHandle.h"

#include "Logging.h"
#include "NotImplemented.h"
#include "SocketStreamHandleClient.h"

#include "WebSocketBridge.h"

namespace WebCore {

SocketStreamHandle::SocketStreamHandle(const KURL& url, SocketStreamHandleClient* client)
    : SocketStreamHandleBase(url, client)
    , m_url(url)
{
    LOG(Network, "SocketStreamHandle::SocketStreamHandle %p", this);
    bool isSecure = m_url.protocolIs("wss");
    int port = m_url.hasPort() ? m_url.port() : (isSecure ? 443 : 80);

    String httpProtocol;
    if (isSecure)
        httpProtocol = "https://";
    else
        httpProtocol = "http://";

    String uri = httpProtocol + m_url.host() + ":" + String::number(port);
    m_webSocketBridge = new WebSocketBridge(this, uri);
}

SocketStreamHandle::~SocketStreamHandle()
{
    LOG(Network, "SocketStreamHandle::~SocketStreamHandle %p", this);
    if (m_webSocketBridge) {
        delete m_webSocketBridge;
    }
}

void SocketStreamHandle::socketConnectedCallback()
{
    LOG(Network, "SocketStreamHandle::socketConnected %p", this);
    if (client()) {
        m_state = SocketStreamHandleBase::Open;
        client()->didOpen(this);
    }
}

void SocketStreamHandle::socketClosedCallback()
{
    LOG(Network, "SocketStreamHandle::socketClosedCallback %p", this);
    if (client()) {
        client()->didClose(this);
    }
}

void SocketStreamHandle::socketReadyReadCallback(const char* data, int length)
{
    LOG(Network, "SocketStreamHandle::socketReadyRead %p", this);
    if (client()) {
        client()->didReceiveData(this, data, length);
    }
}

void SocketStreamHandle::socketErrorCallback()
{
    LOG(Network, "SocketStreamHandle::socketErrorCallback %p", this);
    if (client()) {
        client()->didClose(this);
    }
}

int SocketStreamHandle::platformSend(const char* data, int len)
{
    LOG(Network, "SocketStreamHandle::platformSend %p", this);
    m_webSocketBridge->sendWebSocket(data, len);
    return len;
}

void SocketStreamHandle::platformClose()
{
    LOG(Network, "SocketStreamHandle %p platformClose", this);
    m_webSocketBridge->closeWebSocket();
}

void SocketStreamHandle::didReceiveAuthenticationChallenge(const AuthenticationChallenge&)
{
    notImplemented();
}

void SocketStreamHandle::receivedCredential(const AuthenticationChallenge&, const Credential&)
{
    notImplemented();
}

void SocketStreamHandle::receivedRequestToContinueWithoutCredential(const AuthenticationChallenge&)
{
    notImplemented();
}

void SocketStreamHandle::receivedCancellation(const AuthenticationChallenge&)
{
    notImplemented();
}
}  // namespace WebCore

