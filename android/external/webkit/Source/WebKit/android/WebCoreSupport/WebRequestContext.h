/*
 * Copyright 2010, The Android Open Source Project
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef WebRequestContext_h
#define WebRequestContext_h

#include "ChromiumIncludes.h"
#include "PlatformString.h"

#include <wtf/ThreadingPrimitives.h>

namespace android {

// This class is generally not threadsafe.
class WebRequestContext : public net::URLRequestContext {
public:
    // URLRequestContext overrides.
    virtual const std::string& GetUserAgent(const GURL&) const;
    // CAPP_WEB_WAP_PROFILE: Support UserAgentProfile
    virtual const std::string& GetUAProfile() const;
    // CAPP_WEB_WAP_PROFILE_END
    virtual const std::string& accept_language() const;

    WebRequestContext(bool isPrivateBrowsing);

    // These methods are threadsafe.
    void setUserAgent(const WTF::String&);
    // CAPP_WEB_WAP_PROFILE: Support UserAgentProfile
    void setUAProfile(const WTF::String&);
    // CAPP_WEB_WAP_PROFILE_END
    void setCacheMode(int);
    int getCacheMode();
    static void setAcceptLanguage(const WTF::String&);
    static const WTF::String& acceptLanguage();
    // CAPP_WEB_ADDITIONALHEADERS: Support additional operator's header
    static void setAdditionalHeaders(const WTF::String&);
    virtual const std::string& getAdditionalHeaders() const;
    // CAPP_WEB_ADDITIONALHEADERS_END

private:
    WebRequestContext();
    ~WebRequestContext();

    std::string m_userAgent;
    // CAPP_WEB_WAP_PROFILE: Support UserAgentProfile
    std::string m_uaProfile;
    // CAPP_WEB_WAP_PROFILE_END
    int m_cacheMode;
    mutable WTF::Mutex m_userAgentMutex;
    // CAPP_WEB_WAP_PROFILE: Support UserAgentProfile
    mutable WTF::Mutex m_uaProfileMutex;
    // CAPP_WEB_WAP_PROFILE_END
    bool m_isPrivateBrowsing;
};

} // namespace android

#endif
