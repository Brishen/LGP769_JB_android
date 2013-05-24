/*
 * Copyright (C) 2011 Google Inc. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS'' AND ANY
 *  EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 *  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 *  ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef ScriptedAnimationController_h
#define ScriptedAnimationController_h

#if ENABLE(REQUEST_ANIMATION_FRAME)
#include "DOMTimeStamp.h"
#if USE(REQUEST_ANIMATION_FRAME_TIMER)
#include "Timer.h"
#endif
#include <wtf/RefCounted.h>
#include <wtf/RefPtr.h>
#include <wtf/Vector.h>

namespace WebCore {

class Document;
class RequestAnimationFrameCallback;

class ScriptedAnimationController : public RefCounted<ScriptedAnimationController>
{
public:
    // CAPPFIX_WEB_HTML5: Request Animation Frame
    static PassRefPtr<ScriptedAnimationController> create(Document* document)
    {
        return adoptRef(new ScriptedAnimationController(document));
    }
    ~ScriptedAnimationController();
    void clearDocumentPointer() { m_document = 0; }
    // CAPPFIX_WEB_HTML5_END

    typedef int CallbackId;

    // CAPPFIX_WEB_HTML5: Request Animation Frame
    CallbackId registerCallback(PassRefPtr<RequestAnimationFrameCallback>);
    // CAPPFIX_WEB_HTML5_END
    void cancelCallback(CallbackId);
    void serviceScriptedAnimations(DOMTimeStamp);

    void suspend();
    void resume();

private:
    ScriptedAnimationController(Document*);
    typedef Vector<RefPtr<RequestAnimationFrameCallback> > CallbackList;
    CallbackList m_callbacks;

    Document* m_document;
    CallbackId m_nextCallbackId;
    int m_suspendCount;

    // CAPPFIX_WEB_HTML5: Request Animation Frame
    void scheduleAnimation();

#if USE(REQUEST_ANIMATION_FRAME_TIMER)
    void animationTimerFired(Timer<ScriptedAnimationController>*);
    Timer<ScriptedAnimationController> m_animationTimer;
    double m_lastAnimationFrameTime;
#endif
    // CAPPFIX_WEB_HTML5_END

};

}

#endif // ENABLE(REQUEST_ANIMATION_FRAME)

#endif // ScriptedAnimationController_h

