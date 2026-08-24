/* Copyright (c) 2020-2026 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef XOSXDEBUGGER_H
#define XOSXDEBUGGER_H

#include "xunixdebugger.h"

class XOSXDebugger : public XUnixDebugger {
    Q_OBJECT

public:
    explicit XOSXDebugger(QObject *pParent, XInfoDB *pXInfoDB);
    ~XOSXDebugger() override;
    virtual bool load();
    virtual bool attach();
    virtual bool stop();
    virtual void cleanUp();
    virtual QString getArch();
    virtual XBinary::MODE getMode();

protected:
    virtual STATE waitForSignal(qint64 nThreadID, qint32 nOptions) override;
    virtual bool resumeThread(X_ID nThreadId, qint32 nSignal = 0) override;
    virtual bool resumeAllThreads() override;

private:
    struct DARWIN_STATE;

    bool installExceptionPort(task_t hTask);
    void shutdownExceptionPort(bool bForwardPending);
    bool receiveException(STATE *pState);
    bool replyCurrentException(qint32 nSignal, bool bForwardException);
    bool continueAfterException(X_ID nThreadId, qint32 nSignal, bool bAllThreads);
    bool prepareSingleStepIsolation(X_ID *pStepThreadId);
    void releaseSingleStepIsolation();
    bool syncDarwinThreads(X_ID nStoppedThreadId = 0);

signals:

private:
    DARWIN_STATE *m_pDarwinState;
};

#endif  // XOSXDEBUGGER_H
