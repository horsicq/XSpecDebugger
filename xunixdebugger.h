/* Copyright (c) 2020-2022 hors<horsicq@gmail.com>
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
#ifndef XUNIXDEBUGGER_H
#define XUNIXDEBUGGER_H

#include "xabstractdebugger.h"

class XUnixDebugger : public XAbstractDebugger
{
    Q_OBJECT

public:
    struct EXECUTEPROCESS
    {
        QString sStatus;
    };

    enum DEBUGGER_STATUS
    {
        DEBUGGER_STATUS_UNKNOWN=0,
        DEBUGGER_STATUS_SIGNAL,
        DEBUGGER_STATUS_STOP,
        DEBUGGER_STATUS_EXIT
    };

    struct STATE
    {
        quint32 nCode;
        DEBUGGER_STATUS debuggerStatus;
    };

    explicit XUnixDebugger(QObject *pParent=nullptr);

    virtual bool stop();
    virtual void cleanUp();

    EXECUTEPROCESS executeProcess(QString sFileName,QString sDirectory); // TODO args, TODO sDirectory
    void setPtraceOptions(qint64 nThreadID);
    STATE waitForSignal(qint64 nProcessID);
    void continueThread(qint64 nThreadID); // TODO rename to resumrThread
    static bool resumeThread(XProcess::HANDLEID handleID);
    virtual REGISTERS getRegisters(XProcess::HANDLEID handleID, REG_OPTIONS regOptions);
    virtual bool _setStep(XProcess::HANDLEID handleID);
};

#endif // XUNIXDEBUGGER_H
