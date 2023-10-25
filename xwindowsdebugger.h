/* Copyright (c) 2020-2023 hors<horsicq@gmail.com>
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
#ifndef XWINDOWSDEBUGGER_H
#define XWINDOWSDEBUGGER_H

#include "xabstractdebugger.h"
#include "xpe.h"

class XWindowsDebugger : public XAbstractDebugger {
    Q_OBJECT

public:
    explicit XWindowsDebugger(QObject *pParent, XInfoDB *pXInfoDB);
    virtual bool run();
    virtual bool load();
    virtual bool attach();
    virtual bool stop();
    virtual void cleanUp();
    virtual QString getArch();
    virtual XBinary::MODE getMode();
    virtual bool stepIntoByHandle(X_HANDLE hThread, XInfoDB::BPI bpInfo);
    virtual bool stepOverByHandle(X_HANDLE hThread, XInfoDB::BPI bpInfo);
    virtual bool stepInto();
    virtual bool stepOver();

private:
    void _debugLoop(DWORD dwProcessID);
    void _handleBreakpoint(XADDR nAddress, X_ID nThreadID);
    quint32 on_EXCEPTION_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent);
    quint32 on_CREATE_THREAD_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent);
    quint32 on_CREATE_PROCESS_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent);
    quint32 on_EXIT_THREAD_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent);
    quint32 on_EXIT_PROCESS_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent);
    quint32 on_LOAD_DLL_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent);
    quint32 on_UNLOAD_DLL_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent);
    quint32 on_OUTPUT_DEBUG_STRING_EVENT(DEBUG_EVENT *pDebugEvent);
    quint32 on_RIP_EVENT(DEBUG_EVENT *pDebugEvent);

private:
    QMap<qint64, QString> g_mapThreadBPToRestore;
    QMap<QString, XInfoDB::FUNCTION_INFO> g_mapFunctionInfos;  // TODO move to XInfoDB
    //    QMap<qint64,XBinary::FUNCTION_ADDRESS> g_mapFunctionAddresses; // mb TODO move to Abstract
    bool g_bBreakpointSystem;
    bool g_bBreakpointEntryPoint;
};

#endif  // XWINDOWSDEBUGGER_H
