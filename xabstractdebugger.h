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
#ifndef XABSTRACTDEBUGGER_H
#define XABSTRACTDEBUGGER_H

#include "xbinary.h"
#include "xcapstone.h"
#include "xprocess.h"
#include "xprocessdevice.h"
#include "xinfodb.h"
#include <QThread>

// TODO Attach
// TODO Detach
class XAbstractDebugger : public QObject
{
    Q_OBJECT
    
public:
    struct OPTIONS
    {
        QString sFileName;
        QString sDirectory;
        QString sArguments;
        bool bShowConsole;
        bool bBreakpointOnSystem;
        bool bBreakpointOnProgramEntryPoint;
        bool bBreakPointOnDLLMain;
        bool bBreakPointOnTLSFunction;      // For Windows TLS
    };

    enum MT
    {
        MT_UNKNOWN=0,
        MT_INFO,
        MT_WARNING,
        MT_ERROR
    };

    explicit XAbstractDebugger(QObject *pParent,XInfoDB *pXInfoDB);
    void setXInfoDB(XInfoDB *pXInfoDB);
    XInfoDB *getXInfoDB();
    virtual bool load()=0;
    virtual bool stop();
    virtual void cleanUp();
    virtual QString getArch()=0;
    virtual XBinary::MODE getMode()=0;

    void setDisasmMode(XBinary::DM disasmMode);
    void setTraceFileName(QString sTraceFileName);
    void clearTraceFile();
    void writeToTraceFile(QString sString);

    void setOptions(OPTIONS options);
    OPTIONS *getOptions();

    void _messageString(MT messageType,QString sText);

    qint64 getFunctionAddress(QString sFunctionName); // TODO move to XInfoDB
    QString getAddressSymbolString(quint64 nAddress); // TODO move to XInfoDB

    qint64 getRetAddress(XProcess::HANDLEID handleID); // TODO move to XInfoDB

    XCapstone::DISASM_STRUCT disasm(quint64 nAddress); // TODO move to XInfoDB

    bool isUserCode(quint64 nAddress); // TODO move to XInfoDB
    bool bIsSystemCode(quint64 nAddress); // TODO move to XInfoDB

    bool dumpToFile(QString sFileName);

    char *allocateAnsiStringMemory(QString sFileName); // TODO move to XInfoDB

    void setDebugActive(bool bState);
    bool isDebugActive();

    virtual bool stepIntoByHandle(X_HANDLE hThread,XInfoDB::BPI bpInfo);
    virtual bool stepIntoById(X_ID nThreadId,XInfoDB::BPI bpInfo);
    virtual bool stepOverByHandle(X_HANDLE hThread,XInfoDB::BPI bpInfo);
    virtual bool stepOverById(X_ID nThreadId,XInfoDB::BPI bpInfo);
    void wait();

public slots:
    void process();
    void testSlot(X_ID nThreadId); // TODO remove

signals:
    void messageString(XAbstractDebugger::MT messageType,QString sText);

    void eventCreateProcess(XInfoDB::PROCESS_INFO *pProcessInfo);
    void eventExitProcess(XInfoDB::EXITPROCESS_INFO *pExitProcessInfo);
    void eventCreateThread(XInfoDB::THREAD_INFO *pThreadInfo);
    void eventExitThread(XInfoDB::EXITTHREAD_INFO *pExitThreadInfo);
    void eventLoadSharedObject(XInfoDB::SHAREDOBJECT_INFO *pSharedObjectInfo);
    void eventUnloadSharedObject(XInfoDB::SHAREDOBJECT_INFO *pSharedObjectInfo);
    void eventDebugString(XInfoDB::DEBUGSTRING_INFO *pDebugString);
    void eventBreakPoint(XInfoDB::BREAKPOINT_INFO *pBreakPointInfo);
    void eventFunctionEnter(XInfoDB::FUNCTION_INFO *pFunctionInfo);
    void eventFunctionLeave(XInfoDB::FUNCTION_INFO *pFunctionInfo);

private:
    XInfoDB *g_pXInfoDB;
    OPTIONS g_options;
    csh g_handle;
    QString g_sTraceFileName;
    bool g_bIsDebugActive;
};

#endif // XABSTRACTDEBUGGER_H
