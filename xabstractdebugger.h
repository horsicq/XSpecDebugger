/* Copyright (c) 2020-2025 hors<horsicq@gmail.com>
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

#include <QThread>
#include <QTimer>

#include "xbinary.h"
#include "xcapstone.h"
#include "xinfodb.h"
#include "xoptions.h"
#include "xprocess.h"
#include "xprocessdevice.h"

// TODO Attach
// TODO Detach
class XAbstractDebugger : public QObject {
    Q_OBJECT

public:
    enum OPTIONS_TYPE {
        OPTIONS_TYPE_SHOWCONSOLE = 0,
        OPTIONS_TYPE_UNICODEENVIRONMENT,
        OPTIONS_TYPE_BREAKPONTEXCEPTIONS,
        OPTIONS_TYPE_BREAKPONTSYSTEM,
        OPTIONS_TYPE_BREAKPOINTENTRYPOINT,
        OPTIONS_TYPE_BREAKPOINTDLLMAIN,
        OPTIONS_TYPE_BREAKPOINTTLSFUNCTION,
        OPTIONS_TYPE_CHANGEPERMISSIONS,
        __OPTIONS_TYPE_SIZE
    };

    struct OPTIONS_RECORD {
        bool bValid;
        QVariant varValue;
    };

    struct OPTIONS {
        QString sFileName;
        QString sDirectory;
        QString sArguments;
        qint64 nPID;  // Attach
        OPTIONS_RECORD records[__OPTIONS_TYPE_SIZE];
        QFile::Permissions origPermissions;
    };

    enum BPSTATUS {
        BPSTATUS_UNKNOWN = 0,
        BPSTATUS_CALLBACK,
        BPSTATUS_HANDLED,
        BPSTATUS_EXIT
    };

    explicit XAbstractDebugger(QObject *pParent, XInfoDB *pXInfoDB);
    void setXInfoDB(XInfoDB *pXInfoDB);
    XInfoDB *getXInfoDB();
    virtual bool load() = 0;
    virtual bool attach() = 0;
    virtual bool run();
    virtual bool stop();
    virtual void cleanUp();
    virtual QString getArch() = 0;        // TODO move toXInfoDB
    virtual XBinary::MODE getMode() = 0;  // TODO move toXInfoDB

    void setDisasmMode(XBinary::DM disasmMode);
    void setTraceFileName(const QString &sTraceFileName);
    void clearTraceFile();
    void writeToTraceFile(const QString &sString);

    void setOptions(const OPTIONS &options);
    OPTIONS *getOptions();

    qint64 getFunctionAddress(const QString &sFunctionName);  // TODO move to XInfoDB
    QString getAddressSymbolString(quint64 nAddress);         // TODO move to XInfoDB

    qint64 getRetAddress(XProcess::HANDLEID handleID);  // TODO move to XInfoDB

    // XCapstone::DISASM_STRUCT disasm(quint64 nAddress);  // TODO move to XInfoDB

    bool isUserCode(quint64 nAddress);     // TODO move to XInfoDB
    bool bIsSystemCode(quint64 nAddress);  // TODO move to XInfoDB

    bool dumpToFile(const QString &sFileName);

    void setDebugActive(bool bState);
    bool isDebugActive();

    void setTraceActive(bool bState);
    bool isTraceActive();

    virtual bool stepIntoByHandle(X_HANDLE hThread, XInfoDB::BPI bpInfo);
    virtual bool stepIntoById(X_ID nThreadId, XInfoDB::BPI bpInfo);
    virtual bool stepOverByHandle(X_HANDLE hThread, XInfoDB::BPI bpInfo);
    virtual bool stepOverById(X_ID nThreadId, XInfoDB::BPI bpInfo);

    virtual bool stepInto();
    virtual bool stepOver();

    void wait();
    void _waitEvents();

    void _eventBreakPoint(XInfoDB::BREAKPOINT_INFO *pBreakPointInfo);

    static OPTIONS getDefaultOptions(QString sFileName);

public slots:
    void process();
    void testSlot(X_ID nThreadId);  // TODO remove

signals:
    void cannotLoadFile(const QString &sFileName);  // TODO send if cannot load file to debugger
    void errorMessage(const QString &sErrorMessage);
    void infoMessage(const QString &sInfoMessage);
    void warningMessage(const QString &sWarningMessage);

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
    bool g_bIsTraceActive;
};

#endif  // XABSTRACTDEBUGGER_H
