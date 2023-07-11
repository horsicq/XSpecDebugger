#ifndef XDEBUGGERCONSOLE_H
#define XDEBUGGERCONSOLE_H

#include <QObject>
#include <QTimer>
#ifdef Q_OS_WIN
#include "xwindowsdebugger.h"
#endif
#ifdef Q_OS_LINUX
#include "xlinuxdebugger.h"
#endif
#ifdef Q_OS_OSX
#include "xosxdebugger.h"
#endif

class XDebuggerConsole : public QObject {
    Q_OBJECT
public:
    explicit XDebuggerConsole(QObject *pParent = nullptr);

    void run(XAbstractDebugger::OPTIONS options);

    struct COMMAND_RESULT {
        QList<QString> listTexts;
        QList<QString> listErrors;
    };

    static void commandControl(COMMAND_RESULT *pCommandResult, const QString &sCommand, XAbstractDebugger *pDebugger);  // TODO PDStruct
    // TODO History TODO init for init commandControl

private:
    static XADDR _getAddress(COMMAND_RESULT *pCommandResult, const QString &sString, XADDR nDefaultValue);
    static qint32 _getNumber(COMMAND_RESULT *pCommandResult, const QString &sString, qint32 nDefaultValue);

private slots:
    void onEventCreateProcess(XInfoDB::PROCESS_INFO *pProcessInfo);
    void onEventExitProcess(XInfoDB::EXITPROCESS_INFO *pExitProcessInfo);
    void onEventCreateThread(XInfoDB::THREAD_INFO *pThreadInfo);
    void onEventExitThread(XInfoDB::EXITTHREAD_INFO *pExitThreadInfo);
    void onEventLoadSharedObject(XInfoDB::SHAREDOBJECT_INFO *pSharedObjectInfo);
    void onEventUnloadSharedObject(XInfoDB::SHAREDOBJECT_INFO *pSharedObjectInfo);
    void onEventDebugString(XInfoDB::DEBUGSTRING_INFO *pDebugString);
    void onEventBreakPoint(XInfoDB::BREAKPOINT_INFO *pBreakPointInfo);
    void onEventFunctionEnter(XInfoDB::FUNCTION_INFO *pFunctionInfo);
    void onEventFunctionLeave(XInfoDB::FUNCTION_INFO *pFunctionInfo);

private:
    XInfoDB *g_pInfoDB;
#ifdef Q_OS_WIN
    QThread *g_pThread;
#endif
    XAbstractDebugger *g_pDebugger;
    XAbstractDebugger::OPTIONS g_options;
};

#endif  // XDEBUGGERCONSOLE_H
