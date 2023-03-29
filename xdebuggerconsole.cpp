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
#include "xdebuggerconsole.h"

XDebuggerConsole::XDebuggerConsole(QObject *pParent)
    : QObject(pParent)
{
    g_pInfoDB = nullptr;
#ifdef Q_OS_WIN
    g_pThread = new QThread;
#endif
    g_pDebugger = nullptr;
    breakpointInfoLast = {};
    g_options = {};
}

void XDebuggerConsole::run(XAbstractDebugger::OPTIONS options)
{
    g_options = options;
#ifdef QT_DEBUG
    qDebug("void XDebuggerConsole::setData(XAbstractDebugger *pDebugger)");
#endif

    g_pInfoDB = new XInfoDB;
    g_pInfoDB->setDebuggerState(true);

#ifdef Q_OS_WIN
    g_pThread = new QThread;
    g_pDebugger = new XWindowsDebugger(0, g_pInfoDB);
#endif
#ifdef Q_OS_LINUX
    g_pDebugger = new XLinuxDebugger(0, g_pInfoDB);
#endif
#ifdef Q_OS_MACOS
    g_pDebugger = new XOSXDebugger(0, g_pInfoDB);
#endif

    g_pDebugger->setOptions(options);

#ifdef Q_OS_WIN
    connect(g_pThread, SIGNAL(started()), g_pDebugger, SLOT(process()));
#endif
    //    connect(pDebugger,SIGNAL(finished()),pDebugger,SLOT(deleteLater()));

    connect(g_pDebugger, SIGNAL(eventCreateProcess(XInfoDB::PROCESS_INFO *)), this, SLOT(onEventCreateProcess(XInfoDB::PROCESS_INFO *)), Qt::DirectConnection);
    connect(g_pDebugger, SIGNAL(eventBreakPoint(XInfoDB::BREAKPOINT_INFO *)), this, SLOT(onEventBreakPoint(XInfoDB::BREAKPOINT_INFO *)), Qt::DirectConnection);
    connect(g_pDebugger, SIGNAL(eventExitProcess(XInfoDB::EXITPROCESS_INFO *)), this, SLOT(onEventExitProcess(XInfoDB::EXITPROCESS_INFO *)), Qt::DirectConnection);
    connect(g_pDebugger, SIGNAL(eventCreateThread(XInfoDB::THREAD_INFO *)), this, SLOT(onEventCreateThread(XInfoDB::THREAD_INFO *)), Qt::DirectConnection);
    connect(g_pDebugger, SIGNAL(eventExitThread(XInfoDB::EXITTHREAD_INFO *)), this, SLOT(onEventExitThread(XInfoDB::EXITTHREAD_INFO *)), Qt::DirectConnection);
    connect(g_pDebugger, SIGNAL(eventLoadSharedObject(XInfoDB::SHAREDOBJECT_INFO *)), this, SLOT(onEventLoadSharedObject(XInfoDB::SHAREDOBJECT_INFO *)),
            Qt::DirectConnection);
    connect(g_pDebugger, SIGNAL(eventUnloadSharedObject(XInfoDB::SHAREDOBJECT_INFO *)), this, SLOT(onEventUnloadSharedObject(XInfoDB::SHAREDOBJECT_INFO *)),
            Qt::DirectConnection);

#ifdef Q_OS_WIN
    g_pDebugger->moveToThread(g_pThread);
    g_pThread->start();
#endif
#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
    g_pDebugger->process();
#endif

    QTextStream streamIn(stdin);

    while (true) {
        QString sCommand;
        sCommand = "step";
        sCommand = streamIn.readLine(256);

        if (sCommand == "step") {
    #ifdef Q_OS_WIN
            g_pDebugger->stepIntoByHandle(breakpointInfoLast.hThread, XInfoDB::BPI_STEPINTO);
    #endif
    #ifdef Q_OS_LINUX
            qDebug("STEP!!!STEP");
            g_pDebugger->stepIntoById(breakpointInfoLast.nThreadID, XInfoDB::BPI_STEPINTO);
    #endif
        } else if (sCommand == "quit") {
            qDebug("QUIT");
            break;
        }

        {
            QTimer timer;
            timer.setSingleShot(true);

            QEventLoop loop;
            connect(&timer, SIGNAL(timeout()), &loop, SLOT(quit()));
            timer.start(500);  // use miliseconds
            loop.exec();
        }
    }

    delete g_pInfoDB;
#ifdef Q_OS_WIN
    delete g_pThread;
#endif
    delete g_pDebugger;
}

void XDebuggerConsole::onEventCreateProcess(XInfoDB::PROCESS_INFO *pProcessInfo)
{
    qDebug("void XDebuggerConsole::onEventCreateProcess(XInfoDB::PROCESS_INFO *pProcessInfo)");
}

void XDebuggerConsole::onEventExitProcess(XInfoDB::EXITPROCESS_INFO *pExitProcessInfo)
{
    qDebug("void XDebuggerConsole::onEventExitProcess(XInfoDB::EXITPROCESS_INFO *pExitProcessInfo)");
}

void XDebuggerConsole::onEventCreateThread(XInfoDB::THREAD_INFO *pThreadInfo)
{
    qDebug("void XDebuggerConsole::onEventCreateThread(XInfoDB::THREAD_INFO *pThreadInfo)");
}

void XDebuggerConsole::onEventExitThread(XInfoDB::EXITTHREAD_INFO *pExitThreadInfo)
{
    qDebug("void XDebuggerConsole::onEventExitThread(XInfoDB::EXITTHREAD_INFO *pExitThreadInfo)");
}

void XDebuggerConsole::onEventLoadSharedObject(XInfoDB::SHAREDOBJECT_INFO *pSharedObjectInfo)
{
    qDebug("void XDebuggerConsole::onEventLoadSharedObject(XInfoDB::SHAREDOBJECT_INFO *pSharedObjectInfo)");
}

void XDebuggerConsole::onEventUnloadSharedObject(XInfoDB::SHAREDOBJECT_INFO *pSharedObjectInfo)
{
    qDebug("void XDebuggerConsole::onEventUnloadSharedObject(XInfoDB::SHAREDOBJECT_INFO *pSharedObjectInfo)");
}

void XDebuggerConsole::onEventDebugString(XInfoDB::DEBUGSTRING_INFO *pDebugString)
{
    qDebug("void XDebuggerConsole::onEventDebugString(XInfoDB::DEBUGSTRING_INFO *pDebugString)");
}

void XDebuggerConsole::onEventBreakPoint(XInfoDB::BREAKPOINT_INFO *pBreakPointInfo)
{
    breakpointInfoLast = *pBreakPointInfo;
    qDebug("void XDebuggerConsole::onEventBreakPoint(XInfoDB::BREAKPOINT_INFO *pBreakPointInfo)");
}

void XDebuggerConsole::onEventFunctionEnter(XInfoDB::FUNCTION_INFO *pFunctionInfo)
{
    qDebug("void XDebuggerConsole::onEventFunctionEnter(XInfoDB::FUNCTION_INFO *pFunctionInfo)");
}

void XDebuggerConsole::onEventFunctionLeave(XInfoDB::FUNCTION_INFO *pFunctionInfo)
{
    qDebug("void XDebuggerConsole::onEventFunctionLeave(XInfoDB::FUNCTION_INFO *pFunctionInfo)");
}
