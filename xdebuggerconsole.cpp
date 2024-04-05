/* Copyright (c) 2020-2024 hors<horsicq@gmail.com>
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

XDebuggerConsole::XDebuggerConsole(QObject *pParent) : QObject(pParent)
{
    g_pInfoDB = nullptr;
#ifdef Q_OS_WIN
    g_pThread = new QThread;
#endif
    g_pDebugger = nullptr;
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
        sCommand = streamIn.readLine(256);

        COMMAND_RESULT commandResult;

        commandControl(&commandResult, sCommand, g_pDebugger);

#ifndef QT_GUI_LIB
        qint32 nNumberOfTexts = commandResult.listTexts.count();
        qint32 nNumberOfErrors = commandResult.listErrors.count();

        for (qint32 i = 0; i < nNumberOfTexts; i++) {
            printf("%s\n", commandResult.listTexts.at(i).toUtf8().data());
        }

        for (qint32 i = 0; i < nNumberOfErrors; i++) {
            printf("%s\n", commandResult.listErrors.at(i).toUtf8().data());
        }
#endif
        g_pDebugger->_waitEvents();

        if (!g_pDebugger->isDebugActive()) {
            break;
        }
    }

    delete g_pInfoDB;
#ifdef Q_OS_WIN
    delete g_pThread;
#endif
    delete g_pDebugger;
}

void XDebuggerConsole::commandControl(COMMAND_RESULT *pCommandResult, const QString &sCommand, XAbstractDebugger *pDebugger)
{
    QString sArg[3];

    for (qint32 i = 0; i < 3; i++) {
        sArg[i] = sCommand.section(" ", i, i);
    }

    XInfoDB *pInfoDB = nullptr;

    if (pDebugger) {
        pInfoDB = pDebugger->getXInfoDB();
    }

    pCommandResult->listTexts.append("CMD: " + sCommand);

    if (sArg[0] == "help") {
        pCommandResult->listTexts.append("step");
        pCommandResult->listTexts.append("disasm");
        pCommandResult->listTexts.append("regs");
        pCommandResult->listTexts.append("run");
        pCommandResult->listTexts.append("modules");
        pCommandResult->listTexts.append("regions");
        pCommandResult->listTexts.append("threads");
        pCommandResult->listTexts.append("breakpoints");
        pCommandResult->listTexts.append("bpx <ADDRESS>");
        pCommandResult->listTexts.append("quit");
    } else if (sArg[0] == "step") {
        qint32 nCount = _getNumber(pCommandResult, sArg[1], 1);

        if (nCount == 1) {
            pDebugger->stepInto();
            pDebugger->_waitEvents();
        } else if (nCount > 1) {
            for (qint32 i = 0; i < nCount; i++) {
                commandControl(pCommandResult, sArg[0], pDebugger);
            }
        }
    } else if (sArg[0] == "disasm") {
        XADDR nDisasmAddress = _getAddress(pCommandResult, sArg[1], -1);
        qint32 nCount = _getNumber(pCommandResult, sArg[2], 10);

        if (nDisasmAddress == (XADDR)-1) {
#ifdef Q_PROCESSOR_X86_32
            nDisasmAddress = pInfoDB->getCurrentRegCache(XInfoDB::XREG_EIP).var.v_uint32;
#endif
#ifdef Q_PROCESSOR_X86_64
            nDisasmAddress = pInfoDB->getCurrentRegCache(XInfoDB::XREG_RIP).var.v_uint64;
#endif
        }

        for (qint32 i = 0; i < nCount; i++) {
            XCapstone::DISASM_RESULT disasmResult = pInfoDB->disasm(nDisasmAddress);

            if (disasmResult.bIsValid) {
                QString sString = QString("%1: %2 %3").arg(XBinary::valueToHexEx(nDisasmAddress), disasmResult.sMnemonic, disasmResult.sString);
                pCommandResult->listTexts.append(sString);
            } else {
                break;
            }

            nDisasmAddress += disasmResult.nSize;
        }
    } else if (sArg[0] == "regs") {
        QList<XInfoDB::REG_RECORD> listRegs = pInfoDB->getCurrentRegs();

        qint32 nNumberOfRecords = listRegs.count();

        for (qint32 i = 0; i < nNumberOfRecords; i++) {
            pCommandResult->listTexts.append(QString("%1: ").arg(XInfoDB::regIdToString(listRegs.at(i).reg)) + XBinary::xVariantToHex(listRegs.at(i).value));
        }
    } else if (sArg[0] == "run") {
        pDebugger->run();
    } else if (sArg[0] == "modules") {
        QList<XProcess::MODULE> *pModulesList = pInfoDB->getCurrentModulesList();

        qint32 nNumberOfModules = pModulesList->count();

        for (qint32 i = 0; i < nNumberOfModules; i++) {
            printf("%llx %llx %s %s\n", pModulesList->at(i).nAddress, pModulesList->at(i).nSize, pModulesList->at(i).sName.toUtf8().data(),
                   pModulesList->at(i).sFileName.toUtf8().data());
        }
    } else if (sArg[0] == "regions") {
        QList<XProcess::MEMORY_REGION> *pRegionsList = pInfoDB->getCurrentMemoryRegionsList();

        qint32 nNumberOfRegions = pRegionsList->count();

        for (qint32 i = 0; i < nNumberOfRegions; i++) {
            printf("%llx %llx\n", pRegionsList->at(i).nAddress, pRegionsList->at(i).nSize);
        }
    } else if (sArg[0] == "threads") {
        QList<XProcess::THREAD_INFO> *pThreadsList = pInfoDB->getCurrentThreadsList();

        qint32 nNumberOfThreads = pThreadsList->count();

        for (qint32 i = 0; i < nNumberOfThreads; i++) {
            printf("%lld\n", pThreadsList->at(i).nID);
        }
    } else if (sArg[0] == "breakpoints") {
        QList<XInfoDB::BREAKPOINT> *pBreakPoints = pInfoDB->getBreakpoints();

        qint32 nNumberOfBreakPoints = pBreakPoints->count();

        for (qint32 i = 0; i < nNumberOfBreakPoints; i++) {
            QString sString = QString("%1 %2").arg(XBinary::valueToHexEx(pBreakPoints->at(i).nAddress), XBinary::valueToHexEx(pBreakPoints->at(i).nDataSize));
            pCommandResult->listTexts.append(sString);
        }

    } else if (sArg[0] == "bpx") {
        XADDR nAddress = sCommand.section(" ", 1, 1).toULongLong(0, 16);
        QString sString = "BPX: " + XBinary::valueToHexEx(nAddress);

        XInfoDB::BREAKPOINT bp = {};
        bp.nAddress = nAddress;

        if (pInfoDB->addBreakPoint(bp)) {
            pCommandResult->listTexts.append(sString);
        } else {
            pCommandResult->listTexts.append(tr("Cannot set") + sString);
        }
    } else if (sArg[0] == "quit") {
        printf("STOP\n");
        pDebugger->stop();
        // break;
    } else {
        QString sError = QString("%1: %2").arg(tr("Unknown command"), sCommand);
        pCommandResult->listErrors.append(sError);
    }
}

XADDR XDebuggerConsole::_getAddress(COMMAND_RESULT *pCommandResult, const QString &sString, XADDR nDefaultValue)
{
    XADDR nResult = nDefaultValue;

    if (sString != "") {
        bool bOK = false;
        nResult = sString.toULongLong(&bOK, 16);

        if (!bOK) {
            nResult = nDefaultValue;
            QString sError = QString("%1: %2").arg(tr("Invalid address"), sString);
            pCommandResult->listErrors.append(sError);
        }
    }

    return nResult;
}

qint32 XDebuggerConsole::_getNumber(COMMAND_RESULT *pCommandResult, const QString &sString, qint32 nDefaultValue)
{
    qint32 nResult = nDefaultValue;

    if (sString != "") {
        bool bOK = false;
        nResult = sString.toULongLong(&bOK, 10);

        if (!bOK) {
            nResult = nDefaultValue;
            QString sError = QString("%1: %2").arg(tr("Invalid number"), sString);
            pCommandResult->listErrors.append(sError);
        }
    }

    return nResult;
}

void XDebuggerConsole::onEventCreateProcess(XInfoDB::PROCESS_INFO *pProcessInfo)
{
    qDebug("void XDebuggerConsole::onEventCreateProcess(XInfoDB::PROCESS_INFO *pProcessInfo)");
    qDebug("ProcessID: %lld", pProcessInfo->nProcessID);
}

void XDebuggerConsole::onEventExitProcess(XInfoDB::EXITPROCESS_INFO *pExitProcessInfo)
{
    Q_UNUSED(pExitProcessInfo)
    qDebug("void XDebuggerConsole::onEventExitProcess(XInfoDB::EXITPROCESS_INFO *pExitProcessInfo)");
}

void XDebuggerConsole::onEventCreateThread(XInfoDB::THREAD_INFO *pThreadInfo)
{
    Q_UNUSED(pThreadInfo)
    qDebug("void XDebuggerConsole::onEventCreateThread(XInfoDB::THREAD_INFO *pThreadInfo)");
}

void XDebuggerConsole::onEventExitThread(XInfoDB::EXITTHREAD_INFO *pExitThreadInfo)
{
    Q_UNUSED(pExitThreadInfo)
    qDebug("void XDebuggerConsole::onEventExitThread(XInfoDB::EXITTHREAD_INFO *pExitThreadInfo)");
}

void XDebuggerConsole::onEventLoadSharedObject(XInfoDB::SHAREDOBJECT_INFO *pSharedObjectInfo)
{
    Q_UNUSED(pSharedObjectInfo)
    qDebug("void XDebuggerConsole::onEventLoadSharedObject(XInfoDB::SHAREDOBJECT_INFO *pSharedObjectInfo)");
}

void XDebuggerConsole::onEventUnloadSharedObject(XInfoDB::SHAREDOBJECT_INFO *pSharedObjectInfo)
{
    Q_UNUSED(pSharedObjectInfo)
    qDebug("void XDebuggerConsole::onEventUnloadSharedObject(XInfoDB::SHAREDOBJECT_INFO *pSharedObjectInfo)");
}

void XDebuggerConsole::onEventDebugString(XInfoDB::DEBUGSTRING_INFO *pDebugString)
{
    Q_UNUSED(pDebugString)
    qDebug("void XDebuggerConsole::onEventDebugString(XInfoDB::DEBUGSTRING_INFO *pDebugString)");
}

void XDebuggerConsole::onEventBreakPoint(XInfoDB::BREAKPOINT_INFO *pBreakPointInfo)
{
    qDebug("void XDebuggerConsole::onEventBreakPoint(XInfoDB::BREAKPOINT_INFO *pBreakPointInfo)");

    XInfoDB::XREG_OPTIONS regOptions = {};
    regOptions.bIP = true;
    regOptions.bDebug = true;
    regOptions.bFlags = true;
    regOptions.bFloat = true;
    regOptions.bGeneral = true;
    regOptions.bSegments = true;
    regOptions.bXMM = true;
    regOptions.bYMM = true;

    g_pInfoDB->updateModulesList();
    g_pInfoDB->updateMemoryRegionsList();
    g_pInfoDB->updateThreadsList();

#ifdef Q_OS_WIN
    g_pInfoDB->updateRegsByHandle(pBreakPointInfo->hThread, regOptions);
#endif
#ifdef Q_OS_LINUX
    g_pInfoDB->updateRegsById(pBreakPointInfo->nThreadID, regOptions);
#endif
}

void XDebuggerConsole::onEventFunctionEnter(XInfoDB::FUNCTION_INFO *pFunctionInfo)
{
    Q_UNUSED(pFunctionInfo)
    qDebug("void XDebuggerConsole::onEventFunctionEnter(XInfoDB::FUNCTION_INFO *pFunctionInfo)");
}

void XDebuggerConsole::onEventFunctionLeave(XInfoDB::FUNCTION_INFO *pFunctionInfo)
{
    Q_UNUSED(pFunctionInfo)
    qDebug("void XDebuggerConsole::onEventFunctionLeave(XInfoDB::FUNCTION_INFO *pFunctionInfo)");
}
