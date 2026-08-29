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
#include "xdebuggerconsole.h"

#include <QFile>
#include <QProcess>

#include <limits>

XDebuggerConsole::XDebuggerConsole(QObject *pParent) : QObject(pParent)
{
    g_pInfoDB = nullptr;
#ifdef Q_OS_WIN
    g_pThread = nullptr;
    g_nWorkerFinished.storeRelaxed(0);
#endif
    g_pDebugger = nullptr;
    g_nTargetStarted.storeRelaxed(0);
    g_options = {};
}

bool XDebuggerConsole::run(XAbstractDebugger::OPTIONS options)
{
    g_options = options;
    g_nTargetStarted.storeRelaxed(0);
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
    connect(g_pThread, &QThread::started, this, [this]() { g_nWorkerFinished.storeRelease(1); }, Qt::DirectConnection);
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

        if (sCommand.isNull()) {
#ifdef Q_OS_WIN
            // Closed redirected input can arrive before CreateProcessW has completed.
            // Wait until the target is active or the worker reports a failed/finished load.
            while ((!g_pDebugger->isDebugActive()) && (!g_nWorkerFinished.loadAcquire())) {
                g_pDebugger->_waitEvents();
            }
#endif
            if (g_pDebugger->isDebugActive()) {
                g_nTargetStarted.storeRelease(1);
                g_pDebugger->stop();
            }

            break;
        }

        COMMAND_RESULT commandResult;

        commandControl(&commandResult, sCommand, g_pDebugger);

        qint32 nNumberOfTexts = commandResult.listTexts.count();
        qint32 nNumberOfErrors = commandResult.listErrors.count();

        for (qint32 i = 0; i < nNumberOfTexts; i++) {
            QByteArray baText = commandResult.listTexts.at(i).toUtf8();
            fprintf(stdout, "%s\n", baText.constData());
        }

        for (qint32 i = 0; i < nNumberOfErrors; i++) {
            QByteArray baError = commandResult.listErrors.at(i).toUtf8();
            fprintf(stderr, "%s\n", baError.constData());
        }
        fflush(stdout);
        fflush(stderr);
        g_pDebugger->_waitEvents();

        if (!g_pDebugger->isDebugActive()) {
            break;
        }
    }

#ifdef Q_OS_WIN
    g_pThread->quit();
    g_pThread->wait();
#endif

    g_pDebugger->cleanUp();
    delete g_pDebugger;
    g_pDebugger = nullptr;

#ifdef Q_OS_WIN
    delete g_pThread;
    g_pThread = nullptr;
#endif

    delete g_pInfoDB;
    g_pInfoDB = nullptr;

    return g_nTargetStarted.loadAcquire() != 0;
}

void XDebuggerConsole::commandControl(COMMAND_RESULT *pCommandResult, const QString &sCommand, XAbstractDebugger *pDebugger)
{
    if (!pCommandResult) {
        return;
    }

    const QString sTrimmedCommand = sCommand.trimmed();
    const QStringList listArguments = QProcess::splitCommand(sTrimmedCommand);

    if (listArguments.isEmpty()) {
        return;
    }

    const QString sCommandName = listArguments.constFirst().toLower();

    XInfoDB *pInfoDB = nullptr;

    if (pDebugger) {
        pInfoDB = pDebugger->getXInfoDB();
    }

    pCommandResult->listTexts.append("CMD: " + sTrimmedCommand);

    if (sCommandName == "help") {
        pCommandResult->listTexts.append("step");
        pCommandResult->listTexts.append("disasm");
        pCommandResult->listTexts.append("regs");
        pCommandResult->listTexts.append("run");
        pCommandResult->listTexts.append("modules");
        pCommandResult->listTexts.append("regions");
        pCommandResult->listTexts.append("threads");
        pCommandResult->listTexts.append("breakpoints");
        pCommandResult->listTexts.append("bpx <ADDRESS>");
        pCommandResult->listTexts.append("dump [ADDRESS] [SIZE] [FILENAME]");
        pCommandResult->listTexts.append("quit");
    } else if ((!pDebugger) || (!pInfoDB)) {
        pCommandResult->listErrors.append(tr("No active debugger target"));
    } else if (sCommandName == "step") {
        if (listArguments.count() > 2) {
            pCommandResult->listErrors.append(tr("Usage: step [COUNT]"));
            return;
        }

        qint32 nCount = 1;
        if ((listArguments.count() == 2) && (!_getNumber(pCommandResult, listArguments.at(1), &nCount))) {
            return;
        }

        if ((nCount < 1) || (nCount > 100000)) {
            pCommandResult->listErrors.append(tr("Step count must be between 1 and 100000"));
            return;
        }

        if (nCount == 1) {
            pDebugger->stepInto();
            pDebugger->_waitEvents();
        } else if (nCount > 1) {
            for (qint32 i = 0; i < nCount; i++) {
                commandControl(pCommandResult, sCommandName, pDebugger);
            }
        }
    } else if (sCommandName == "disasm") {
        if (listArguments.count() > 3) {
            pCommandResult->listErrors.append(tr("Usage: disasm [ADDRESS] [COUNT]"));
            return;
        }

        XADDR nDisasmAddress = (XADDR)-1;
        qint32 nCount = 10;

        if ((listArguments.count() >= 2) && (!_getAddress(pCommandResult, listArguments.at(1), &nDisasmAddress))) {
            return;
        }
        if ((listArguments.count() == 3) && (!_getNumber(pCommandResult, listArguments.at(2), &nCount))) {
            return;
        }
        if ((nCount < 1) || (nCount > 100000)) {
            pCommandResult->listErrors.append(tr("Disassembly count must be between 1 and 100000"));
            return;
        }

        if (nDisasmAddress == (XADDR)-1) {
            nDisasmAddress = pInfoDB->getCurrentInstructionPointerCache();
        }

        for (qint32 i = 0; i < nCount; i++) {
            // XCapstone::DISASM_RESULT disasmResult = pInfoDB->disasm(nDisasmAddress);

            // if (disasmResult.bIsValid) {
            //     QString sString = QString("%1: %2 %3").arg(XBinary::valueToHexEx(nDisasmAddress), disasmResult.sMnemonic, disasmResult.sString);
            //     pCommandResult->listTexts.append(sString);
            // } else {
            //     break;
            // }

            // nDisasmAddress += disasmResult.nSize;
        }
    } else if (sCommandName == "regs") {
        QList<XInfoDB::REG_RECORD> listRegs = pInfoDB->getCurrentRegs();

        qint32 nNumberOfRecords = listRegs.count();

        for (qint32 i = 0; i < nNumberOfRecords; i++) {
            pCommandResult->listTexts.append(QString("%1: ").arg(XInfoDB::regIdToString(listRegs.at(i).reg)) + XBinary::xVariantToHex(listRegs.at(i).value));
        }
    } else if (sCommandName == "run") {
        pDebugger->run();
    } else if (sCommandName == "modules") {
        QList<XProcess::MODULE> *pModulesList = pInfoDB->getCurrentModulesList();

        qint32 nNumberOfModules = pModulesList->count();

        for (qint32 i = 0; i < nNumberOfModules; i++) {
            printf("%llx %llx %s %s\n", pModulesList->at(i).nAddress, pModulesList->at(i).nSize, pModulesList->at(i).sName.toUtf8().data(),
                   pModulesList->at(i).sFileName.toUtf8().data());
        }
    } else if (sCommandName == "regions") {
        QList<XProcess::MEMORY_REGION> *pRegionsList = pInfoDB->getCurrentMemoryRegionsList();

        qint32 nNumberOfRegions = pRegionsList->count();

        for (qint32 i = 0; i < nNumberOfRegions; i++) {
            printf("%llx %llx\n", pRegionsList->at(i).nAddress, pRegionsList->at(i).nSize);
        }
    } else if (sCommandName == "threads") {
        QList<XProcess::THREAD_INFO> *pThreadsList = pInfoDB->getCurrentThreadsList();

        qint32 nNumberOfThreads = pThreadsList->count();

        for (qint32 i = 0; i < nNumberOfThreads; i++) {
            printf("%lld\n", pThreadsList->at(i).nID);
        }
    } else if (sCommandName == "breakpoints") {
        QList<XInfoDB::BREAKPOINT> *pBreakPoints = pInfoDB->getBreakpoints();

        qint32 nNumberOfBreakPoints = pBreakPoints->count();

        for (qint32 i = 0; i < nNumberOfBreakPoints; i++) {
            QString sString = QString("%1 %2").arg(XBinary::valueToHexEx(pBreakPoints->at(i).nAddress), XBinary::valueToHexEx(pBreakPoints->at(i).nDataSize));
            pCommandResult->listTexts.append(sString);
        }

    } else if (sCommandName == "bpx") {
        if (listArguments.count() != 2) {
            pCommandResult->listErrors.append(tr("Usage: bpx <ADDRESS>"));
            return;
        }

        XADDR nAddress = 0;
        if (!_getAddress(pCommandResult, listArguments.at(1), &nAddress)) {
            return;
        }

        QString sString = "BPX: " + XBinary::valueToHexEx(nAddress);

        XInfoDB::BREAKPOINT bp = {};
        bp.nAddress = nAddress;

        if (pInfoDB->addBreakPoint(bp)) {
            pCommandResult->listTexts.append(sString);
        } else {
            pCommandResult->listTexts.append(tr("Cannot set") + sString);
        }
    } else if (sCommandName == "dump") {
        // dump [ADDRESS] [SIZE] [FILENAME] - write a live process-memory region to a file.
        // With no arguments, dumps the whole main-module image.
        static const qint32 N_MAX_DUMP_SIZE = 64 * 1024 * 1024;

        if (listArguments.count() > 4) {
            pCommandResult->listErrors.append(tr("Usage: dump [ADDRESS] [SIZE] [FILENAME]"));
            return;
        }

        XADDR nAddress = 0;
        qint32 nSize = 0;

        if (listArguments.count() == 1) {
            nAddress = pInfoDB->getProcessInfo()->nImageBase;
            const quint64 nImageSize = pInfoDB->getProcessInfo()->nImageSize;

            if (nImageSize > (quint64)std::numeric_limits<qint32>::max()) {
                pCommandResult->listErrors.append(tr("Main module is too large to dump safely"));
                return;
            }

            nSize = (qint32)nImageSize;
        } else {
            if (!_getAddress(pCommandResult, listArguments.at(1), &nAddress)) {
                return;
            }

            nSize = 0x1000;
            if ((listArguments.count() >= 3) && (!_getNumber(pCommandResult, listArguments.at(2), &nSize))) {
                return;
            }
        }

        if ((nSize < 1) || (nSize > N_MAX_DUMP_SIZE)) {
            pCommandResult->listErrors.append(tr("Dump size must be between 1 and 67108864 bytes"));
            return;
        }

        QString sFileName = listArguments.value(3);

        if (sFileName == "") {
            sFileName = "dump.bin";
        }

        QByteArray baData = pInfoDB->read_array(nAddress, (quint64)nSize);

        if (baData.size() != nSize) {
            pCommandResult->listErrors.append(
                QString("%1: %2 (%3/%4)").arg(tr("Cannot read complete memory range"), XBinary::valueToHexEx(nAddress)).arg(baData.size()).arg(nSize));
            return;
        }

        QFile file(sFileName);

        if (file.open(QIODevice::WriteOnly)) {
            const qint64 nWritten = file.write(baData);
            file.close();

            if (nWritten == baData.size()) {
                pCommandResult->listTexts.append(
                    QString("DUMP: %1 %2 -> %3").arg(XBinary::valueToHexEx(nAddress), XBinary::valueToHexEx((quint64)baData.size()), sFileName));
            } else {
                pCommandResult->listErrors.append(QString("%1: %2 (%3/%4)").arg(tr("Incomplete file write"), sFileName).arg(nWritten).arg(baData.size()));
            }
        } else {
            pCommandResult->listErrors.append(QString("%1: %2 (%3)").arg(tr("Cannot write file"), sFileName, file.errorString()));
        }
    } else if (sCommandName == "quit") {
        printf("STOP\n");
        pDebugger->stop();
        // break;
    } else {
        QString sError = QString("%1: %2").arg(tr("Unknown command"), sCommand);
        pCommandResult->listErrors.append(sError);
    }
}

bool XDebuggerConsole::_getAddress(COMMAND_RESULT *pCommandResult, const QString &sString, XADDR *pValue)
{
    if ((!pCommandResult) || (!pValue)) {
        return false;
    }

    bool bOK = false;
    const XADDR nValue = sString.toULongLong(&bOK, 16);

    if (!bOK) {
        pCommandResult->listErrors.append(QString("%1: %2").arg(tr("Invalid address"), sString));
        return false;
    }

    *pValue = nValue;
    return true;
}

bool XDebuggerConsole::_getNumber(COMMAND_RESULT *pCommandResult, const QString &sString, qint32 *pValue)
{
    if ((!pCommandResult) || (!pValue)) {
        return false;
    }

    bool bOK = false;
    const qulonglong nValue = sString.toULongLong(&bOK, 10);

    if ((!bOK) || (nValue > (qulonglong)std::numeric_limits<qint32>::max())) {
        pCommandResult->listErrors.append(QString("%1: %2").arg(tr("Invalid number"), sString));
        return false;
    }

    *pValue = (qint32)nValue;
    return true;
}

void XDebuggerConsole::onEventCreateProcess(XInfoDB::PROCESS_INFO *pProcessInfo)
{
    g_nTargetStarted.storeRelease(1);
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
    regOptions.bGeneral = true;
#ifdef Q_PROCESSOR_X86
    regOptions.bDebug = true;
    regOptions.bFlags = true;
    regOptions.bFloat = true;
    regOptions.bSegments = true;
    regOptions.bXMM = true;
    regOptions.bYMM = true;
#endif

    g_pInfoDB->updateModulesList();
    g_pInfoDB->updateMemoryRegionsList();
    g_pInfoDB->updateThreadsList();

#ifdef Q_OS_WIN
    g_pInfoDB->updateRegsByHandle(pBreakPointInfo->hThread, regOptions);
#endif
#if defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
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
