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
#include "xunixdebugger.h"

XUnixDebugger::XUnixDebugger(QObject *pParent, XInfoDB *pXInfoDB) : XAbstractDebugger(pParent, pXInfoDB)
{
    g_pTimer = nullptr;
}

bool XUnixDebugger::run()
{
    bool bResult = false;
    // TODO
    // TODO resuleAllSuspendedThreads

    qint64 nCurrentThreadId = getXInfoDB()->getCurrentThreadId();

    if (g_mapBpOver[nCurrentThreadId] == BPOVER_STEP) {
        bResult = stepIntoById(nCurrentThreadId, XInfoDB::BPI_STEPINTO_RESTOREBP);
    } else {
        bResult = getXInfoDB()->resumeAllThreads();
    }
    return bResult;
}

bool XUnixDebugger::stop()
{
    bool bResult = false;

    if (kill(getXInfoDB()->getProcessInfo()->nProcessID, SIGKILL) != -1) {
        stopDebugLoop();

        setDebugActive(false);

        bResult = true;
    }

    return bResult;
}

void XUnixDebugger::cleanUp()
{
    XUnixDebugger::stop();
    XUnixDebugger::wait();
    // TODO stopDebugEvent
#ifdef Q_OS_LINUX
    if (getXInfoDB()->getProcessInfo()->hProcessMemoryIO) {
        XProcess::closeMemoryIO(getXInfoDB()->getProcessInfo()->hProcessMemoryIO);
        getXInfoDB()->getProcessInfo()->hProcessMemoryIO = 0;
    }

    if (getXInfoDB()->getProcessInfo()->hProcessMemoryQuery) {
        XProcess::closeMemoryQuery(getXInfoDB()->getProcessInfo()->hProcessMemoryQuery);
        getXInfoDB()->getProcessInfo()->hProcessMemoryQuery = 0;
    }
#endif
    g_mapBpOver.clear();
    g_mapThreadBPToRestore.clear();
}

XUnixDebugger::EXECUTEPROCESS XUnixDebugger::executeProcess(QString sFileName, QString sDirectory)
{
    EXECUTEPROCESS result = {};

    result.sStatus = "Error";
#ifdef Q_OS_MAC
    if (::chdir(qPrintable(sDirectory)) == 0)
#endif
    {
        char **ppArgv = new char *[2];

        ppArgv[0] = allocateAnsiStringMemory(sFileName);

#ifdef QT_DEBUG
        qDebug("FileName %s", ppArgv[0]);
#endif

        qint32 nRet = execv(ppArgv[0], ppArgv);  // TODO Unicode

        if (nRet == -1) {
            result.sStatus = QString("execv() failed: %1").arg(strerror(errno));

#ifdef QT_DEBUG
            qDebug("Status %s", result.sStatus.toLatin1().data());
#endif
        }

        for (qint32 i = 0; i < 2; i++) {
            delete[] ppArgv[i];
        }

        delete[] ppArgv;
    }

    return result;
}

void XUnixDebugger::setPtraceOptions(qint64 nThreadID)
{
    // TODO getOptions !!!
    // TODO result bool
//    long options=PTRACE_O_TRACECLONE;
//    long options=PTRACE_O_EXITKILL|PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEFORK;
#if defined(Q_OS_LINUX)
    long options = PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE;
    // PTRACE_O_TRACECLONE create thread

    if (ptrace(PTRACE_SETOPTIONS, nThreadID, 0, options) == -1) {
#ifdef QT_DEBUG
        qDebug("Cannot PTRACE_SETOPTIONS");
#endif
    }
#endif
    // mb TODO
}

XUnixDebugger::STATE XUnixDebugger::waitForSignal(qint64 nProcessID, qint32 nOptions)
{
    STATE result = {};

    pid_t nThreadId = 0;
    qint32 nResult = 0;

    // TODO a function
    // TODO Clone event
    do {
        nThreadId = waitpid(nProcessID, &nResult, nOptions);
    } while ((nThreadId == -1) && (errno == EINTR));

    if (nThreadId < 0) {
        qDebug("waitpid failed: %s", strerror(errno));
    }

    if (nThreadId > 0) {
        result.bIsValid = true;
        result.nThreadId = nThreadId;
        result.nAddress = getXInfoDB()->getCurrentInstructionPointer_Id(nThreadId);

        siginfo_t sigInfo = {};

        if (ptrace(PTRACE_GETSIGINFO, nThreadId, 0, &sigInfo) < 0) {
            qDebug("Error: %s", strerror(errno));
        } else {
            qDebug("Parent: si_signo %X", sigInfo.si_signo);
            qDebug("Parent: si_code %X", sigInfo.si_code);
            qDebug("Parent: si_value %X", sigInfo.si_value.sival_int);
            qDebug("Parent: si_errno %X", sigInfo.si_errno);
            qDebug("Parent: si_pid %u", sigInfo.si_pid);
            qDebug("Parent: si_uid %u", sigInfo.si_uid);
            qDebug("Parent: si_addr %lX", (uint64_t)sigInfo.si_addr);
            qDebug("Parent: si_status %X", sigInfo.si_status);
            qDebug("Parent: si_band %lX", sigInfo.si_band);
        }

        // 80 = SI_KERNEL

        if (sigInfo.si_code == TRAP_TRACE) {
            result.debuggerStatus = DEBUGGER_STATUS_STEP;
            result.nCode = WSTOPSIG(nResult);
        } else if (sigInfo.si_code == SI_KERNEL) {
            result.nAddress = result.nAddress - 1;  // BP
            result.debuggerStatus = DEBUGGER_STATUS_KERNEL;
            result.nCode = WSTOPSIG(nResult);
        } else if (WIFSTOPPED(nResult)) {
            result.debuggerStatus = DEBUGGER_STATUS_STOP;
            result.nCode = WSTOPSIG(nResult);

            if (WSTOPSIG(nResult) == SIGABRT) {
                qDebug("process unexpectedly aborted");
            } else {

            }
            qDebug("!!!WSTOPSIG %x", WSTOPSIG(nResult));
        } else if (WIFEXITED(nResult)) {
            result.debuggerStatus = DEBUGGER_STATUS_EXIT;
            result.nCode = WEXITSTATUS(nResult);
            qDebug("!!!WEXITSTATUS %x", WEXITSTATUS(nResult));
        } else if (WIFSIGNALED(nResult)) {
            result.debuggerStatus = DEBUGGER_STATUS_SIGNAL;
            result.nCode = WTERMSIG(nResult);
            qDebug("!!!WTERMSIG %x", WTERMSIG(nResult));
        }
        // TODO fast events

        qDebug("STATUS: %x", nResult);
    }

    return result;
}

void XUnixDebugger::continueThread(qint64 nThreadID)
{
    // TODO
#if defined(Q_OS_LINUX)
    if (ptrace(PTRACE_CONT, nThreadID, 0, 0)) {
        int wait_status;
        waitpid(nThreadID, &wait_status, 0);
    }
#endif
#if defined(Q_OS_OSX)
    ptrace(PT_CONTINUE, nThreadID, 0, 0);
#endif

    //    int wait_status;
    //    waitpid(nThreadID,&wait_status,0);
    // TODO result
}

bool XUnixDebugger::resumeThread(XProcess::HANDLEID handleID)
{
    bool bResult = false;
#if defined(Q_OS_LINUX)
    if (ptrace(PTRACE_CONT, handleID.nID, 0, 0)) {
        int wait_status;
        waitpid(handleID.nID, &wait_status, 0);
    }
#endif
    return bResult;
}

bool XUnixDebugger::_setStep(XProcess::HANDLEID handleID)
{
    // TODO handle return
    bool bResult = true;
#if defined(Q_OS_LINUX)
    ptrace(PTRACE_SINGLESTEP, handleID.nID, 0, 0);
#endif
#if defined(Q_OS_OSX)
    ptrace(PT_STEP, handleID.nID, 0, 0);
#endif
    //    int wait_status;
    //    waitpid(handleID.nID,&wait_status,0);
    //    // TODO result

    return bResult;
}

void XUnixDebugger::startDebugLoop()
{
    stopDebugLoop();

    g_pTimer = new QTimer(this);

    connect(g_pTimer, SIGNAL(timeout()), this, SLOT(_debugEvent()));

    g_pTimer->start(N_N_DEDELAY);
}

void XUnixDebugger::stopDebugLoop()
{
    if (g_pTimer) {
        g_pTimer->stop();

        delete g_pTimer;

        g_pTimer = nullptr;
    }
}

bool XUnixDebugger::stepIntoById(X_ID nThreadId, XInfoDB::BPI bpInfo)
{
    return getXInfoDB()->stepInto_Id(nThreadId, bpInfo, true);
}

bool XUnixDebugger::stepOverById(X_ID nThreadId, XInfoDB::BPI bpInfo)
{
    return getXInfoDB()->stepOver_Id(nThreadId, bpInfo, true);
}

bool XUnixDebugger::stepInto()
{
    return stepIntoById(getXInfoDB()->getCurrentThreadId(), XInfoDB::BPI_STEPINTO);
}

bool XUnixDebugger::stepOver()
{
    return stepIntoById(getXInfoDB()->getCurrentThreadId(), XInfoDB::BPI_STEPINTO);
}

void XUnixDebugger::_debugEvent()
{
    if (isDebugActive()) {

        bool bContinue = false;

        qint64 nId = getXInfoDB()->getProcessInfo()->nProcessID;

        STATE state = waitForSignal(nId, __WALL | WNOHANG);

        if (state.bIsValid) {
            if ((state.debuggerStatus == DEBUGGER_STATUS_STEP) || (state.debuggerStatus == DEBUGGER_STATUS_KERNEL)) {
                XInfoDB::BREAKPOINT_INFO breakPointInfo = {};

                bool bBreakPoint = false;

                if (state.debuggerStatus == DEBUGGER_STATUS_STEP) {
                    if (g_mapThreadBPToRestore.contains(state.nThreadId)) {
                        XInfoDB::BREAKPOINT _currentBP = g_mapThreadBPToRestore.value(state.nThreadId);
                        getXInfoDB()->addBreakPoint(_currentBP.nAddress, _currentBP.bpType, _currentBP.bpInfo, _currentBP.nCount, _currentBP.sInfo);
                        g_mapThreadBPToRestore.remove(state.nThreadId);

                        g_mapBpOver[state.nThreadId] = BPOVER_RESTORE;
                    }

                    if (getXInfoDB()->getThreadBreakpoints()->contains(state.nThreadId)) {
                        breakPointInfo.bpType = XInfoDB::BPT_CODE_HARDWARE;
                        breakPointInfo.bpInfo = XInfoDB::BPI_STEPINTO;  // TODO STEPOVER

                        bBreakPoint = true;

                        if (g_mapBpOver[state.nThreadId] == BPOVER_RESTORE) {
                            g_mapBpOver[state.nThreadId] == BPOVER_NORMAL;
                        }
                    }
                    // TODO not custom trace
                } else if (state.debuggerStatus == DEBUGGER_STATUS_KERNEL) {
                    if (getXInfoDB()->isBreakPointPresent(state.nAddress, XInfoDB::BPT_CODE_SOFTWARE)) {
                        // TODO Check suspend all threads
                        XInfoDB::BREAKPOINT _currentBP = getXInfoDB()->findBreakPointByAddress(state.nAddress);
                        breakPointInfo.bpType = _currentBP.bpType;
                        breakPointInfo.bpInfo = _currentBP.bpInfo;

                        getXInfoDB()->setCurrentIntructionPointer_Id(state.nThreadId, state.nAddress);  // go to prev instruction address

                        getXInfoDB()->removeBreakPoint(state.nAddress, _currentBP.bpType);

                        if (_currentBP.nCount != -1) {
                            _currentBP.nCount--;
                        }

                        if (_currentBP.nCount) {
                            g_mapThreadBPToRestore.insert(state.nThreadId, _currentBP);
                            g_mapBpOver.insert(state.nThreadId, BPOVER_STEP);
                        }

                        // TODO restore !!!

                        bBreakPoint = true;
                    }
                }

                // TODO suspend all other threads
                if (bBreakPoint) {
                    breakPointInfo.nAddress = state.nAddress;
                    breakPointInfo.pHProcessMemoryIO = getXInfoDB()->getProcessInfo()->hProcessMemoryIO;
                    breakPointInfo.pHProcessMemoryQuery = getXInfoDB()->getProcessInfo()->hProcessMemoryQuery;
                    breakPointInfo.nProcessID = getXInfoDB()->getProcessInfo()->nProcessID;
                    breakPointInfo.nThreadID = getXInfoDB()->getProcessInfo()->nMainThreadID; // TODO Check !!!

                    _eventBreakPoint(&breakPointInfo);
                }
            } else if (state.debuggerStatus == DEBUGGER_STATUS_EXIT) {
                // TODO STOP
                // mb TODO exitThread
                g_pTimer->stop();

                XInfoDB::EXITPROCESS_INFO exitProcessInfo = {};
                exitProcessInfo.nProcessID = state.nThreadId;
                exitProcessInfo.nThreadID = state.nThreadId;
                exitProcessInfo.nExitCode = state.nCode;

                getXInfoDB()->removeThreadInfo(state.nThreadId);

                emit eventExitProcess(&exitProcessInfo);

                setDebugActive(false);
            }

            if (g_mapBpOver[state.nThreadId] == BPOVER_RESTORE) {
                continueThread(state.nThreadId);
                g_mapBpOver.remove(state.nThreadId);
            }

            if (g_mapBpOver[state.nThreadId] == BPOVER_NORMAL) {
                g_mapBpOver.remove(state.nThreadId);
            }
        }
    }
}
