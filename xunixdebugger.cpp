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
#include "xunixdebugger.h"

XUnixDebugger::XUnixDebugger(QObject *pParent, XInfoDB *pXInfoDB) : XAbstractDebugger(pParent, pXInfoDB)
{
    g_pTimer = nullptr;
}

bool XUnixDebugger::run()
{
    return getXInfoDB()->resumeAllThreads();
}

bool XUnixDebugger::stop()
{
    bool bResult = false;

    if (getXInfoDB()->getThreadInfos()->count()) {
        if (kill(getXInfoDB()->getProcessInfo()->nProcessID, SIGKILL) != -1) {
            stopDebugLoop();

            setDebugActive(false);

            bResult = true;
        }
    }

    return bResult;
}

void XUnixDebugger::cleanUp()
{
    XUnixDebugger::stop();
    XUnixDebugger::wait();
    // TODO stopDebugEvent
}

XUnixDebugger::EXECUTEPROCESS XUnixDebugger::executeProcess(const QString &sFileName, const QString &sDirectory)
{
    // TODO Working directory
    Q_UNUSED(sDirectory)
    EXECUTEPROCESS result = {};

    bool bSuccess = true;

    result.sErrorString = "Error";
#ifdef Q_OS_MAC
    bSuccess = false;
    if (::chdir(qPrintable(sDirectory)) == 0) {
        bSuccess = true;
    }
#endif
    if (bSuccess) {
        char **ppArgv = new char *[2];

        ppArgv[0] = XInfoDB::allocateStringMemory(sFileName);

        qint32 nRet = execv(ppArgv[0], ppArgv);  // TODO Unicode

        if (nRet == -1) {
            result.sErrorString = QString("%1: execv() failed: %2").arg(sFileName, strerror(errno));
        }

        for (qint32 i = 0; i < 2; i++) {
            delete[] ppArgv[i];
        }

        delete[] ppArgv;
    }

    return result;
}

bool XUnixDebugger::setPtraceOptions(qint64 nThreadID)
{
    bool bResult = false;
    // TODO getOptions !!!
    // TODO result bool
//    long options=PTRACE_O_TRACECLONE;
//    long options=PTRACE_O_EXITKILL|PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEFORK;
#if defined(Q_OS_LINUX)
    long options = PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE;
    // PTRACE_O_TRACECLONE create thread

    if (ptrace(PTRACE_SETOPTIONS, nThreadID, 0, options) != -1) {
        bResult = true;
    } else {
#ifdef QT_DEBUG
        qDebug("Cannot PTRACE_SETOPTIONS");
#endif
    }
#endif
    // mb TODO
    return bResult;
}

XUnixDebugger::STATE XUnixDebugger::waitForSignal(qint64 nThreadID, qint32 nOptions)
{
    STATE result = {};

    pid_t nChildThreadId = 0;
    qint32 nResult = 0;

    // TODO a function
    // TODO Clone event
    do {
        nChildThreadId = waitpid(nThreadID, &nResult, nOptions);
    } while ((nChildThreadId == -1) && (errno == EINTR));

    if (nChildThreadId < 0) {
        qDebug("errno: %x", errno);
        qDebug("waitpid failed: %s", strerror(errno));
    }

    if (nChildThreadId > 0) {
        result.bIsValid = true;
        result.nThreadId = nChildThreadId;
        result.nAddress = getXInfoDB()->getCurrentInstructionPointer_Id(nChildThreadId);

        siginfo_t sigInfo = {};

        if (ptrace(PTRACE_GETSIGINFO, nChildThreadId, 0, &sigInfo) < 0) {
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

            result.nExceptionAddress = (XADDR)sigInfo.si_addr;
        }

        // 80 = SI_KERNEL

        if (sigInfo.si_code == TRAP_TRACE) {
            result.debuggerStatus = DEBUGGER_STATUS_STEP;
        } else if (sigInfo.si_code == TRAP_BRKPT) {
            result.debuggerStatus = DEBUGGER_STATUS_BREAKPOINT;  // TODO // 0xF1 int1
        } else if (sigInfo.si_code == SI_KERNEL) {               // 0xCC int3 9xF4 hlt
            // result.nAddress = result.nAddress - 1;  // BP
            result.debuggerStatus = DEBUGGER_STATUS_KERNEL;
        } else if (WIFSTOPPED(nResult)) {
            result.nCode = WSTOPSIG(nResult);

            if (WSTOPSIG(nResult) == SIGTRAP) {
                result.debuggerStatus = DEBUGGER_STATUS_SIGTRAP;
            } else if (WSTOPSIG(nResult) == SIGABRT) {
                result.debuggerStatus = DEBUGGER_STATUS_STOP;
            } else {
                result.debuggerStatus = DEBUGGER_STATUS_EXCEPTION;
            }

            if (WSTOPSIG(nResult) == SIGABRT) {
                qDebug("process unexpectedly aborted");
            } else if (WSTOPSIG(nResult) == SIGPIPE) {
                qDebug("SIGPIPE");  // TODO Check IN/OUT HANDLES
            } else if (WSTOPSIG(nResult) == SIGTRAP) {
                qDebug("SIGTRAP");
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
    } else if ((nChildThreadId < 0) && (errno == 10)) {
        // No child processes
        // TODO
        stopDebugLoop();
    }

    return result;
}

bool XUnixDebugger::waitForSigchild()
{
    sigset_t mask = {};
    siginfo_t info = {};
    timespec ts = {};
    ts.tv_nsec = 10000000;  // 10 ms
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);

    qint32 nRet = 0;
    do {
        nRet = sigtimedwait(&mask, &info, &ts);
    } while (nRet == -1 && errno == EINTR);

    return (nRet == SIGCHLD);
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

    // g_pTimer->start(N_N_DEDELAY);
    g_pTimer->start(0);
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
    bool bResult = false;

    bResult = getXInfoDB()->stepInto_Id(nThreadId, bpInfo);

    if (bResult) {
        bResult = getXInfoDB()->resumeAllThreads();
    }

    return bResult;
}

bool XUnixDebugger::stepOverById(X_ID nThreadId, XInfoDB::BPI bpInfo)
{
    bool bResult = false;

    bResult = getXInfoDB()->stepOver_Id(nThreadId, bpInfo);

    if (bResult) {
        bResult = getXInfoDB()->resumeAllThreads();
    }

    return bResult;
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
        // bool bContinue = false;

        if (!waitForSigchild()) {
            qint64 nId = getXInfoDB()->getProcessInfo()->nProcessID;  // TODO all threads

            STATE state = waitForSignal(nId, __WALL | WNOHANG);

            if (state.bIsValid) {
                BPSTATUS result = BPSTATUS_UNKNOWN;

                getXInfoDB()->setThreadStatus(state.nThreadId, XInfoDB::THREAD_STATUS_PAUSED);

                if (state.debuggerStatus == DEBUGGER_STATUS_SIGNAL) {
                    qDebug("DEBUGGER_STATUS_SIGNAL");
                } else if (state.debuggerStatus == DEBUGGER_STATUS_STOP) {
                    qDebug("DEBUGGER_STATUS_STOP");
                } else if (state.debuggerStatus == DEBUGGER_STATUS_STEP) {
                    qDebug("DEBUGGER_STATUS_STEP");

                    BPSTATUS nStepToRestoreResult = _handleBreakpoint(state, XInfoDB::BPT_CODE_STEP_TO_RESTORE);
                    BPSTATUS nStepFlagResult = _handleBreakpoint(state, XInfoDB::BPT_CODE_STEP_FLAG);
                    BPSTATUS nBreakpointResult = _handleBreakpoint(state, XInfoDB::BPT_CODE_SOFTWARE_INT1);

                    if ((nStepFlagResult == BPSTATUS_CALLBACK) || (nBreakpointResult == BPSTATUS_CALLBACK)) {
                        result = BPSTATUS_CALLBACK;
                    } else if (nStepToRestoreResult == BPSTATUS_HANDLED) {
                        result = BPSTATUS_HANDLED;
                    }
                } else if (state.debuggerStatus == DEBUGGER_STATUS_KERNEL) {
                    qDebug("DEBUGGER_STATUS_KERNEL");
                    result = _handleBreakpoint(state, XInfoDB::BPT_CODE_SOFTWARE_INT3);
                } else if (state.debuggerStatus == DEBUGGER_STATUS_BREAKPOINT) {
                    qDebug("DEBUGGER_STATUS_BREAKPOINT");
                    result = _handleBreakpoint(state, XInfoDB::BPT_CODE_SOFTWARE_INT3);
                } else if (state.debuggerStatus == DEBUGGER_STATUS_EXIT) {
                    qDebug("DEBUGGER_STATUS_EXIT");
                    result = BPSTATUS_EXIT;
                }
                //
                //                getXInfoDB()->setThreadStatus(state.nThreadId, XInfoDB::THREAD_STATUS_PAUSED);

                //                if ((state.debuggerStatus == DEBUGGER_STATUS_STEP) || (state.debuggerStatus == DEBUGGER_STATUS_KERNEL) ||
                //                    (state.debuggerStatus == DEBUGGER_STATUS_BREAKPOINT)) {
                //                    XInfoDB::BREAKPOINT_INFO breakPointInfo = {};

                //                    bool bBreakPoint = false;

                //                    if (state.debuggerStatus == DEBUGGER_STATUS_STEP) {
                //                        if (g_mapThreadBPToRestore.contains(state.nThreadId)) {
                //                            QString _sUUID = g_mapThreadBPToRestore.value(state.nThreadId);
                //                            getXInfoDB()->enableBreakPoint(_sUUID);
                //                            g_mapThreadBPToRestore.remove(state.nThreadId);

                //                            g_mapBpOver[state.nThreadId] = BPOVER_RESTORE;
                //                        }

                //                        if (getXInfoDB()->getThreadBreakpoints()->contains(state.nThreadId)) {
                //                            getXInfoDB()->getThreadBreakpoints()->remove(state.nThreadId);

                //                            breakPointInfo.bpType = XInfoDB::BPT_CODE_STEP_FLAG;
                //                            breakPointInfo.bpInfo = XInfoDB::BPI_STEPINTO;  // TODO STEPOVER

                //                            bBreakPoint = true;

                //                            if (g_mapBpOver[state.nThreadId] == BPOVER_RESTORE) {
                //                                g_mapBpOver[state.nThreadId] = BPOVER_NORMAL;
                //                            }
                //                        }
                //                        // TODO not custom trace
                //                    } else if ((state.debuggerStatus == DEBUGGER_STATUS_KERNEL) || (state.debuggerStatus == DEBUGGER_STATUS_BREAKPOINT)) {
                //                        qint64 nDelta = 0;

                //                        if (true) {  // TODO If XInfoDB::BPT_CODE_SOFTWARE_INT3 or XInfoDB::BPT_CODE_SOFTWARE_INT1 // TODO remove !!! Use find by
                //                        exception
                //                            nDelta = 1;
                //                        }

                //                        XADDR nBreakpointAddress = state.nAddress - nDelta;

                //                        if (getXInfoDB()->isBreakPointPresent(nBreakpointAddress, XInfoDB::BPT_CODE_SOFTWARE_DEFAULT)) {  // TODO
                //                            // TODO Check suspend all threads
                //                            XInfoDB::BREAKPOINT _currentBP = getXInfoDB()->findBreakPointByAddress(nBreakpointAddress,
                //                            XInfoDB::BPT_CODE_SOFTWARE_DEFAULT); breakPointInfo.bpType = _currentBP.bpType; breakPointInfo.bpInfo = _currentBP.bpInfo;

                //                            if (nDelta) {
                //                                getXInfoDB()->setCurrentIntructionPointer_Id(state.nThreadId, nBreakpointAddress);  // go to prev instruction address
                //                            }

                //                            getXInfoDB()->disableBreakPoint(_currentBP.sUUID);

                //                            if (_currentBP.nCount != -1) {
                //                                _currentBP.nCount--;
                //                            }

                //                            if (_currentBP.nCount) {
                //                                g_mapThreadBPToRestore.insert(state.nThreadId, _currentBP.sUUID);
                //                                g_mapBpOver.insert(state.nThreadId, BPOVER_STEP);
                //                            } else {
                //                                getXInfoDB()->removeBreakPoint(_currentBP.sUUID);
                //                            }

                //                            // TODO restore !!!

                //                            bBreakPoint = true;
                //                        } else if (getOptions()->records[OPTIONS_TYPE_BREAKPOINTSYSTEM].varValue.toBool()) {
                //                            bBreakPoint = true;
                //                            // TODO Send signal if not
                //                        }
                //                    }

                //                    // TODO suspend all other threads
                //                    if (bBreakPoint) {
                //                        breakPointInfo.nExceptionAddress = state.nAddress;
                //                        breakPointInfo.pHProcessMemoryIO = getXInfoDB()->getProcessInfo()->hProcessMemoryIO;
                //                        breakPointInfo.pHProcessMemoryQuery = getXInfoDB()->getProcessInfo()->hProcessMemoryQuery;
                //                        breakPointInfo.nProcessID = getXInfoDB()->getProcessInfo()->nProcessID;
                //                        breakPointInfo.nThreadID = getXInfoDB()->getProcessInfo()->nMainThreadID;  // TODO Check !!!

                //                        _eventBreakPoint(&breakPointInfo);
                //                    }
                //                } else if (state.debuggerStatus == DEBUGGER_STATUS_EXIT) {
                //                    // TODO STOP
                //                    // mb TODO exitThread
                //                    g_pTimer->stop();

                //                    XInfoDB::EXITPROCESS_INFO exitProcessInfo = {};
                //                    exitProcessInfo.nProcessID = state.nThreadId;
                //                    exitProcessInfo.nThreadID = state.nThreadId;
                //                    exitProcessInfo.nExitCode = state.nCode;

                //                    getXInfoDB()->removeThreadInfo(state.nThreadId);

                //                    emit eventExitProcess(&exitProcessInfo);

                //                    setDebugActive(false);
                //                }

                //                if (g_mapBpOver[state.nThreadId] == BPOVER_RESTORE) {
                //                    getXInfoDB()->resumeThread_Id(state.nThreadId);
                //                    g_mapBpOver.remove(state.nThreadId);
                //                }

                //                if (g_mapBpOver[state.nThreadId] == BPOVER_NORMAL) {
                //                    g_mapBpOver.remove(state.nThreadId);
                //                }

                if (result == BPSTATUS_UNKNOWN) {
                    //                    if (true) {
                    //                        qDebug("SYSTEM BP SOFTWARE");

                    //                        getXInfoDB()->suspendAllThreads();

                    //                        XInfoDB::BREAKPOINT_INFO breakPointInfo = {};
                    //                        breakPointInfo.vInfo = state.nCode;
                    //                        breakPointInfo.nAddress = state.nAddress;
                    //                        breakPointInfo.nExceptionAddress = state.nExceptionAddress;
                    //                        breakPointInfo.nProcessID = getXInfoDB()->getProcessInfo()->nProcessID;
                    //                        breakPointInfo.nThreadID = state.nThreadId;
                    //                        breakPointInfo.bpType = XInfoDB::BPT_CODE_SYSTEM_EXCEPTION;
                    //                        breakPointInfo.bpInfo = XInfoDB::BPI_SYSTEM;

                    //                        _eventBreakPoint(&breakPointInfo);

                    //                        result = BPSTATUS_CALLBACK;
                    //                    }
                }

                if (result == BPSTATUS_UNKNOWN) {
                    getXInfoDB()->resumeThread_Id(state.nThreadId);
                } else if (result == BPSTATUS_HANDLED) {
                    getXInfoDB()->resumeAllThreads();
                } else if (result == BPSTATUS_EXIT) {
                    setDebugActive(false);
                }
            }
        }
    }
}

XAbstractDebugger::BPSTATUS XUnixDebugger::_handleBreakpoint(STATE state, XInfoDB::BPT bpType)
{
    BPSTATUS result = BPSTATUS_UNKNOWN;

    XInfoDB::BREAKPOINT _currentBP = {};

    bool bSuccess = false;

    if (bpType == XInfoDB::BPT_CODE_SOFTWARE_INT3) {
        _currentBP = getXInfoDB()->findBreakPointByExceptionAddress(state.nAddress, bpType);
    } else if ((bpType == XInfoDB::BPT_CODE_STEP_FLAG) || (bpType == XInfoDB::BPT_CODE_STEP_TO_RESTORE)) {
        _currentBP = getXInfoDB()->findBreakPointByThreadID(state.nThreadId, bpType);
    }

    if (_currentBP.sUUID != "") {
        bSuccess = true;
    }

    // TODO

    if (bSuccess) {
        getXInfoDB()->suspendAllThreads();

        if ((bpType == XInfoDB::BPT_CODE_SOFTWARE_INT1) || (bpType == XInfoDB::BPT_CODE_SOFTWARE_INT3) || (bpType == XInfoDB::BPT_CODE_SOFTWARE_UD2) ||
            (bpType == XInfoDB::BPT_CODE_SOFTWARE_HLT) || (bpType == XInfoDB::BPT_CODE_SOFTWARE_CLI) || (bpType == XInfoDB::BPT_CODE_SOFTWARE_STI) ||
            (bpType == XInfoDB::BPT_CODE_SOFTWARE_INSB) || (bpType == XInfoDB::BPT_CODE_SOFTWARE_INSD) || (bpType == XInfoDB::BPT_CODE_SOFTWARE_OUTSB) ||
            (bpType == XInfoDB::BPT_CODE_SOFTWARE_OUTSD) || (bpType == XInfoDB::BPT_CODE_SOFTWARE_INT3LONG)) {
            if ((bpType == XInfoDB::BPT_CODE_SOFTWARE_INT1) || (bpType == XInfoDB::BPT_CODE_SOFTWARE_INT3) || (bpType == XInfoDB::BPT_CODE_SOFTWARE_INT3LONG)) {
                getXInfoDB()->setCurrentIntructionPointer_Id(state.nThreadId, _currentBP.nAddress);  // go to prev instruction address
            }

            if (_currentBP.bOneShot) {
                getXInfoDB()->removeBreakPoint(_currentBP.sUUID);
            } else {
                getXInfoDB()->disableBreakPoint(_currentBP.sUUID);
            }

            XInfoDB::BREAKPOINT_INFO breakPointInfo = {};
            breakPointInfo.nAddress = state.nAddress;
            breakPointInfo.nExceptionAddress = _currentBP.nAddress;
            breakPointInfo.nProcessID = getXInfoDB()->getProcessInfo()->nProcessID;
            breakPointInfo.nThreadID = state.nThreadId;
            breakPointInfo.bpType = _currentBP.bpType;
            breakPointInfo.bpInfo = _currentBP.bpInfo;
            breakPointInfo.vInfo = _currentBP.vInfo;

            _eventBreakPoint(&breakPointInfo);

            // mb TODO add it later
            if (!_currentBP.bOneShot) {
                XInfoDB::BREAKPOINT bp = {};
                bp.nAddress = state.nAddress;
                bp.nThreadID = state.nThreadId;
                bp.bpType = XInfoDB::BPT_CODE_STEP_TO_RESTORE;
                bp.vInfo = _currentBP.sUUID;
                getXInfoDB()->addBreakPoint(bp);
            }

            result = BPSTATUS_CALLBACK;
        } else if (bpType == XInfoDB::BPT_CODE_STEP_FLAG) {
            // mb TODO count
            getXInfoDB()->removeBreakPoint(_currentBP.sUUID);

            XInfoDB::BREAKPOINT_INFO breakPointInfo = {};
            breakPointInfo.nAddress = state.nAddress;
            breakPointInfo.nExceptionAddress = state.nExceptionAddress;
            breakPointInfo.nProcessID = getXInfoDB()->getProcessInfo()->nProcessID;
            breakPointInfo.nThreadID = state.nThreadId;
            breakPointInfo.bpType = _currentBP.bpType;
            breakPointInfo.bpInfo = _currentBP.bpInfo;
            breakPointInfo.vInfo = _currentBP.vInfo;

            _eventBreakPoint(&breakPointInfo);

            result = BPSTATUS_CALLBACK;
        } else if (bpType == XInfoDB::BPT_CODE_STEP_TO_RESTORE) {
            getXInfoDB()->removeBreakPoint(_currentBP.sUUID);

            XInfoDB::BREAKPOINT _subBP = getXInfoDB()->findBreakPointByUUID(_currentBP.vInfo.toString());

            if (_subBP.sUUID != "") {
                XADDR nCurrentAddress = getXInfoDB()->getCurrentInstructionPointer_Id(state.nThreadId);

                if ((nCurrentAddress >= _subBP.nAddress) && (nCurrentAddress < _subBP.nAddress + _subBP.nDataSize)) {
                    XInfoDB::BREAKPOINT bp = {};
                    bp.nAddress = nCurrentAddress;
                    bp.nThreadID = state.nThreadId;
                    bp.bpType = XInfoDB::BPT_CODE_STEP_TO_RESTORE;
                    bp.vInfo = _subBP.sUUID;
                    getXInfoDB()->addBreakPoint(bp);
                } else {
                    getXInfoDB()->enableBreakPoint(_subBP.sUUID);
                }
            }

            result = BPSTATUS_HANDLED;
        }
    }

    return result;
}
