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
#include "xunixdebugger.h"

#include <QProcess>
#include <QThread>

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
XInfoDB::BPT getNativeSoftwareBreakpointType()
{
#if defined(Q_OS_MACOS) && defined(Q_PROCESSOR_ARM_64)
    return XInfoDB::BPT_CODE_SOFTWARE_BRK;
#else
    return XInfoDB::BPT_CODE_SOFTWARE_INT3;
#endif
}
}  // namespace

XUnixDebugger::XUnixDebugger(QObject *pParent, XInfoDB *pXInfoDB) : XAbstractDebugger(pParent, pXInfoDB)
{
    g_pTimer = nullptr;
    g_bTerminationPending = false;
    g_nTerminationProcessId = 0;
    g_nTerminationExitThreadId = 0;
    g_nTerminationExitCode = 0;
}

bool XUnixDebugger::run()
{
    if (g_bTerminationPending) {
        return false;
    }

    return resumeAllThreads();
}

bool XUnixDebugger::resumeThread(X_ID nThreadId, qint32 nSignal)
{
    return getXInfoDB()->resumeThread_Id(nThreadId, nSignal);
}

bool XUnixDebugger::resumeAllThreads()
{
    return getXInfoDB()->resumeAllThreads();
}

bool XUnixDebugger::stop()
{
    if (g_bTerminationPending) {
        return true;
    }

    XInfoDB::PROCESS_INFO *pProcessInfo = getXInfoDB()->getProcessInfo();
    const X_ID nProcessId = pProcessInfo->nProcessID;

    if (!nProcessId) {
        return false;
    }

    // Stopping is a state transition, not completion. In particular, Linux reports a
    // PTRACE_EVENT_EXIT stop before the final wait status; deleting the polling timer here
    // strands that tracee and prevents eventExitProcess from reaching the GUI/console.
    g_bTerminationPending = true;
    g_nTerminationProcessId = nProcessId;
    g_nTerminationExitThreadId = nProcessId;
    g_nTerminationExitCode = SIGKILL;
    g_sTerminationFileName = pProcessInfo->sFileName;
    g_setTerminationThreadIds.clear();
    _refreshTerminationThreads();

    if ((::kill(static_cast<pid_t>(nProcessId), SIGKILL) == -1) && (errno != ESRCH)) {
        const qint32 nKillError = errno;
        g_bTerminationPending = false;
        g_nTerminationProcessId = 0;
        g_nTerminationExitThreadId = 0;
        g_nTerminationExitCode = 0;
        g_sTerminationFileName.clear();
        g_setTerminationThreadIds.clear();
        emit errorMessage(QString("%1: %2").arg(tr("Cannot terminate process"), QString::fromLocal8Bit(strerror(nKillError))));
        return false;
    }

    // Include a TID registered by any nested callback before this request returns. Clone events
    // not yet consumed are discovered through PTRACE_GETEVENTMSG in the drain itself.
    _refreshTerminationThreads();

    return true;
}

void XUnixDebugger::cleanUp()
{
    if (getXInfoDB()->getProcessInfo()->nProcessID) {
        XUnixDebugger::stop();
    }

    // requestShutdown() deliberately clears isDebugActive(), so wait() cannot be used for
    // teardown. Drain independently of that flag and do not let the tracer disappear while
    // Linux still has a PTRACE_EVENT_EXIT stop outstanding.
    finishPendingTermination();
    stopDebugLoop();
    XAbstractDebugger::cleanUp();
}

bool XUnixDebugger::hasPendingTermination() const
{
    return g_bTerminationPending;
}

void XUnixDebugger::finishPendingTermination()
{
    if (g_bTerminationPending) {
        // Direct create-process/thread callbacks may request Stop while the loader is still
        // publishing successfully traced TIDs. Refresh after those callbacks unwind so cleanup
        // does not finalize on the leader while a later registered sibling remains waitable.
        _refreshTerminationThreads();
        _drainTermination(true);
    }
}

void XUnixDebugger::_refreshTerminationThreads()
{
    if (!g_bTerminationPending || !g_nTerminationProcessId) {
        return;
    }

#if defined(Q_OS_LINUX)
    const QList<XInfoDB::THREAD_INFO> listThreadInfos = *(getXInfoDB()->getThreadInfos());
    for (const XInfoDB::THREAD_INFO &threadInfo : listThreadInfos) {
        if (threadInfo.nThreadID) {
            g_setTerminationThreadIds.insert(threadInfo.nThreadID);
        }
    }
#endif

    // Cache only TIDs known to be ptrace-owned by this debugger. A raw /proc snapshot may
    // contain threads whose attach failed; treating those as waitable can hang shutdown forever.
    // Darwin exposes one wait status for the process, so its Mach thread IDs are not added here.
    g_setTerminationThreadIds.insert(g_nTerminationProcessId);
}

bool XUnixDebugger::_drainTermination(bool bWait)
{
    while (g_bTerminationPending) {
        bool bProgress = false;

#if defined(Q_OS_LINUX)
        const QList<X_ID> listThreadIds = g_setTerminationThreadIds.values();
        for (X_ID nThreadId : listThreadIds) {
            qint32 nStatus = 0;
            qint32 nWaitOptions = WNOHANG | __WALL;

            pid_t nWaitResult = 0;
            do {
                nWaitResult = ::waitpid(static_cast<pid_t>(nThreadId), &nStatus, nWaitOptions);
            } while ((nWaitResult == -1) && (errno == EINTR));

            if (nWaitResult > 0) {
                bProgress = true;

                if (WIFSTOPPED(nStatus)) {
                    const quint32 nPtraceEvent = static_cast<quint32>(nStatus) >> 16;

                    if (nPtraceEvent == PTRACE_EVENT_CLONE) {
                        unsigned long nNewThreadId = 0;
                        if ((ptrace(PTRACE_GETEVENTMSG, nWaitResult, nullptr, &nNewThreadId) != -1) && nNewThreadId) {
                            g_setTerminationThreadIds.insert(static_cast<X_ID>(nNewThreadId));
                        }
                    }

                    // PTRACE_EVENT_EXIT must be continued before waitpid can return the final
                    // WIFEXITED/WIFSIGNALED state. For an older pending stop, re-deliver SIGKILL.
                    const qint32 nSignal = (nPtraceEvent == PTRACE_EVENT_EXIT) ? 0 : SIGKILL;
                    void *pSignal = reinterpret_cast<void *>(static_cast<quintptr>(nSignal));
                    if ((ptrace(PTRACE_CONT, nWaitResult, nullptr, pSignal) == -1) && (errno != ESRCH)) {
                        emit warningMessage(QString("%1 %2: %3").arg(tr("Cannot continue terminating thread"))
                                                .arg(static_cast<qint64>(nWaitResult))
                                                .arg(QString::fromLocal8Bit(strerror(errno))));
                    }
                } else if (WIFEXITED(nStatus) || WIFSIGNALED(nStatus)) {
                    const X_ID nExitedThreadId = static_cast<X_ID>(nWaitResult);
                    if (nExitedThreadId == g_nTerminationProcessId) {
                        g_nTerminationExitThreadId = nExitedThreadId;
                        g_nTerminationExitCode = WIFEXITED(nStatus) ? static_cast<quint32>(WEXITSTATUS(nStatus))
                                                                   : static_cast<quint32>(WTERMSIG(nStatus));
                    }
                    g_setTerminationThreadIds.remove(nExitedThreadId);
                    getXInfoDB()->removeThreadInfo(nExitedThreadId);
                }
            } else if ((nWaitResult == -1) && (errno == ECHILD)) {
                // The set contains only successfully traced TIDs. For a specific TID on the
                // tracer thread, a live child yields 0 with WNOHANG; ECHILD means its wait
                // relationship/status has already been consumed. No unrelated child is touched.
                g_setTerminationThreadIds.remove(nThreadId);
                getXInfoDB()->removeThreadInfo(nThreadId);
                bProgress = true;
            } else if (nWaitResult == -1) {
                const qint32 nWaitError = errno;
                emit errorMessage(QString("%1 %2: %3").arg(tr("Cannot reap terminating thread"))
                                      .arg(static_cast<qint64>(nThreadId))
                                      .arg(QString::fromLocal8Bit(strerror(nWaitError))));
                // A permanent waitpid error must not spin the shutdown worker forever. The
                // target already has SIGKILL pending; dropping tracer ownership during teardown
                // is the only remaining kernel-level fallback.
                g_setTerminationThreadIds.remove(nThreadId);
                getXInfoDB()->removeThreadInfo(nThreadId);
                bProgress = true;
            }
        }
#elif defined(Q_OS_MACOS)
        qint32 nStatus = 0;
        pid_t nWaitResult = 0;
        do {
            nWaitResult = ::waitpid(static_cast<pid_t>(g_nTerminationProcessId), &nStatus, WNOHANG);
        } while ((nWaitResult == -1) && (errno == EINTR));

        if (nWaitResult > 0) {
            bProgress = true;
            if (WIFSTOPPED(nStatus)) {
                if ((ptrace(PT_CONTINUE, nWaitResult, reinterpret_cast<caddr_t>(1), SIGKILL) == -1) && (errno != ESRCH)) {
                    emit warningMessage(QString("%1: %2").arg(tr("Cannot continue terminating process"), QString::fromLocal8Bit(strerror(errno))));
                }
            } else if (WIFEXITED(nStatus) || WIFSIGNALED(nStatus)) {
                g_nTerminationExitThreadId = static_cast<X_ID>(nWaitResult);
                g_nTerminationExitCode = WIFEXITED(nStatus) ? static_cast<quint32>(WEXITSTATUS(nStatus))
                                                            : static_cast<quint32>(WTERMSIG(nStatus));
                g_setTerminationThreadIds.clear();
            }
        } else if ((nWaitResult == -1) && (errno == ECHILD)) {
            errno = 0;
            if ((::kill(static_cast<pid_t>(g_nTerminationProcessId), 0) == -1) && (errno == ESRCH)) {
                g_setTerminationThreadIds.clear();
                bProgress = true;
            }
        }
#endif

        if (g_setTerminationThreadIds.isEmpty()) {
            _completeProcessExit(g_nTerminationProcessId, g_nTerminationExitThreadId, g_nTerminationExitCode, g_sTerminationFileName);
            return true;
        }

        if (!bWait) {
            return false;
        }

        if (!bProgress) {
            QThread::msleep(1);
        }
    }

    return true;
}

void XUnixDebugger::_completeProcessExit(X_ID nProcessId, X_ID nThreadId, quint32 nExitCode, const QString &sFileName)
{
    XInfoDB::EXITPROCESS_INFO exitProcessInfo = {};
    exitProcessInfo.nProcessID = nProcessId;
    exitProcessInfo.nThreadID = nThreadId;
    exitProcessInfo.nExitCode = nExitCode;
    exitProcessInfo.sFileName = sFileName;

    const QList<XInfoDB::THREAD_INFO> listThreadInfos = *(getXInfoDB()->getThreadInfos());
    for (const XInfoDB::THREAD_INFO &threadInfo : listThreadInfos) {
        getXInfoDB()->removeThreadInfo(threadInfo.nThreadID);
    }
    getXInfoDB()->setCurrentThreadId(0);

    // Teardown disconnected the GUI before requestShutdown(); user-facing exit delivery is only
    // meaningful for a live session. The local event record remains valid for all current Direct
    // and BlockingQueued connections until emit returns.
    if (!isShutdownRequested()) {
        emit eventExitProcess(&exitProcessInfo);
    }

    XInfoDB::PROCESS_INFO *pProcessInfo = getXInfoDB()->getProcessInfo();
    pProcessInfo->nProcessID = 0;
    pProcessInfo->nMainThreadID = 0;
    setDebugActive(false);
    stopDebugLoop();

    g_bTerminationPending = false;
    g_nTerminationProcessId = 0;
    g_nTerminationExitThreadId = 0;
    g_nTerminationExitCode = 0;
    g_sTerminationFileName.clear();
    g_setTerminationThreadIds.clear();
}

XUnixDebugger::EXECUTEPROCESS XUnixDebugger::executeProcess(const QString &sFileName, const QString &sDirectory)
{
    // Runs in the forked child, after PTRACE_TRACEME. Technique from edb: honor the working
    // directory, then exec the target with a full argv (program + parsed arguments).
    EXECUTEPROCESS result = {};

    bool bSuccess = true;

    result.sErrorString = "Error";

    if (!sDirectory.isEmpty()) {
        if (::chdir(sDirectory.toUtf8().constData()) != 0) {
            bSuccess = false;
            result.sErrorString = QString("chdir() failed: %1").arg(strerror(errno));
        }
    }

    if (bSuccess) {
        QStringList listArguments;
        listArguments.append(sFileName);

        QString sArguments = getOptions()->sArguments;
        if (!sArguments.isEmpty()) {
#if QT_VERSION >= QT_VERSION_CHECK(5, 15, 0)
            listArguments.append(QProcess::splitCommand(sArguments));
#else
            listArguments.append(sArguments.split(QRegExp("\\s+"), QString::SkipEmptyParts));
#endif
        }

        qint32 nCount = listArguments.count();

        char **ppArgv = new char *[nCount + 1];  // +1 for the terminating nullptr

        for (qint32 i = 0; i < nCount; i++) {
            ppArgv[i] = XInfoDB::allocateStringMemory(listArguments.at(i));
        }
        ppArgv[nCount] = nullptr;

        qint32 nRet = execv(ppArgv[0], ppArgv);  // TODO Unicode

        if (nRet == -1) {
            result.sErrorString = QString("%1: execv() failed: %2").arg(sFileName, strerror(errno));
        }

        // Only reached if execv failed (on success the image is replaced).
        for (qint32 i = 0; i < nCount; i++) {
            delete[] ppArgv[i];
        }

        delete[] ppArgv;
    }

    return result;
}

bool XUnixDebugger::setPtraceOptions(qint64 nThreadID)
{
    bool bResult = false;
#if defined(Q_OS_LINUX)
    // Technique from edb:
    //   PTRACE_O_TRACECLONE - deliver an event when the target creates a thread (essential for
    //                         multithreaded debugging; decoded via status>>8 in waitForSignal)
    //   PTRACE_O_EXITKILL   - kill the debuggee if the debugger dies
    //   PTRACE_O_TRACEEXIT  - stop just before a thread/process exits so the exit code is
    //                         retrievable via PTRACE_GETEVENTMSG
    long options = PTRACE_O_EXITKILL | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT;

    if (ptrace(PTRACE_SETOPTIONS, nThreadID, 0, options) != -1) {
        bResult = true;
    } else {
#ifdef QT_DEBUG
        qDebug("Cannot PTRACE_SETOPTIONS: %s", strerror(errno));
#endif
    }
#else
    Q_UNUSED(nThreadID)
#endif
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

#if defined(Q_OS_LINUX)
        // ptrace-event stops (clone/exit) are encoded in the high byte of the wait status and
        // arrive as SIGTRAP stops. Decode them before the signal analysis below, otherwise a
        // thread-create would be misinterpreted as a breakpoint/single-step.
        if (WIFSTOPPED(nResult)) {
            const qint32 nEvent = (nResult >> 8);

            if (nEvent == (SIGTRAP | (PTRACE_EVENT_CLONE << 8))) {
                unsigned long nNewThreadId = 0;
                if (ptrace(PTRACE_GETEVENTMSG, nChildThreadId, 0, &nNewThreadId) != -1) {
                    result.nNewThreadId = (X_ID)nNewThreadId;
                }
                result.debuggerStatus = DEBUGGER_STATUS_THREADCREATE;
                return result;
            } else if (nEvent == (SIGTRAP | (PTRACE_EVENT_EXIT << 8))) {
                unsigned long nExitStatus = 0;
                ptrace(PTRACE_GETEVENTMSG, nChildThreadId, 0, &nExitStatus);
                result.nCode = (quint32)nExitStatus;
                result.debuggerStatus = DEBUGGER_STATUS_THREADEXIT;
                return result;
            }
        }
#endif

        if (WIFSTOPPED(nResult)) {
            result.nAddress = getXInfoDB()->getCurrentInstructionPointer_Id(nChildThreadId);
            result.nCode = WSTOPSIG(nResult);

            siginfo_t sigInfo = {};
            bool bHasSigInfo = false;

#if defined(Q_OS_LINUX)
            bHasSigInfo = (ptrace(PTRACE_GETSIGINFO, nChildThreadId, 0, &sigInfo) >= 0);
#endif

#if defined(Q_OS_LINUX)
            if (!bHasSigInfo) {
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
#else
            result.nExceptionAddress = result.nAddress;
#endif

            // Signal-specific si_code values overlap (for example TRAP_BRKPT and SEGV_MAPERR are
            // both 1), so trap codes are meaningful only when the actual stop signal is SIGTRAP.
            if (result.nCode == SIGTRAP) {
#if defined(Q_OS_LINUX)
                if (bHasSigInfo && (sigInfo.si_code == TRAP_TRACE)) {
                    result.debuggerStatus = DEBUGGER_STATUS_STEP;
                } else if (bHasSigInfo && (sigInfo.si_code == TRAP_BRKPT)) {
                    result.debuggerStatus = DEBUGGER_STATUS_BREAKPOINT;  // TODO // 0xF1 int1
                } else if (bHasSigInfo && (sigInfo.si_code == SI_KERNEL)) {
                    // result.nAddress = result.nAddress - 1;  // BP
                    result.debuggerStatus = DEBUGGER_STATUS_KERNEL;  // 0xCC int3, 0xF4 hlt
                } else {
                    result.debuggerStatus = DEBUGGER_STATUS_SIGTRAP;
                }
#else
                // Darwin's ptrace API has no PTRACE_GETSIGINFO equivalent. The pending debugger
                // bookkeeping distinguishes a requested single-step from a software trap.
                XInfoDB::BREAKPOINT stepBreakpoint = getXInfoDB()->findBreakPointByThreadID(nChildThreadId, XInfoDB::BPT_CODE_STEP_FLAG);
                XInfoDB::BREAKPOINT restoreBreakpoint = getXInfoDB()->findBreakPointByThreadID(nChildThreadId, XInfoDB::BPT_CODE_STEP_TO_RESTORE);
                result.debuggerStatus = (!stepBreakpoint.sUUID.isEmpty() || !restoreBreakpoint.sUUID.isEmpty()) ? DEBUGGER_STATUS_STEP
                                                                                                                : DEBUGGER_STATUS_BREAKPOINT;
#endif
            } else if (result.nCode == SIGABRT) {
                result.debuggerStatus = DEBUGGER_STATUS_STOP;
            } else {
                result.debuggerStatus = DEBUGGER_STATUS_EXCEPTION;
            }

            if (result.nCode == SIGABRT) {
                qDebug("process unexpectedly aborted");
            } else if (result.nCode == SIGPIPE) {
                qDebug("SIGPIPE");  // TODO Check IN/OUT HANDLES
            } else if (result.nCode == SIGTRAP) {
                qDebug("SIGTRAP");
            } else if (result.nCode == SIGSTOP) {
                qDebug("SIGSTOP");
            } else {
            }
            qDebug("!!!WSTOPSIG %x", result.nCode);
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
    } else if ((nChildThreadId < 0) && (errno == ECHILD)) {
        // No child processes
        // TODO
        stopDebugLoop();
    }

    return result;
}

bool XUnixDebugger::waitForSigchild()
{
#if defined(Q_OS_LINUX)
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
#else
    // Darwin has no sigtimedwait(). Its event loop polls waitpid(WNOHANG) directly.
    return false;
#endif
}

bool XUnixDebugger::_setStep(XProcess::HANDLEID handleID)
{
    bool bResult = false;
#if defined(Q_OS_LINUX)
    bResult = (ptrace(PTRACE_SINGLESTEP, handleID.nID, 0, 0) != -1);
#endif
#if defined(Q_OS_MACOS)
    // Darwin's ptrace step operation always chooses task_threads()[0].  Mach-backed
    // debuggers identify threads with stable THREAD_IDENTIFIER_INFO IDs, so set the
    // selected thread's hardware step state through XInfoDB instead.
    bResult = getXInfoDB()->_setStep_Id(static_cast<X_ID>(handleID.nID));
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
    if (g_bTerminationPending) {
        return false;
    }

    bool bResult = false;

    bResult = getXInfoDB()->stepInto_Id(nThreadId, bpInfo);

    if (bResult) {
        bResult = resumeAllThreads();
    }

    return bResult;
}

bool XUnixDebugger::stepOverById(X_ID nThreadId, XInfoDB::BPI bpInfo)
{
    if (g_bTerminationPending) {
        return false;
    }

    bool bResult = false;

    bResult = getXInfoDB()->stepOver_Id(nThreadId, bpInfo);

    if (bResult) {
        bResult = resumeAllThreads();
    }

    return bResult;
}

bool XUnixDebugger::stepInto()
{
    return stepIntoById(getXInfoDB()->getCurrentThreadId(), XInfoDB::BPI_STEPINTO);
}

bool XUnixDebugger::stepOver()
{
    return stepOverById(getXInfoDB()->getCurrentThreadId(), XInfoDB::BPI_STEPOVER);
}

void XUnixDebugger::_debugEvent()
{
    if (g_bTerminationPending) {
        _drainTermination(false);
        return;
    }

    if (isDebugActive()) {
        // bool bContinue = false;

        if (!waitForSigchild()) {
            // Wait for an event on ANY traced thread (-1), not only the main thread, so events on
            // sibling threads of a multithreaded target are reaped. __WALL also covers threads.
            qint32 nWaitOptions = WNOHANG;
#if defined(Q_OS_LINUX)
            nWaitOptions |= __WALL;
#ifdef __WNOTHREAD
            nWaitOptions |= __WNOTHREAD;
#endif
#endif
            qint64 nWaitTarget = -1;
#if defined(Q_OS_MACOS)
            // Darwin debugger threads are Mach objects, not waitpid children. Poll only the
            // debuggee PID so an unrelated QProcess child cannot be consumed as a debug event.
            nWaitTarget = getXInfoDB()->getProcessInfo()->nProcessID;
#endif
            STATE state = waitForSignal(nWaitTarget, nWaitOptions);

            if (state.bIsValid) {
                BPSTATUS result = BPSTATUS_UNKNOWN;

                // WIFEXITED/WIFSIGNALED describe a tracee that has actually gone away. On Linux
                // the thread-group leader can report its final status before sibling TIDs have
                // been reaped, so process completion is the last tracked thread, not PID == TID.
                // Darwin exposes one waitpid status for the whole process and completes directly.
                if ((state.debuggerStatus == DEBUGGER_STATUS_EXIT) || (state.debuggerStatus == DEBUGGER_STATUS_SIGNAL)) {
                    XInfoDB::PROCESS_INFO *pProcessInfo = getXInfoDB()->getProcessInfo();
#if defined(Q_OS_MACOS)
                    _completeProcessExit(pProcessInfo->nProcessID, state.nThreadId, state.nCode, pProcessInfo->sFileName);
#else
                    getXInfoDB()->removeThreadInfo(state.nThreadId);

                    if (getXInfoDB()->getThreadInfos()->isEmpty()) {
                        _completeProcessExit(pProcessInfo->nProcessID, state.nThreadId, state.nCode, pProcessInfo->sFileName);
                    } else {
                        if (getXInfoDB()->getCurrentThreadId() == state.nThreadId) {
                            getXInfoDB()->setCurrentThreadId(0);
                        }

                        XInfoDB::EXITTHREAD_INFO exitThreadInfo = {};
                        exitThreadInfo.nThreadID = state.nThreadId;
                        exitThreadInfo.nExitCode = state.nCode;
                        emit eventExitThread(&exitThreadInfo);
                    }
#endif

                    return;
                }

                // Every remaining status is a ptrace stop. Mark it paused before attempting to
                // continue it; resumeThread_Id intentionally refuses to continue running threads.
                getXInfoDB()->setThreadStatus(state.nThreadId, XInfoDB::THREAD_STATUS_PAUSED);

                // Thread-lifecycle events (from PTRACE_O_TRACECLONE / PTRACE_O_TRACEEXIT).
                if (state.debuggerStatus == DEBUGGER_STATUS_THREADCREATE) {
                    if (state.nNewThreadId) {
                        XInfoDB::THREAD_INFO threadInfo = {};
                        threadInfo.nThreadID = state.nNewThreadId;
                        threadInfo.threadStatus = XInfoDB::THREAD_STATUS_RUNNING;
                        getXInfoDB()->addThreadInfo(&threadInfo);

                        // Debug registers are per-thread: copy the parent thread's hardware
                        // breakpoints onto the new thread (technique from edb).
                        XInfoDB::XHARDWAREBP hardwareBP = getXInfoDB()->getHardwareBP_Id(state.nThreadId);
                        getXInfoDB()->setHardwareBP_Id(state.nNewThreadId, hardwareBP);

                        emit eventCreateThread(&threadInfo);
                    }
                    // The new thread's initial (SIGSTOP) stop is reaped by a later wait(-1) pass.
                    resumeThread(state.nThreadId);
                    return;
                } else if (state.debuggerStatus == DEBUGGER_STATUS_THREADEXIT) {
                    // PTRACE_EVENT_EXIT is a pre-exit stop. Continue it now; the following
                    // WIFEXITED/WIFSIGNALED status performs removal and emits exactly one event.
                    resumeThread(state.nThreadId);
                    return;
                }

                if (state.debuggerStatus == DEBUGGER_STATUS_STOP) {
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
                    result = _handleBreakpoint(state, getNativeSoftwareBreakpointType());
                } else if (state.debuggerStatus == DEBUGGER_STATUS_BREAKPOINT) {
                    qDebug("DEBUGGER_STATUS_BREAKPOINT");
                    result = _handleBreakpoint(state, getNativeSoftwareBreakpointType());
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

                // A DirectConnection script callback may request stop from inside
                // _handleBreakpoint(). Do not resume or mutate breakpoint state after SIGKILL;
                // the outer debug-event frame is now unwound enough to drain safely.
                if (g_bTerminationPending) {
                    finishPendingTermination();
                    return;
                }

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
                    qint32 nSignal = 0;

                    if (((state.debuggerStatus == DEBUGGER_STATUS_EXCEPTION) || (state.debuggerStatus == DEBUGGER_STATUS_STOP)) &&
                        (state.nCode != SIGSTOP)) {
                        // Preserve signal-delivery semantics for faults and ordinary signals. A
                        // debugger-generated SIGSTOP is deliberately suppressed when continuing.
                        nSignal = state.nCode;
                    }
#if defined(Q_OS_MACOS)
                    else if ((state.debuggerStatus == DEBUGGER_STATUS_BREAKPOINT) && (state.nCode == SIGTRAP)) {
                        // An INT3/BRK that is not ours must continue through Darwin's previous
                        // exception handler instead of being swallowed by the debugger.
                        nSignal = SIGTRAP;
                    }
#endif

                    if (!resumeThread(state.nThreadId, nSignal)) {
                        emit errorMessage(QString("%1 %2: %3").arg(tr("Cannot continue thread"))
                                              .arg(state.nThreadId)
                                              .arg(QString::fromLocal8Bit(strerror(errno))));
                    }
                } else if (result == BPSTATUS_HANDLED) {
                    resumeAllThreads();
                }
            }
        }
    }
}

XAbstractDebugger::BPSTATUS XUnixDebugger::_handleBreakpoint(STATE state, XInfoDB::BPT bpType)
{
    if (g_bTerminationPending) {
        return BPSTATUS_EXIT;
    }

    BPSTATUS result = BPSTATUS_UNKNOWN;

    XInfoDB::BREAKPOINT _currentBP = {};

    bool bSuccess = false;

    if (bpType == XInfoDB::BPT_CODE_SOFTWARE_INT3) {
        _currentBP = getXInfoDB()->findBreakPointByExceptionAddress(state.nAddress, bpType);
    } else if (bpType == XInfoDB::BPT_CODE_SOFTWARE_BRK) {
        _currentBP = getXInfoDB()->findBreakPointByAddress(state.nAddress, bpType);
    } else if ((bpType == XInfoDB::BPT_CODE_STEP_FLAG) || (bpType == XInfoDB::BPT_CODE_STEP_TO_RESTORE)) {
        _currentBP = getXInfoDB()->findBreakPointByThreadID(state.nThreadId, bpType);
    }

    if (_currentBP.sUUID != "") {
        bSuccess = true;
    }

    // TODO

    if (bSuccess) {
        getXInfoDB()->suspendAllThreads();

        if ((bpType == XInfoDB::BPT_CODE_SOFTWARE_INT1) || (bpType == XInfoDB::BPT_CODE_SOFTWARE_INT3) || (bpType == XInfoDB::BPT_CODE_SOFTWARE_BRK) ||
            (bpType == XInfoDB::BPT_CODE_SOFTWARE_UD2) ||
            (bpType == XInfoDB::BPT_CODE_SOFTWARE_HLT) || (bpType == XInfoDB::BPT_CODE_SOFTWARE_CLI) || (bpType == XInfoDB::BPT_CODE_SOFTWARE_STI) ||
            (bpType == XInfoDB::BPT_CODE_SOFTWARE_INSB) || (bpType == XInfoDB::BPT_CODE_SOFTWARE_INSD) || (bpType == XInfoDB::BPT_CODE_SOFTWARE_OUTSB) ||
            (bpType == XInfoDB::BPT_CODE_SOFTWARE_OUTSD) || (bpType == XInfoDB::BPT_CODE_SOFTWARE_INT3LONG)) {
            if ((bpType == XInfoDB::BPT_CODE_SOFTWARE_INT1) || (bpType == XInfoDB::BPT_CODE_SOFTWARE_INT3) || (bpType == XInfoDB::BPT_CODE_SOFTWARE_INT3LONG)) {
                getXInfoDB()->setCurrentIntructionPointer_Id(state.nThreadId, _currentBP.nAddress);  // go to prev instruction address
            }

            const bool bOriginalInstructionRestored = _currentBP.bOneShot ? getXInfoDB()->removeBreakPoint(_currentBP.sUUID)
                                                                          : getXInfoDB()->disableBreakPoint(_currentBP.sUUID);

            XInfoDB::BREAKPOINT_INFO breakPointInfo = {};
            breakPointInfo.nAddress = state.nAddress;
            breakPointInfo.nExceptionAddress = _currentBP.nAddress;
            breakPointInfo.nProcessID = getXInfoDB()->getProcessInfo()->nProcessID;
            breakPointInfo.nThreadID = state.nThreadId;
            breakPointInfo.bpType = _currentBP.bpType;
            breakPointInfo.bpInfo = _currentBP.bpInfo;
            breakPointInfo.vInfo = _currentBP.vInfo;

            _eventBreakPoint(&breakPointInfo);

            if (g_bTerminationPending) {
                return BPSTATUS_EXIT;
            }

            if (!bOriginalInstructionRestored) {
                emit errorMessage(QString("%1: 0x%2").arg(tr("Cannot restore software breakpoint")).arg(_currentBP.nAddress, 0, 16));
                return BPSTATUS_CALLBACK;
            }

            // mb TODO add it later
            if (!_currentBP.bOneShot) {
                XInfoDB::BREAKPOINT bp = {};
                bp.nAddress = _currentBP.nAddress;
                bp.nThreadID = state.nThreadId;
                bp.bpType = XInfoDB::BPT_CODE_STEP_TO_RESTORE;
                bp.vInfo = _currentBP.sUUID;
                if (!getXInfoDB()->addBreakPoint(bp)) {
                    emit errorMessage(QString("%1: 0x%2").arg(tr("Cannot single-step restored breakpoint")).arg(_currentBP.nAddress, 0, 16));
                }
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

            if (g_bTerminationPending) {
                return BPSTATUS_EXIT;
            }

            result = BPSTATUS_CALLBACK;
        } else if (bpType == XInfoDB::BPT_CODE_STEP_TO_RESTORE) {
            if (!getXInfoDB()->removeBreakPoint(_currentBP.sUUID)) {
                emit errorMessage(tr("Cannot finish breakpoint single-step"));
                return BPSTATUS_CALLBACK;
            }

            XInfoDB::BREAKPOINT _subBP = getXInfoDB()->findBreakPointByUUID(_currentBP.vInfo.toString());

            if (_subBP.sUUID != "") {
                XADDR nCurrentAddress = getXInfoDB()->getCurrentInstructionPointer_Id(state.nThreadId);
                bool bBreakpointRearmed = false;

                if ((nCurrentAddress >= _subBP.nAddress) && (nCurrentAddress < _subBP.nAddress + _subBP.nDataSize)) {
                    XInfoDB::BREAKPOINT bp = {};
                    bp.nAddress = nCurrentAddress;
                    bp.nThreadID = state.nThreadId;
                    bp.bpType = XInfoDB::BPT_CODE_STEP_TO_RESTORE;
                    bp.vInfo = _subBP.sUUID;
                    bBreakpointRearmed = getXInfoDB()->addBreakPoint(bp);
                } else {
                    bBreakpointRearmed = getXInfoDB()->enableBreakPoint(_subBP.sUUID);
                }

                if (!bBreakpointRearmed) {
                    emit errorMessage(QString("%1: 0x%2").arg(tr("Cannot rearm software breakpoint")).arg(_subBP.nAddress, 0, 16));
                    return BPSTATUS_CALLBACK;
                }
            }

            result = BPSTATUS_HANDLED;
        }
    }

    return result;
}
