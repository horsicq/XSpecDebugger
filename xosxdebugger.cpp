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
#include "xosxdebugger.h"

#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QVector>
#if QT_VERSION < QT_VERSION_CHECK(5, 15, 0)
#include <QRegExp>
#endif

#include <crt_externs.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/ndr.h>
#include <signal.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
enum CHILD_LAUNCH_STAGE {
    CHILD_LAUNCH_STAGE_UNKNOWN = 0,
    CHILD_LAUNCH_STAGE_PTRACE,
    CHILD_LAUNCH_STAGE_SIGEXC,
    CHILD_LAUNCH_STAGE_CHDIR,
    CHILD_LAUNCH_STAGE_EXECVE
};

union DARWIN_MACH_MESSAGE {
    mach_msg_header_t header;
    char data[1024];
};

struct DARWIN_EXCEPTION_CAPTURE {
    task_t hExpectedTask;
    task_t hTask;
    thread_act_t hThread;
    exception_type_t exceptionType;
    QVector<mach_exception_data_type_t> listCodes;
};

struct DARWIN_EXCEPTION_MESSAGE {
    DARWIN_MACH_MESSAGE request;
    DARWIN_MACH_MESSAGE reply;
    DARWIN_EXCEPTION_CAPTURE capture;
    X_ID nThreadId;
};

struct DARWIN_MIG_REPLY_ERROR {
    mach_msg_header_t header;
    NDR_record_t ndr;
    kern_return_t result;
};

DARWIN_EXCEPTION_CAPTURE *g_pExceptionCapture = nullptr;

void copyExceptionCodes(QVector<mach_exception_data_type_t> *pCodes, mach_exception_data_t pData, mach_msg_type_number_t nCodeCount)
{
    pCodes->clear();
    pCodes->reserve(static_cast<qint32>(nCodeCount));

    for (mach_msg_type_number_t i = 0; i < nCodeCount; i++) {
        mach_exception_data_type_t nCode = 0;
        memcpy(&nCode, reinterpret_cast<const char *>(pData) + (i * sizeof(nCode)), sizeof(nCode));
        pCodes->append(nCode);
    }
}

kern_return_t getThreadIdentifier(thread_act_t hThread, X_ID *pThreadId)
{
    thread_identifier_info_data_t identifierInfo = {};
    mach_msg_type_number_t nInfoCount = THREAD_IDENTIFIER_INFO_COUNT;
    const kern_return_t result = thread_info(hThread, THREAD_IDENTIFIER_INFO, reinterpret_cast<thread_info_t>(&identifierInfo), &nInfoCount);

    if ((result == KERN_SUCCESS) && pThreadId) {
        *pThreadId = static_cast<X_ID>(identifierInfo.thread_id);
    }

    return result;
}

void setReplyResult(DARWIN_EXCEPTION_MESSAGE *pMessage, kern_return_t result)
{
    if (pMessage->reply.header.msgh_size >= sizeof(DARWIN_MIG_REPLY_ERROR)) {
        reinterpret_cast<DARWIN_MIG_REPLY_ERROR *>(&pMessage->reply)->result = result;
    }
}

kern_return_t sendExceptionReply(DARWIN_EXCEPTION_MESSAGE *pMessage)
{
    return mach_msg(&pMessage->reply.header, MACH_SEND_MSG | MACH_SEND_INTERRUPT, pMessage->reply.header.msgh_size, 0, MACH_PORT_NULL,
                    MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
}

struct CHILD_LAUNCH_ERROR {
    qint32 nStage;
    qint32 nError;
};

void writeChildLaunchError(qint32 nFileDescriptor, CHILD_LAUNCH_STAGE stage, qint32 nError)
{
    CHILD_LAUNCH_ERROR launchError = {};
    launchError.nStage = stage;
    launchError.nError = nError;

    const char *pData = reinterpret_cast<const char *>(&launchError);
    size_t nRemaining = sizeof(launchError);

    while (nRemaining) {
        ssize_t nWritten = ::write(nFileDescriptor, pData, nRemaining);

        if (nWritten > 0) {
            pData += nWritten;
            nRemaining -= (size_t)nWritten;
        } else if ((nWritten == -1) && (errno == EINTR)) {
            continue;
        } else {
            break;
        }
    }
}

void reapChild(pid_t nProcessID)
{
    qint32 nStatus = 0;
    pid_t nWaitResult = 0;

    do {
        nWaitResult = ::waitpid(nProcessID, &nStatus, 0);
    } while ((nWaitResult == -1) && (errno == EINTR));
}

void terminateAndReapChild(pid_t nProcessID)
{
    if ((::kill(nProcessID, SIGKILL) == -1) && (errno != ESRCH)) {
#ifdef QT_DEBUG
        qDebug("Cannot terminate child: %s", strerror(errno));
#endif
    }

    reapChild(nProcessID);
}
}  // namespace

extern "C" boolean_t mach_exc_server(mach_msg_header_t *pRequest, mach_msg_header_t *pReply);

extern "C" kern_return_t catch_mach_exception_raise(mach_port_t hExceptionPort, mach_port_t hThread, mach_port_t hTask,
                                                     exception_type_t exceptionType, mach_exception_data_t pCodes,
                                                     mach_msg_type_number_t nCodeCount)
{
    Q_UNUSED(hExceptionPort)

    if ((g_pExceptionCapture == nullptr) || (hTask != g_pExceptionCapture->hExpectedTask)) {
        return KERN_FAILURE;
    }

    g_pExceptionCapture->hTask = hTask;
    g_pExceptionCapture->hThread = hThread;
    g_pExceptionCapture->exceptionType = exceptionType;
    copyExceptionCodes(&g_pExceptionCapture->listCodes, pCodes, nCodeCount);

    return KERN_SUCCESS;
}

extern "C" kern_return_t catch_mach_exception_raise_state(mach_port_t hExceptionPort, exception_type_t exceptionType,
                                                           const mach_exception_data_t pCodes, mach_msg_type_number_t nCodeCount, int *pFlavor,
                                                           const thread_state_t pOldState, mach_msg_type_number_t nOldStateCount,
                                                           thread_state_t pNewState, mach_msg_type_number_t *pNewStateCount)
{
    Q_UNUSED(hExceptionPort)
    Q_UNUSED(exceptionType)
    Q_UNUSED(pCodes)
    Q_UNUSED(nCodeCount)
    Q_UNUSED(pFlavor)
    Q_UNUSED(pOldState)
    Q_UNUSED(nOldStateCount)
    Q_UNUSED(pNewState)
    Q_UNUSED(pNewStateCount)

    return KERN_FAILURE;
}

extern "C" kern_return_t catch_mach_exception_raise_state_identity(
    mach_port_t hExceptionPort, mach_port_t hThread, mach_port_t hTask, exception_type_t exceptionType, mach_exception_data_t pCodes,
    mach_msg_type_number_t nCodeCount, int *pFlavor, thread_state_t pOldState, mach_msg_type_number_t nOldStateCount, thread_state_t pNewState,
    mach_msg_type_number_t *pNewStateCount)
{
    Q_UNUSED(hExceptionPort)
    Q_UNUSED(hThread)
    Q_UNUSED(hTask)
    Q_UNUSED(exceptionType)
    Q_UNUSED(pCodes)
    Q_UNUSED(nCodeCount)
    Q_UNUSED(pFlavor)
    Q_UNUSED(pOldState)
    Q_UNUSED(nOldStateCount)
    Q_UNUSED(pNewState)
    Q_UNUSED(pNewStateCount)

    return KERN_FAILURE;
}

struct XOSXDebugger::DARWIN_STATE {
    task_t hTask = MACH_PORT_NULL;
    mach_port_t hExceptionPort = MACH_PORT_NULL;
    exception_mask_t exceptionMask = EXC_MASK_SOFTWARE | EXC_MASK_BREAKPOINT;
    exception_mask_t savedMasks[EXC_TYPES_COUNT] = {};
    mach_port_t savedPorts[EXC_TYPES_COUNT] = {};
    exception_behavior_t savedBehaviors[EXC_TYPES_COUNT] = {};
    thread_state_flavor_t savedFlavors[EXC_TYPES_COUNT] = {};
    mach_msg_type_number_t nSavedPortCount = 0;
    QList<DARWIN_EXCEPTION_MESSAGE> listQueuedMessages;
    DARWIN_EXCEPTION_MESSAGE currentMessage = {};
    QList<X_ID> listStepSuspendedThreadIds;
    bool bCurrentMessage = false;
    bool bTaskSuspended = false;
    bool bInitialPtraceStop = false;
};

XOSXDebugger::XOSXDebugger(QObject *pParent, XInfoDB *pXInfoDB) : XUnixDebugger(pParent, pXInfoDB)
{
}

bool XOSXDebugger::load()
{
    QString sFileName = getOptions()->sFileName;
    QString sDirectory = getOptions()->sDirectory;
    setDebugActive(false);

    if (!XBinary::isFileExists(sFileName)) {
        emit errorMessage(QString("%1: %2").arg(tr("Cannot load file"), sFileName));
        return false;
    }

    // Build all Qt-backed data before fork(). The child uses only async-signal-safe system calls
    // before execve(), avoiding allocator locks inherited from other threads.
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

    QList<QByteArray> listArgumentData;
    for (const QString &sArgument : listArguments) {
        listArgumentData.append(QFile::encodeName(sArgument));
    }

    QVector<char *> listArgumentPointers;
    for (qint32 i = 0; i < listArgumentData.count(); i++) {
        listArgumentPointers.append(listArgumentData[i].data());
    }
    listArgumentPointers.append(nullptr);

    QList<QByteArray> listEnvironmentData;
    char **ppInheritedEnvironment = *_NSGetEnviron();
    for (char **ppEnvironment = ppInheritedEnvironment; ppEnvironment && *ppEnvironment; ppEnvironment++) {
        listEnvironmentData.append(QByteArray(*ppEnvironment));
    }

    QVector<char *> listEnvironmentPointers;
    for (qint32 i = 0; i < listEnvironmentData.count(); i++) {
        listEnvironmentPointers.append(listEnvironmentData[i].data());
    }
    listEnvironmentPointers.append(nullptr);

    QByteArray baFileName = QFile::encodeName(sFileName);
    QByteArray baDirectory = QFile::encodeName(sDirectory);
    const bool bHasDirectory = !baDirectory.isEmpty();
    char *pFileName = baFileName.data();
    char *pDirectory = baDirectory.data();
    char **ppArguments = listArgumentPointers.data();
    char **ppEnvironment = listEnvironmentPointers.data();

    qint32 anLaunchPipe[2] = {-1, -1};
    if (::pipe(anLaunchPipe) == -1) {
        emit errorMessage(QString("%1: %2").arg(tr("Cannot create launch pipe"), QString::fromLocal8Bit(strerror(errno))));
        return false;
    }

    qint32 nDescriptorFlags = ::fcntl(anLaunchPipe[1], F_GETFD);
    if ((nDescriptorFlags == -1) || (::fcntl(anLaunchPipe[1], F_SETFD, nDescriptorFlags | FD_CLOEXEC) == -1)) {
        qint32 nPipeError = errno;
        ::close(anLaunchPipe[0]);
        ::close(anLaunchPipe[1]);
        emit errorMessage(QString("%1: %2").arg(tr("Cannot configure launch pipe"), QString::fromLocal8Bit(strerror(nPipeError))));
        return false;
    }

    pid_t nProcessID = ::fork();

    if (nProcessID == 0) {
        // Closing the CLOEXEC descriptor is the success handshake. Every controlled failure
        // writes one fixed-size record and exits without invoking Qt in the forked child.
        ::close(anLaunchPipe[0]);

        if (::ptrace(PT_TRACE_ME, 0, 0, 0) == -1) {
            qint32 nError = errno;
            writeChildLaunchError(anLaunchPipe[1], CHILD_LAUNCH_STAGE_PTRACE, nError);
            ::_exit(127);
        }

        if (bHasDirectory && (::chdir(pDirectory) == -1)) {
            qint32 nError = errno;
            writeChildLaunchError(anLaunchPipe[1], CHILD_LAUNCH_STAGE_CHDIR, nError);
            ::_exit(127);
        }

        ::execve(pFileName, ppArguments, ppEnvironment);

        qint32 nError = errno;
        writeChildLaunchError(anLaunchPipe[1], CHILD_LAUNCH_STAGE_EXECVE, nError);
        ::_exit(127);
    }

    qint32 nForkError = errno;
    ::close(anLaunchPipe[1]);

    if (nProcessID < 0) {
        ::close(anLaunchPipe[0]);
        emit errorMessage(QString("%1: %2").arg(tr("Cannot fork"), QString::fromLocal8Bit(strerror(nForkError))));
        return false;
    }

    CHILD_LAUNCH_ERROR launchError = {};
    char *pLaunchError = reinterpret_cast<char *>(&launchError);
    size_t nErrorBytes = 0;
    qint32 nReadError = 0;

    while (nErrorBytes < sizeof(launchError)) {
        ssize_t nRead = ::read(anLaunchPipe[0], pLaunchError + nErrorBytes, sizeof(launchError) - nErrorBytes);

        if (nRead > 0) {
            nErrorBytes += (size_t)nRead;
        } else if (nRead == 0) {
            break;
        } else if (errno == EINTR) {
            continue;
        } else {
            nReadError = errno;
            break;
        }
    }

    ::close(anLaunchPipe[0]);

    if (nReadError) {
        terminateAndReapChild(nProcessID);
        emit errorMessage(QString("%1: %2").arg(tr("Cannot read launch status"), QString::fromLocal8Bit(strerror(nReadError))));
        return false;
    }

    if (nErrorBytes) {
        if (nErrorBytes != sizeof(launchError)) {
            terminateAndReapChild(nProcessID);
            emit errorMessage(tr("Invalid child launch status"));
            return false;
        }

        QString sOperation;
        if (launchError.nStage == CHILD_LAUNCH_STAGE_PTRACE) {
            sOperation = "ptrace(PT_TRACE_ME)";
        } else if (launchError.nStage == CHILD_LAUNCH_STAGE_CHDIR) {
            sOperation = "chdir";
        } else if (launchError.nStage == CHILD_LAUNCH_STAGE_EXECVE) {
            sOperation = "execve";
        } else {
            sOperation = tr("Child launch");
        }

        reapChild(nProcessID);
        emit errorMessage(QString("%1: %2").arg(sOperation, QString::fromLocal8Bit(strerror(launchError.nError))));
        return false;
    }

    STATE stateStart = waitForSignal(nProcessID, 0);
    if ((!stateStart.bIsValid) ||
        ((stateStart.debuggerStatus != DEBUGGER_STATUS_SIGTRAP) && (stateStart.debuggerStatus != DEBUGGER_STATUS_BREAKPOINT))) {
        terminateAndReapChild(nProcessID);
        emit errorMessage(tr("The child did not stop after execve"));
        return false;
    }

    XInfoDB::PROCESS_INFO processInfo = {};
    processInfo.nProcessID = nProcessID;
    processInfo.nMainThreadID = nProcessID;
    processInfo.sFileName = sFileName;
    processInfo.sBaseFileName = QFileInfo(sFileName).fileName();
    processInfo.hProcess = XProcess::openProcess(nProcessID);

    if (!processInfo.hProcess) {
        terminateAndReapChild(nProcessID);
        emit errorMessage(tr("Cannot open the child task port"));
        return false;
    }

    getXInfoDB()->setProcessInfo(processInfo);
    setDebugActive(true);
    emit eventCreateProcess(&processInfo);

    XInfoDB::THREAD_INFO threadInfo = {};
    threadInfo.nThreadID = nProcessID;
    threadInfo.threadStatus = XInfoDB::THREAD_STATUS_PAUSED;
    getXInfoDB()->addThreadInfo(&threadInfo);
    emit eventCreateThread(&threadInfo);

    getXInfoDB()->setThreadStatus(stateStart.nThreadId, XInfoDB::THREAD_STATUS_PAUSED);

    XInfoDB::BREAKPOINT_INFO breakPointInfo = {};
    breakPointInfo.nExceptionAddress = getXInfoDB()->getCurrentInstructionPointer_Id(nProcessID);
    breakPointInfo.bpType = XInfoDB::BPT_PROCESS_STOP;
    breakPointInfo.bpInfo = XInfoDB::BPI_PROCESSENTRYPOINT;
    breakPointInfo.hProcess = getXInfoDB()->getProcessInfo()->hProcess;
    breakPointInfo.nProcessID = getXInfoDB()->getProcessInfo()->nProcessID;
    breakPointInfo.nThreadID = getXInfoDB()->getProcessInfo()->nMainThreadID;

    _eventBreakPoint(&breakPointInfo);
    startDebugLoop();

    return true;
}

bool XOSXDebugger::attach()
{
    emit errorMessage(tr("Attaching to an existing process is not supported on macOS"));
    return false;
}

void XOSXDebugger::cleanUp()
{
    XUnixDebugger::cleanUp();

    XInfoDB::PROCESS_INFO *pProcessInfo = getXInfoDB()->getProcessInfo();
    if (pProcessInfo->hProcess) {
        mach_port_deallocate(mach_task_self(), pProcessInfo->hProcess);
        pProcessInfo->hProcess = MACH_PORT_NULL;
    }
}

QString XOSXDebugger::getArch()
{
#ifdef Q_PROCESSOR_ARM_64
    return "ARM64";
#elif defined(Q_PROCESSOR_X86_64)
    return "AMD64";
#else
    return QSysInfo::currentCpuArchitecture();
#endif
}

XBinary::MODE XOSXDebugger::getMode()
{
    return (sizeof(void *) == 8) ? XBinary::MODE_64 : XBinary::MODE_32;
}
