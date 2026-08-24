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
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/ndr.h>
#if defined(Q_PROCESSOR_X86_64)
#include <mach/i386/exception.h>
#elif defined(Q_PROCESSOR_ARM_64)
#include <mach/arm/exception.h>
#endif
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

XOSXDebugger::XOSXDebugger(QObject *pParent, XInfoDB *pXInfoDB) : XUnixDebugger(pParent, pXInfoDB), m_pDarwinState(new DARWIN_STATE)
{
}

XOSXDebugger::~XOSXDebugger()
{
    shutdownExceptionPort(true);
    delete m_pDarwinState;
}

bool XOSXDebugger::installExceptionPort(task_t hTask)
{
    shutdownExceptionPort(false);

    m_pDarwinState->hTask = hTask;
    kern_return_t result = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &m_pDarwinState->hExceptionPort);

    if (result == KERN_SUCCESS) {
        result = mach_port_insert_right(mach_task_self(), m_pDarwinState->hExceptionPort, m_pDarwinState->hExceptionPort, MACH_MSG_TYPE_MAKE_SEND);
    }

    if (result == KERN_SUCCESS) {
        m_pDarwinState->nSavedPortCount = EXC_TYPES_COUNT;
        result = task_get_exception_ports(hTask, m_pDarwinState->exceptionMask, m_pDarwinState->savedMasks,
                                          &m_pDarwinState->nSavedPortCount, m_pDarwinState->savedPorts,
                                          m_pDarwinState->savedBehaviors, m_pDarwinState->savedFlavors);
        if (result != KERN_SUCCESS) {
            m_pDarwinState->nSavedPortCount = 0;
        }
    }

    if (result == KERN_SUCCESS) {
        result = task_set_exception_ports(hTask, m_pDarwinState->exceptionMask, m_pDarwinState->hExceptionPort,
                                          EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, THREAD_STATE_NONE);
    }

    if (result != KERN_SUCCESS) {
        shutdownExceptionPort(false);
        return false;
    }

    m_pDarwinState->bInitialPtraceStop = true;
    return true;
}

void XOSXDebugger::shutdownExceptionPort(bool bForwardPending)
{
    if (m_pDarwinState == nullptr) {
        return;
    }

    if ((m_pDarwinState->hTask != MACH_PORT_NULL) && m_pDarwinState->nSavedPortCount) {
        for (mach_msg_type_number_t i = 0; i < m_pDarwinState->nSavedPortCount; i++) {
            task_set_exception_ports(m_pDarwinState->hTask, m_pDarwinState->savedMasks[i], m_pDarwinState->savedPorts[i],
                                     m_pDarwinState->savedBehaviors[i], m_pDarwinState->savedFlavors[i]);
        }
    }

    if (bForwardPending) {
        if (m_pDarwinState->bCurrentMessage) {
            setReplyResult(&m_pDarwinState->currentMessage, KERN_FAILURE);
            sendExceptionReply(&m_pDarwinState->currentMessage);
        }

        for (DARWIN_EXCEPTION_MESSAGE &message : m_pDarwinState->listQueuedMessages) {
            setReplyResult(&message, KERN_FAILURE);
            sendExceptionReply(&message);
        }
    }

    m_pDarwinState->bCurrentMessage = false;
    m_pDarwinState->listQueuedMessages.clear();
    releaseSingleStepIsolation();

    if (m_pDarwinState->bTaskSuspended && (m_pDarwinState->hTask != MACH_PORT_NULL)) {
        task_resume(m_pDarwinState->hTask);
    }
    m_pDarwinState->bTaskSuspended = false;

    for (mach_msg_type_number_t i = 0; i < m_pDarwinState->nSavedPortCount; i++) {
        if (MACH_PORT_VALID(m_pDarwinState->savedPorts[i])) {
            mach_port_deallocate(mach_task_self(), m_pDarwinState->savedPorts[i]);
        }
    }
    m_pDarwinState->nSavedPortCount = 0;

    if (MACH_PORT_VALID(m_pDarwinState->hExceptionPort)) {
        mach_port_destroy(mach_task_self(), m_pDarwinState->hExceptionPort);
    }

    m_pDarwinState->hExceptionPort = MACH_PORT_NULL;
    m_pDarwinState->hTask = MACH_PORT_NULL;
    m_pDarwinState->bInitialPtraceStop = false;
}

bool XOSXDebugger::syncDarwinThreads(X_ID nStoppedThreadId)
{
    QList<X_ID> listThreadIds;
    if (!getXInfoDB()->updateDarwinThreadPorts(&listThreadIds)) {
        return false;
    }

    const QList<XInfoDB::THREAD_INFO> listPreviousThreads = *(getXInfoDB()->getThreadInfos());

    for (X_ID nThreadId : listThreadIds) {
        XInfoDB::THREAD_INFO threadInfo = getXInfoDB()->findThreadInfoByID(nThreadId);

        if (!threadInfo.nThreadID) {
            threadInfo.nThreadID = nThreadId;
            threadInfo.threadStatus = XInfoDB::THREAD_STATUS_PAUSED;
            getXInfoDB()->addThreadInfo(&threadInfo);
            emit eventCreateThread(&threadInfo);
        } else if (m_pDarwinState->bTaskSuspended) {
            getXInfoDB()->setThreadStatus(nThreadId, XInfoDB::THREAD_STATUS_PAUSED);
        }
    }

    for (const XInfoDB::THREAD_INFO &threadInfo : listPreviousThreads) {
        if (!listThreadIds.contains(threadInfo.nThreadID)) {
            getXInfoDB()->removeThreadInfo(threadInfo.nThreadID);

            XInfoDB::EXITTHREAD_INFO exitThreadInfo = {};
            exitThreadInfo.nThreadID = threadInfo.nThreadID;
            emit eventExitThread(&exitThreadInfo);
        }
    }

    if (nStoppedThreadId && !listThreadIds.contains(nStoppedThreadId)) {
        return false;
    }

    return true;
}

bool XOSXDebugger::receiveException(STATE *pState)
{
    if ((pState == nullptr) || !MACH_PORT_VALID(m_pDarwinState->hExceptionPort) || m_pDarwinState->bCurrentMessage) {
        return false;
    }

    auto promoteMessage = [&]() -> bool {
        if (m_pDarwinState->listQueuedMessages.isEmpty()) {
            return false;
        }

        m_pDarwinState->currentMessage = m_pDarwinState->listQueuedMessages.takeFirst();
        m_pDarwinState->bCurrentMessage = true;
        const DARWIN_EXCEPTION_CAPTURE &capture = m_pDarwinState->currentMessage.capture;

        *pState = {};
        pState->bIsValid = true;
        pState->nThreadId = m_pDarwinState->currentMessage.nThreadId;
        pState->nCode = SIGTRAP;
        pState->nAddress = getXInfoDB()->getCurrentInstructionPointer_Id(pState->nThreadId);
        pState->nExceptionAddress = pState->nAddress;

        if ((capture.exceptionType == EXC_SOFTWARE) && (capture.listCodes.count() >= 2) &&
            (capture.listCodes.at(0) == EXC_SOFT_SIGNAL)) {
            pState->nCode = static_cast<quint32>(capture.listCodes.at(1));
            pState->debuggerStatus = ((pState->nCode == SIGSTOP) || (pState->nCode == SIGABRT)) ? DEBUGGER_STATUS_STOP
                                                                                               : DEBUGGER_STATUS_EXCEPTION;
        } else if (capture.exceptionType == EXC_BREAKPOINT) {
            const bool bPendingStep =
                !getXInfoDB()->findBreakPointByThreadID(pState->nThreadId, XInfoDB::BPT_CODE_STEP_FLAG).sUUID.isEmpty() ||
                !getXInfoDB()->findBreakPointByThreadID(pState->nThreadId, XInfoDB::BPT_CODE_STEP_TO_RESTORE).sUUID.isEmpty();
            bool bHardwareStep = bPendingStep;
#if defined(Q_PROCESSOR_X86_64)
            bHardwareStep = bHardwareStep || (!capture.listCodes.isEmpty() && (capture.listCodes.at(0) == EXC_I386_SGL));
#endif
            pState->debuggerStatus = bHardwareStep ? DEBUGGER_STATUS_STEP : DEBUGGER_STATUS_BREAKPOINT;

            if (bHardwareStep && !getXInfoDB()->_setStep_Id(pState->nThreadId, false)) {
                emit errorMessage(QString("%1 %2").arg(tr("Cannot clear single-step state for thread")).arg(pState->nThreadId));
            }
        } else {
            pState->nCode = 0;
            pState->debuggerStatus = DEBUGGER_STATUS_EXCEPTION;
        }

        return true;
    };

    if (promoteMessage()) {
        return true;
    }

    bool bReceivedAny = false;

    while (true) {
        DARWIN_EXCEPTION_MESSAGE message = {};
        message.capture.hExpectedTask = m_pDarwinState->hTask;
        const kern_return_t receiveResult = mach_msg(&message.request.header,
                                                     MACH_RCV_MSG | MACH_RCV_INTERRUPT | MACH_RCV_TIMEOUT,
                                                     0, sizeof(message.request.data), m_pDarwinState->hExceptionPort, 0, MACH_PORT_NULL);

        if (receiveResult == MACH_RCV_TIMED_OUT) {
            break;
        }
        if (receiveResult != KERN_SUCCESS) {
            return false;
        }

        g_pExceptionCapture = &message.capture;
        const bool bDemultiplexed = mach_exc_server(&message.request.header, &message.reply.header);
        g_pExceptionCapture = nullptr;

        if (!bDemultiplexed || (message.capture.hThread == MACH_PORT_NULL) ||
            (getThreadIdentifier(message.capture.hThread, &message.nThreadId) != KERN_SUCCESS) || !message.nThreadId) {
            if (bDemultiplexed) {
                setReplyResult(&message, KERN_FAILURE);
                sendExceptionReply(&message);
            } else {
                mach_msg_destroy(&message.request.header);
            }
            continue;
        }

        if (!m_pDarwinState->bTaskSuspended) {
            if (task_suspend(m_pDarwinState->hTask) != KERN_SUCCESS) {
                setReplyResult(&message, KERN_FAILURE);
                sendExceptionReply(&message);
                continue;
            }
            m_pDarwinState->bTaskSuspended = true;
            releaseSingleStepIsolation();
        }

        m_pDarwinState->listQueuedMessages.append(message);
        bReceivedAny = true;
    }

    if (bReceivedAny) {
        const X_ID nStoppedThreadId = m_pDarwinState->listQueuedMessages.first().nThreadId;
        if (!syncDarwinThreads(nStoppedThreadId)) {
            emit errorMessage(tr("Cannot refresh Darwin thread ports after an exception"));
        }
    }

    return promoteMessage();
}

void XOSXDebugger::releaseSingleStepIsolation()
{
    if (m_pDarwinState->listStepSuspendedThreadIds.isEmpty()) {
        return;
    }

    thread_act_array_t pThreads = nullptr;
    mach_msg_type_number_t nThreadCount = 0;

    if ((m_pDarwinState->hTask != MACH_PORT_NULL) &&
        (task_threads(m_pDarwinState->hTask, &pThreads, &nThreadCount) == KERN_SUCCESS)) {
        for (mach_msg_type_number_t i = 0; i < nThreadCount; i++) {
            X_ID nThreadId = 0;
            if ((getThreadIdentifier(pThreads[i], &nThreadId) == KERN_SUCCESS) &&
                m_pDarwinState->listStepSuspendedThreadIds.contains(nThreadId)) {
                thread_resume(pThreads[i]);
            }
            mach_port_deallocate(mach_task_self(), pThreads[i]);
        }

        if (pThreads) {
            vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(pThreads), static_cast<vm_size_t>(nThreadCount) * sizeof(*pThreads));
        }
    }

    m_pDarwinState->listStepSuspendedThreadIds.clear();
}

bool XOSXDebugger::prepareSingleStepIsolation(X_ID *pStepThreadId)
{
    if (pStepThreadId) {
        *pStepThreadId = 0;
    }

    releaseSingleStepIsolation();

    QList<X_ID> listThreadIds;
    if (!getXInfoDB()->updateDarwinThreadPorts(&listThreadIds)) {
        return false;
    }

    X_ID nStepThreadId = 0;
    for (X_ID nThreadId : listThreadIds) {
        const bool bStep = !getXInfoDB()->findBreakPointByThreadID(nThreadId, XInfoDB::BPT_CODE_STEP_FLAG).sUUID.isEmpty() ||
                           !getXInfoDB()->findBreakPointByThreadID(nThreadId, XInfoDB::BPT_CODE_STEP_TO_RESTORE).sUUID.isEmpty();
        if (bStep) {
            nStepThreadId = nThreadId;
            break;
        }
    }

    if (!nStepThreadId) {
        return true;
    }

    thread_act_array_t pThreads = nullptr;
    mach_msg_type_number_t nThreadCount = 0;
    if (task_threads(m_pDarwinState->hTask, &pThreads, &nThreadCount) != KERN_SUCCESS) {
        return false;
    }

    bool bResult = true;
    for (mach_msg_type_number_t i = 0; i < nThreadCount; i++) {
        X_ID nThreadId = 0;
        if ((getThreadIdentifier(pThreads[i], &nThreadId) != KERN_SUCCESS) || !nThreadId) {
            bResult = false;
        } else if ((nThreadId != nStepThreadId) && (thread_suspend(pThreads[i]) == KERN_SUCCESS)) {
            m_pDarwinState->listStepSuspendedThreadIds.append(nThreadId);
        } else if (nThreadId != nStepThreadId) {
            bResult = false;
        }

        mach_port_deallocate(mach_task_self(), pThreads[i]);
    }

    if (pThreads) {
        vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(pThreads), static_cast<vm_size_t>(nThreadCount) * sizeof(*pThreads));
    }

    if (!bResult) {
        releaseSingleStepIsolation();
        return false;
    }

    if (pStepThreadId) {
        *pStepThreadId = nStepThreadId;
    }

    return true;
}

bool XOSXDebugger::replyCurrentException(qint32 nSignal, bool bForwardException)
{
    if (!m_pDarwinState->bCurrentMessage) {
        return false;
    }

    DARWIN_EXCEPTION_MESSAGE &message = m_pDarwinState->currentMessage;
    const bool bSoftSignal = (message.capture.exceptionType == EXC_SOFTWARE) && (message.capture.listCodes.count() >= 2) &&
                             (message.capture.listCodes.at(0) == EXC_SOFT_SIGNAL);

    if (bSoftSignal &&
        (ptrace(PT_THUPDATE, getXInfoDB()->getProcessInfo()->nProcessID,
                reinterpret_cast<caddr_t>(static_cast<uintptr_t>(message.capture.hThread)), nSignal) == -1)) {
        return false;
    }

    setReplyResult(&message, bForwardException ? KERN_FAILURE : KERN_SUCCESS);
    if (sendExceptionReply(&message) != KERN_SUCCESS) {
        return false;
    }

    m_pDarwinState->bCurrentMessage = false;
    return true;
}

bool XOSXDebugger::continueAfterException(X_ID nThreadId, qint32 nSignal, bool bAllThreads)
{
    Q_UNUSED(bAllThreads)

    if (m_pDarwinState->bCurrentMessage) {
        if (m_pDarwinState->currentMessage.nThreadId != nThreadId) {
            return false;
        }

        const bool bForwardException = (m_pDarwinState->currentMessage.capture.exceptionType == EXC_BREAKPOINT) && (nSignal != 0);
        if (!replyCurrentException(nSignal, bForwardException)) {
            return false;
        }

        // Keep the task frozen while each simultaneously queued stop is surfaced through the
        // common event path. No exception reply is lost or silently swallowed.
        if (!m_pDarwinState->listQueuedMessages.isEmpty()) {
            return true;
        }
    }

    X_ID nStepThreadId = 0;
    if (!prepareSingleStepIsolation(&nStepThreadId)) {
        return false;
    }

    bool bResult = false;
    if (m_pDarwinState->bTaskSuspended) {
        bResult = (task_resume(m_pDarwinState->hTask) == KERN_SUCCESS);
        if (bResult) {
            m_pDarwinState->bTaskSuspended = false;
        }
    } else if (m_pDarwinState->bInitialPtraceStop) {
        bResult = (ptrace(PT_CONTINUE, getXInfoDB()->getProcessInfo()->nProcessID, (caddr_t)1, nSignal) != -1);
        if (bResult) {
            m_pDarwinState->bInitialPtraceStop = false;
        }
    }

    if (!bResult) {
        releaseSingleStepIsolation();
        return false;
    }

    const QList<XInfoDB::THREAD_INFO> listThreadInfos = *(getXInfoDB()->getThreadInfos());
    for (const XInfoDB::THREAD_INFO &threadInfo : listThreadInfos) {
        const XInfoDB::THREAD_STATUS status = (!nStepThreadId || (threadInfo.nThreadID == nStepThreadId)) ? XInfoDB::THREAD_STATUS_RUNNING
                                                                                                         : XInfoDB::THREAD_STATUS_PAUSED;
        getXInfoDB()->setThreadStatus(threadInfo.nThreadID, status);
    }

    return true;
}

XUnixDebugger::STATE XOSXDebugger::waitForSignal(qint64 nThreadID, qint32 nOptions)
{
    STATE result = {};
    if (receiveException(&result)) {
        return result;
    }

    return XUnixDebugger::waitForSignal(nThreadID, nOptions);
}

bool XOSXDebugger::resumeThread(X_ID nThreadId, qint32 nSignal)
{
    return continueAfterException(nThreadId, nSignal, false);
}

bool XOSXDebugger::resumeAllThreads()
{
    X_ID nThreadId = getXInfoDB()->getCurrentThreadId();
    if (m_pDarwinState->bCurrentMessage) {
        nThreadId = m_pDarwinState->currentMessage.nThreadId;
    }

    return continueAfterException(nThreadId, 0, true);
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

        if (::ptrace(PT_SIGEXC, 0, 0, 0) == -1) {
            qint32 nError = errno;
            writeChildLaunchError(anLaunchPipe[1], CHILD_LAUNCH_STAGE_SIGEXC, nError);
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
        } else if (launchError.nStage == CHILD_LAUNCH_STAGE_SIGEXC) {
            sOperation = "ptrace(PT_SIGEXC)";
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
    processInfo.sFileName = sFileName;
    processInfo.sBaseFileName = QFileInfo(sFileName).fileName();
    processInfo.hProcess = XProcess::openProcess(nProcessID);

    if (!processInfo.hProcess) {
        terminateAndReapChild(nProcessID);
        emit errorMessage(tr("Cannot open the child task port"));
        return false;
    }

    if (!installExceptionPort(processInfo.hProcess)) {
        mach_port_deallocate(mach_task_self(), processInfo.hProcess);
        terminateAndReapChild(nProcessID);
        emit errorMessage(tr("Cannot install the Darwin exception port"));
        return false;
    }

    getXInfoDB()->setProcessInfo(processInfo);

    QList<X_ID> listThreadIds;
    if (!getXInfoDB()->updateDarwinThreadPorts(&listThreadIds) || listThreadIds.isEmpty()) {
        shutdownExceptionPort(true);
        getXInfoDB()->clearDarwinThreadPorts();
        mach_port_deallocate(mach_task_self(), processInfo.hProcess);
        getXInfoDB()->getProcessInfo()->hProcess = MACH_PORT_NULL;
        terminateAndReapChild(nProcessID);
        emit errorMessage(tr("Cannot identify the initial Darwin thread"));
        return false;
    }

    processInfo.nMainThreadID = listThreadIds.first();
    getXInfoDB()->getProcessInfo()->nMainThreadID = processInfo.nMainThreadID;
    setDebugActive(true);
    emit eventCreateProcess(&processInfo);

    XInfoDB::THREAD_INFO threadInfo = {};
    threadInfo.nThreadID = processInfo.nMainThreadID;
    threadInfo.threadStatus = XInfoDB::THREAD_STATUS_PAUSED;
    getXInfoDB()->addThreadInfo(&threadInfo);
    emit eventCreateThread(&threadInfo);

    getXInfoDB()->setCurrentThreadId(processInfo.nMainThreadID);

    XInfoDB::BREAKPOINT_INFO breakPointInfo = {};
    breakPointInfo.nExceptionAddress = getXInfoDB()->getCurrentInstructionPointer_Id(processInfo.nMainThreadID);
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

bool XOSXDebugger::stop()
{
    shutdownExceptionPort(true);
    return XUnixDebugger::stop();
}

void XOSXDebugger::cleanUp()
{
    shutdownExceptionPort(true);
    getXInfoDB()->clearDarwinThreadPorts();
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
