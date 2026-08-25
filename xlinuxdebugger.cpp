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
#include "xlinuxdebugger.h"

#include <QDir>
#include <QProcess>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <sys/personality.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern "C" char **environ;

namespace {
enum CHILD_LAUNCH_STAGE {
    CHILD_LAUNCH_STAGE_UNKNOWN = 0,
    CHILD_LAUNCH_STAGE_PTRACE,
    CHILD_LAUNCH_STAGE_CHDIR,
    CHILD_LAUNCH_STAGE_EXECVE
};

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
    if (::kill(nProcessID, SIGKILL) == -1) {
        // The child may already have exited and been reaped by waitForSignal().
        if (errno != ESRCH) {
#ifdef QT_DEBUG
            qDebug("Cannot terminate child: %s", strerror(errno));
#endif
        }
    }

    reapChild(nProcessID);
}
}  // namespace

XLinuxDebugger::XLinuxDebugger(QObject *pParent, XInfoDB *pXInfoDB) : XUnixDebugger(pParent, pXInfoDB)
{
}

bool XLinuxDebugger::load()
{
    bool bResult = false;

    QString sFileName = getOptions()->sFileName;
    QString sDirectory = getOptions()->sDirectory;
    setDebugActive(false);

    if (!XBinary::isFileExists(sFileName)) {
        emit errorMessage(QString("%1: %2").arg(tr("Cannot load file"), sFileName));
        return false;
    }

    // Prepare every object that may allocate before fork(). The child only calls system functions
    // needed for the launch, then execve() or _exit(); invoking Qt allocation in a multithreaded
    // process after fork() can deadlock on a lock held by a vanished thread.
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
        listArgumentData.append(sArgument.toUtf8());
    }

    QVector<char *> listArgumentPointers;
    for (qint32 i = 0; i < listArgumentData.count(); i++) {
        listArgumentPointers.append(listArgumentData[i].data());
    }
    listArgumentPointers.append(nullptr);

    // Preserve the inherited byte-for-byte environment while forcing eager dynamic linking.
    // Environment storage and its pointer table must also be complete before fork().
    QList<QByteArray> listEnvironmentData;
    bool bBindNowPresent = false;

    for (char **ppEnvironment = environ; ppEnvironment && *ppEnvironment; ppEnvironment++) {
        QByteArray baEnvironment(*ppEnvironment);

        if (baEnvironment.startsWith("LD_BIND_NOW=")) {
            baEnvironment = "LD_BIND_NOW=1";
            bBindNowPresent = true;
        }

        listEnvironmentData.append(baEnvironment);
    }

    if (!bBindNowPresent) {
        listEnvironmentData.append("LD_BIND_NOW=1");
    }

    QVector<char *> listEnvironmentPointers;
    for (qint32 i = 0; i < listEnvironmentData.count(); i++) {
        listEnvironmentPointers.append(listEnvironmentData[i].data());
    }
    listEnvironmentPointers.append(nullptr);

    QByteArray baFileName = QFile::encodeName(sFileName);
    QByteArray baDirectory = QFile::encodeName(sDirectory);
    bool bHasDirectory = !baDirectory.isEmpty();
    char *pFileName = baFileName.data();
    char *pDirectory = baDirectory.data();
    char **ppArguments = listArgumentPointers.data();
    char **ppEnvironment = listEnvironmentPointers.data();

    qint32 anLaunchPipe[2] = {-1, -1};
    // Use the Linux system call directly so atomic CLOEXEC setup does not depend on whether the
    // build system exposed glibc's pipe2() declaration through _GNU_SOURCE.
    if (::syscall(SYS_pipe2, anLaunchPipe, O_CLOEXEC) == -1) {
        emit errorMessage(QString("%1: %2").arg(tr("Cannot create launch pipe"), QString::fromLocal8Bit(strerror(errno))));
        return false;
    }

    pid_t nProcessID = ::fork();

    if (nProcessID == 0) {
        // Child process. The write descriptor closes automatically on a successful execve(), so
        // EOF is the success handshake. Failures send one fixed-size, allocation-free record.
        ::close(anLaunchPipe[0]);

        if (::ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
            qint32 nError = errno;
            writeChildLaunchError(anLaunchPipe[1], CHILD_LAUNCH_STAGE_PTRACE, nError);
            ::_exit(127);
        }

        // Technique from edb: make the debugged run reproducible and self-contained.
        ::personality(ADDR_NO_RANDOMIZE);  // disable ASLR so addresses are stable
        // TODO redirect I/O (dup2 stdin/stdout/stderr) when running with a console

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
            sOperation = "ptrace(PTRACE_TRACEME)";
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

    // EOF means execve() succeeded and atomically closed the CLOEXEC write descriptor.
#ifdef QT_DEBUG
    qDebug("Forked");
    qDebug("nProcessID: %d", nProcessID);
#endif

    STATE _stateStart = waitForSignal(nProcessID, __WALL);

    if ((!_stateStart.bIsValid) || (_stateStart.debuggerStatus != DEBUGGER_STATUS_SIGTRAP)) {
        terminateAndReapChild(nProcessID);
        emit errorMessage(tr("The child did not stop after execve"));
        return false;
    }

    if (!setPtraceOptions(nProcessID)) {
        qint32 nPtraceError = errno;
        terminateAndReapChild(nProcessID);
        emit errorMessage(QString("%1: %2").arg(tr("Cannot set ptrace options"), QString::fromLocal8Bit(strerror(nPtraceError))));
        return false;
    }

    setDebugActive(true);

    // TODO load symbols

    XInfoDB::PROCESS_INFO processInfo = {};

    processInfo.nProcessID = nProcessID;
    processInfo.nMainThreadID = nProcessID;
    processInfo.sFileName = sFileName;
    processInfo.sBaseFileName = QFileInfo(sFileName).baseName();
    //                        processInfo.nImageBase;
    //                        processInfo.nImageSize;
    //                        processInfo.nStartAddress;
    //                        processInfo.nThreadLocalBase;
    processInfo.hProcessMemoryIO = XProcess::openMemoryIO(nProcessID);
    processInfo.hProcessMemoryQuery = XProcess::openMemoryQuery(nProcessID);
    //                        processInfo.hMainThread;

    getXInfoDB()->setProcessInfo(processInfo);

    emit eventCreateProcess(&processInfo);

    XInfoDB::THREAD_INFO threadInfo = {};

    threadInfo.nThreadID = nProcessID;
    threadInfo.threadStatus = XInfoDB::THREAD_STATUS_PAUSED;

    getXInfoDB()->addThreadInfo(&threadInfo);

    emit eventCreateThread(&threadInfo);

    if (hasPendingTermination()) {
        finishPendingTermination();
        return true;
    }

    // TODO if BP on system

    getXInfoDB()->setThreadStatus(_stateStart.nThreadId, XInfoDB::THREAD_STATUS_PAUSED);

    XInfoDB::BREAKPOINT_INFO breakPointInfo = {};

    breakPointInfo.nExceptionAddress = getXInfoDB()->getCurrentInstructionPointer_Id(nProcessID);
    breakPointInfo.bpType = XInfoDB::BPT_PROCESS_STOP;
    breakPointInfo.bpInfo = XInfoDB::BPI_PROCESSENTRYPOINT;

    breakPointInfo.pHProcessMemoryIO = getXInfoDB()->getProcessInfo()->hProcessMemoryIO;
    breakPointInfo.pHProcessMemoryQuery = getXInfoDB()->getProcessInfo()->hProcessMemoryQuery;
    breakPointInfo.nProcessID = getXInfoDB()->getProcessInfo()->nProcessID;
    breakPointInfo.nThreadID = getXInfoDB()->getProcessInfo()->nMainThreadID;

    //                getXInfoDB()->suspendAllThreads();
    //                getXInfoDB()->_lockId(nProcessID);
    _eventBreakPoint(&breakPointInfo);

    // A script callback can call stop() synchronously from the initial breakpoint, before a
    // timer exists. The callback has unwound here, so finish that pending kill/reap now instead
    // of starting a normal loop for a dead target.
    if (hasPendingTermination()) {
        finishPendingTermination();
    } else {
        startDebugLoop();
    }
    bResult = true;

    return bResult;
}

bool XLinuxDebugger::attach()
{
    // Technique from edb: enumerate the target's threads via /proc/<pid>/task, PTRACE_ATTACH each
    // TID, synchronize with waitpid(__WALL), set the ptrace options, then register the process and
    // its threads. The target is left stopped (paused) so the user can inspect before resuming.
    bool bResult = false;

    qint64 nProcessID = getOptions()->nPID;

    if (nProcessID) {
        QList<qint64> listThreadIDs;

        QDir taskDir(QString("/proc/%1/task").arg(nProcessID));
        const QStringList listEntries = taskDir.entryList(QDir::Dirs | QDir::NoDotAndDotDot);
        for (const QString &sEntry : listEntries) {
            bool bOk = false;
            qint64 nTID = sEntry.toLongLong(&bOk);
            if (bOk) {
                listThreadIDs.append(nTID);
            }
        }

        // Fall back to the main thread if /proc enumeration yielded nothing.
        if (listThreadIDs.isEmpty()) {
            listThreadIDs.append(nProcessID);
        }

        QList<qint64> listAttachedThreadIDs;

        for (qint64 nTID : listThreadIDs) {
            if (ptrace(PTRACE_ATTACH, nTID, 0, 0) != -1) {
                qint32 nStatus = 0;
                pid_t nWaitResult = 0;
                do {
                    nWaitResult = waitpid(nTID, &nStatus, __WALL);
                } while ((nWaitResult == -1) && (errno == EINTR));

                if ((nWaitResult == nTID) && WIFSTOPPED(nStatus) && setPtraceOptions(nTID)) {
                    listAttachedThreadIDs.append(nTID);
                } else {
                    // Never publish a TID that this tracer cannot wait/control. Cleanup drains
                    // only the successfully attached set, so a failed attach cannot hang it.
                    ptrace(PTRACE_DETACH, nTID, 0, 0);
                }
            } else {
#ifdef QT_DEBUG
                qDebug("Cannot PTRACE_ATTACH %lld: %s", (long long)nTID, strerror(errno));
#endif
            }
        }

        // The thread-group leader is the stable process identity used by wait/stop. If attaching
        // it failed, release any partial attaches rather than advertising a broken session.
        if (!listAttachedThreadIDs.contains(nProcessID)) {
            for (qint64 nTID : listAttachedThreadIDs) {
                ptrace(PTRACE_DETACH, nTID, 0, 0);
            }
            emit errorMessage(QString("%1: %2").arg(tr("Cannot attach to process")).arg(nProcessID));
            return false;
        }

        if (!listAttachedThreadIDs.isEmpty()) {
            setDebugActive(true);

            // The target's executable path is the /proc/<pid>/exe symlink.
            QString sFileName = QFileInfo(QString("/proc/%1/exe").arg(nProcessID)).symLinkTarget();

            XInfoDB::PROCESS_INFO processInfo = {};
            processInfo.nProcessID = nProcessID;
            processInfo.nMainThreadID = nProcessID;
            processInfo.sFileName = sFileName;
            processInfo.sBaseFileName = QFileInfo(sFileName).baseName();
            processInfo.hProcessMemoryIO = XProcess::openMemoryIO(nProcessID);
            processInfo.hProcessMemoryQuery = XProcess::openMemoryQuery(nProcessID);

            getXInfoDB()->setProcessInfo(processInfo);

            emit eventCreateProcess(&processInfo);

            for (qint64 nTID : listAttachedThreadIDs) {
                XInfoDB::THREAD_INFO threadInfo = {};
                threadInfo.nThreadID = nTID;
                threadInfo.threadStatus = XInfoDB::THREAD_STATUS_PAUSED;
                getXInfoDB()->addThreadInfo(&threadInfo);

                emit eventCreateThread(&threadInfo);
            }

            if (hasPendingTermination()) {
                finishPendingTermination();
            } else {
                startDebugLoop();
            }

            bResult = true;
        }
    }

    return bResult;
}

void XLinuxDebugger::cleanUp()
{
#ifdef Q_OS_LINUX
    // TODO Check
    if (getXInfoDB()->getProcessInfo()->hProcessMemoryIO) {
        XProcess::closeMemoryIO(getXInfoDB()->getProcessInfo()->hProcessMemoryIO);
        getXInfoDB()->getProcessInfo()->hProcessMemoryIO = 0;
    }

    if (getXInfoDB()->getProcessInfo()->hProcessMemoryQuery) {
        XProcess::closeMemoryQuery(getXInfoDB()->getProcessInfo()->hProcessMemoryQuery);
        getXInfoDB()->getProcessInfo()->hProcessMemoryQuery = 0;
    }
#endif

    XUnixDebugger::cleanUp();
}

QString XLinuxDebugger::getArch()
{
    // TODO
    return "AMD64";
}

XBinary::MODE XLinuxDebugger::getMode()
{
    XBinary::MODE result = XBinary::MODE_32;

    if (sizeof(void *) == 8) {
        result = XBinary::MODE_64;
    }

    return result;
}
