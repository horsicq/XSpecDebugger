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

#include <sys/personality.h>

XLinuxDebugger::XLinuxDebugger(QObject *pParent, XInfoDB *pXInfoDB) : XUnixDebugger(pParent, pXInfoDB)
{
}

bool XLinuxDebugger::load()
{
    bool bResult = false;

    QString sFileName = getOptions()->sFileName;
    QString sDirectory = getOptions()->sDirectory;

    quint32 nMapSize = 0x1000;
    char *pMapMemory = (char *)mmap(nullptr, nMapSize, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);  // TODO mb a function

    XBinary::_zeroMemory(pMapMemory, nMapSize);

    if (XBinary::isFileExists(sFileName)) {
        qint32 nProcessID = fork();

        if (nProcessID == 0) {
            // Child process
            ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);  // TODO errors

            // Technique from edb: make the debugged run reproducible and self-contained.
            personality(ADDR_NO_RANDOMIZE);  // disable ASLR so addresses are stable
            setenv("LD_BIND_NOW", "1", 1);   // resolve all imports eagerly (no lazy PLT stubs)
            // TODO redirect I/O (dup2 stdin/stdout/stderr) when running with a console

            EXECUTEPROCESS ep = executeProcess(sFileName, sDirectory);

            XBinary::_copyMemory(pMapMemory, ep.sErrorString.toUtf8().data(), ep.sErrorString.toUtf8().size());

            abort();
        } else if (nProcessID > 0) {
            // Parent
            // TODO
            // TODO init
#ifdef QT_DEBUG
            qDebug("Forked");
            qDebug("nProcessID: %d", nProcessID);
#endif

            QString sErrorString = pMapMemory;
            munmap(pMapMemory, nMapSize);

            if (sErrorString != "") {
                emit errorMessage(sErrorString);
            }

            setDebugActive(true);

            STATE _stateStart = waitForSignal(nProcessID, __WALL);  // TODO result

            if (_stateStart.debuggerStatus == DEBUGGER_STATUS_SIGTRAP) {
                setPtraceOptions(nProcessID);  // Set options

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
            }

            startDebugLoop();
        } else if (nProcessID < 0)  // -1
        {
            // Error
            // TODO
#ifdef QT_DEBUG
            qDebug("Cannot fork");
#endif
        }
    }

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

        bool bAttached = false;

        for (qint64 nTID : listThreadIDs) {
            if (ptrace(PTRACE_ATTACH, nTID, 0, 0) != -1) {
                qint32 nStatus = 0;
                waitpid(nTID, &nStatus, __WALL);
                setPtraceOptions(nTID);
                bAttached = true;
            } else {
#ifdef QT_DEBUG
                qDebug("Cannot PTRACE_ATTACH %lld: %s", (long long)nTID, strerror(errno));
#endif
            }
        }

        if (bAttached) {
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

            for (qint64 nTID : listThreadIDs) {
                XInfoDB::THREAD_INFO threadInfo = {};
                threadInfo.nThreadID = nTID;
                threadInfo.threadStatus = XInfoDB::THREAD_STATUS_PAUSED;
                getXInfoDB()->addThreadInfo(&threadInfo);

                emit eventCreateThread(&threadInfo);
            }

            startDebugLoop();

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

    stop();
    wait();
    // TODO stopDebugEvent
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
