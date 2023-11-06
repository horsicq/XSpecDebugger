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
#include "xwindowsdebugger.h"

XWindowsDebugger::XWindowsDebugger(QObject *pParent, XInfoDB *pXInfoDB) : XAbstractDebugger(pParent, pXInfoDB)
{
    g_bBreakpointSystem = false;
    g_bBreakpointEntryPoint = false;

    XWindowsDebugger::cleanUp();
}

bool XWindowsDebugger::run()
{
    return getXInfoDB()->resumeAllThreads();
}

bool XWindowsDebugger::load()
{
    bool bResult = false;

    qint32 nFlags = DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED;  // TODO check CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE;

    if (getOptions()->records[XAbstractDebugger::OPTIONS_TYPE_SHOWCONSOLE].bValid) {
        if (getOptions()->records[XAbstractDebugger::OPTIONS_TYPE_SHOWCONSOLE].varValue.toBool()) {
            nFlags |= CREATE_NEW_CONSOLE;
        } else {
            nFlags |= CREATE_NO_WINDOW;  // NO Console
        }
    }

    if (getOptions()->records[XAbstractDebugger::OPTIONS_TYPE_UNICODEENVIRONMENT].bValid) {
        if (getOptions()->records[XAbstractDebugger::OPTIONS_TYPE_UNICODEENVIRONMENT].varValue.toBool()) {
            nFlags |= CREATE_UNICODE_ENVIRONMENT;
        }
    }

    g_bBreakpointSystem = false;
    g_bBreakpointEntryPoint = false;

    if (getOptions()->records[XAbstractDebugger::OPTIONS_TYPE_BREAKPOINTSYSTEM].bValid) {
        if (getOptions()->records[XAbstractDebugger::OPTIONS_TYPE_BREAKPOINTSYSTEM].varValue.toBool()) {
            g_bBreakpointSystem = true;
        }
    }

    if (getOptions()->records[XAbstractDebugger::OPTIONS_TYPE_BREAKPOINTENTRYPOINT].bValid) {
        if (getOptions()->records[XAbstractDebugger::OPTIONS_TYPE_BREAKPOINTENTRYPOINT].varValue.toBool()) {
            g_bBreakpointEntryPoint = true;
        }
    }

    // TODO DLL

    PROCESS_INFORMATION processInfo = {};
    STARTUPINFOW sturtupInfo = {};

    // TODO 32/64 !!! do not load if not the same(WOW64)
    sturtupInfo.cb = sizeof(sturtupInfo);

    // mb TODO use only the second parameter! the first -> null cause length limitaion.
    QString sArguments = QString("\"%1\" \"%2\"").arg(getOptions()->sFileName, getOptions()->sArguments);
    BOOL bCreateProcess = CreateProcessW((const wchar_t *)(getOptions()->sFileName.utf16()), (wchar_t *)sArguments.utf16(), nullptr, nullptr, 0, nFlags, nullptr,
                                         (const wchar_t *)(getOptions()->sDirectory.utf16()), &sturtupInfo, &processInfo);

    if (bCreateProcess) {
        cleanUp();

#ifdef Q_PROCESSOR_X86_32
        setDisasmMode(XBinary::DM_X86_32);
#endif
#ifdef Q_PROCESSOR_X86_64
        setDisasmMode(XBinary::DM_X86_64);
#endif

        setTraceFileName(XBinary::getResultFileName(getOptions()->sFileName, "trace.txt"));  // TODO Check mb Remove

        bResult = true;
        DWORD dwProcessID = processInfo.dwProcessId;

        if (ResumeThread(processInfo.hThread) != ((DWORD)-1)) {
            setDebugActive(true);

            _debugLoop(dwProcessID);
        }
    } else {
        _messageString(MT_ERROR, QString("%1: %2 (%3)").arg(tr("Cannot load file"), getOptions()->sFileName, XProcess::getLastErrorAsString()));
    }

    return bResult;
}

bool XWindowsDebugger::attach()
{
    // https://www.codeproject.com/Articles/132742/Writing-Windows-Debugger-Part-2
#ifdef QT_DEBUG
    qDebug("XWindowsDebugger::attach()");
#endif

    return false;  // TODO
}

bool XWindowsDebugger::stop()
{
    bool bResult = false;

    if (getXInfoDB()->getProcessInfo()->hProcess) {
        bResult = (bool)TerminateProcess(getXInfoDB()->getProcessInfo()->hProcess, 0);
    }

    return bResult;
}

void XWindowsDebugger::cleanUp()
{
    XWindowsDebugger::stop();

    XAbstractDebugger::cleanUp();
    setDebugActive(false);
    g_mapThreadBPToRestore.clear();
}

QString XWindowsDebugger::getArch()
{
    QString sResult;
    // TODO ARM!
#ifdef Q_PROCESSOR_X86_32
    sResult = "386";
#endif
#ifdef Q_PROCESSOR_X86_64
    sResult = "AMD64";
#endif
    return sResult;
}

XBinary::MODE XWindowsDebugger::getMode()
{
    XBinary::MODE result = XBinary::MODE_32;
#ifdef Q_PROCESSOR_X86_32
    result = XBinary::MODE_32;
#endif
#ifdef Q_PROCESSOR_X86_64
    result = XBinary::MODE_64;
#endif
    return result;
}

bool XWindowsDebugger::stepIntoByHandle(X_HANDLE hThread, XInfoDB::BPI bpInfo)
{
    bool bResult = false;

    bResult = getXInfoDB()->stepInto_Handle(hThread, bpInfo, true);

    if (bResult) {
        bResult = getXInfoDB()->resumeAllThreads();
    }

    return bResult;
}

bool XWindowsDebugger::stepOverByHandle(X_HANDLE hThread, XInfoDB::BPI bpInfo)
{
    bool bResult = false;

    bResult = getXInfoDB()->stepOver_Handle(hThread, bpInfo, true);

    if (bResult) {
        getXInfoDB()->resumeAllThreads();
    }

    return bResult;
}

bool XWindowsDebugger::stepInto()
{
    return stepIntoByHandle(getXInfoDB()->getCurrentThreadHandle(), XInfoDB::BPI_STEPINTO);
}

bool XWindowsDebugger::stepOver()
{
    return stepOverByHandle(getXInfoDB()->getCurrentThreadHandle(), XInfoDB::BPI_STEPINTO);
}

void XWindowsDebugger::_debugLoop(DWORD dwProcessID)
{
    while (isDebugActive()) {
        DEBUG_EVENT dbgEvent = {0};
        WaitForDebugEvent(&dbgEvent, INFINITE);  // TODO Check return

        quint32 nStatus = DBG_CONTINUE;

        if (dbgEvent.dwProcessId == dwProcessID) {
            if (dbgEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
                nStatus = on_EXCEPTION_DEBUG_EVENT(&dbgEvent);
            } else if (dbgEvent.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) {
                nStatus = on_CREATE_THREAD_DEBUG_EVENT(&dbgEvent);
            } else if (dbgEvent.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
                nStatus = on_CREATE_PROCESS_DEBUG_EVENT(&dbgEvent);
            } else if (dbgEvent.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT) {
                nStatus = on_EXIT_THREAD_DEBUG_EVENT(&dbgEvent);
            } else if (dbgEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
                nStatus = on_EXIT_PROCESS_DEBUG_EVENT(&dbgEvent);
            } else if (dbgEvent.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT) {
                nStatus = on_LOAD_DLL_DEBUG_EVENT(&dbgEvent);
            } else if (dbgEvent.dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT) {
                nStatus = on_UNLOAD_DLL_DEBUG_EVENT(&dbgEvent);
            } else if (dbgEvent.dwDebugEventCode == OUTPUT_DEBUG_STRING_EVENT) {
                nStatus = on_OUTPUT_DEBUG_STRING_EVENT(&dbgEvent);
            } else if (dbgEvent.dwDebugEventCode == RIP_EVENT) {
                nStatus = on_RIP_EVENT(&dbgEvent);
            }
        }

        ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, nStatus);
    }
}

void XWindowsDebugger::_handleBreakpoint(XADDR nAddress, X_ID nThreadID, XInfoDB::BPT bpType)
{
    X_HANDLE hThread = getXInfoDB()->findThreadInfoByID(nThreadID).hThread;
    //            bool bThreadsSuspended=getXInfoDB()->suspendOtherThreads(breakPointInfo.nThreadID);
    getXInfoDB()->suspendAllThreads();

    XInfoDB::BREAKPOINT _currentBP = getXInfoDB()->findBreakPointByAddress(nAddress, bpType);

    getXInfoDB()->setCurrentIntructionPointer_Handle(hThread, nAddress);  // go to prev instruction address

    getXInfoDB()->disableBreakPoint(_currentBP.sUUID);

    if (getXInfoDB()->getFunctionHookInfos()->contains(_currentBP.sInfo)) {
        // TODO handle_Kernel32_GetProcAddress

        if (_currentBP.bpInfo == XInfoDB::BPI_FUNCTIONENTER) {
            QString sUUID = XBinary::generateUUID();
            XInfoDB::FUNCTION_INFO functionInfo = getXInfoDB()->getFunctionInfo(hThread, _currentBP.sInfo);

            g_mapFunctionInfos.insert(sUUID, functionInfo);

            emit eventFunctionEnter(&functionInfo);

            getXInfoDB()->addBreakPoint(functionInfo.nRetAddress, XInfoDB::BPT_CODE_SOFTWARE_DEFAULT, XInfoDB::BPI_FUNCTIONLEAVE, 1, _currentBP.sInfo, sUUID);
        } else if (_currentBP.bpInfo == XInfoDB::BPI_FUNCTIONLEAVE) {
            XInfoDB::FUNCTION_INFO functionInfo = g_mapFunctionInfos.value(_currentBP.sUUID);

            emit eventFunctionLeave(&functionInfo);

            g_mapFunctionInfos.remove(_currentBP.sUUID);
        }
    } else {
        XInfoDB::BREAKPOINT_INFO breakPointInfo = {};
        breakPointInfo.nAddress = nAddress;
        breakPointInfo.nProcessID = getXInfoDB()->getProcessInfo()->nProcessID;
        breakPointInfo.nThreadID = nThreadID;
        breakPointInfo.hThread = hThread;
        breakPointInfo.hProcess = getXInfoDB()->getProcessInfo()->hProcess;
        breakPointInfo.bpType = _currentBP.bpType;
        breakPointInfo.bpInfo = _currentBP.bpInfo;
        breakPointInfo.sInfo = _currentBP.sInfo;

        //                if(!(getXInfoDB()->getThreadBreakpoints()->contains(pDebugEvent->dwThreadId))) // If not step. For step there is an another
        //                callback
        //                {
        //                    emit eventBreakPoint(&breakPointInfo);
        //                }

        _eventBreakPoint(&breakPointInfo);
    }

    if (_currentBP.nCount != -1) {
        _currentBP.nCount--;
    }

    if (_currentBP.nCount) {
        g_mapThreadBPToRestore.insert(nThreadID, _currentBP.sUUID);
        getXInfoDB()->_setStep_Handle(hThread);
    } else {
        getXInfoDB()->removeBreakPoint(_currentBP.sUUID);
    }

    //            if(bThreadsSuspended)
    //            {
    //                getXInfoDB()->resumeOtherThreads(breakPointInfo.nThreadID);
    //            }
}

quint32 XWindowsDebugger::on_EXCEPTION_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent)
{
    quint32 nResult = DBG_EXCEPTION_NOT_HANDLED;

    //    getXInfoDB()->setThreadStatus(pDebugEvent->dwThreadId, XInfoDB::THREAD_STATUS_PAUSED);

    quint32 nExceptionCode = pDebugEvent->u.Exception.ExceptionRecord.ExceptionCode;
    quint64 nExceptionAddress = (qint64)(pDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress);

    if ((nExceptionCode == EXCEPTION_BREAKPOINT) || (nExceptionCode == 0x4000001f)) {
        // 4000001f WOW64 breakpoint
        if (getXInfoDB()->findBreakPointByAddress(nExceptionAddress, XInfoDB::BPT_CODE_SOFTWARE_INT3).nAddress == nExceptionAddress) {
            _handleBreakpoint(nExceptionAddress, pDebugEvent->dwThreadId, XInfoDB::BPT_CODE_SOFTWARE_INT3);

            nResult = DBG_CONTINUE;
        } else {
            if (g_bBreakpointSystem) {
                //                bool bThreadsSuspended=getXInfoDB()->suspendOtherThreads(breakPointInfo.nThreadID);
                getXInfoDB()->suspendAllThreads();

                qDebug("SYSTEM BP SOFTWARE");
                XInfoDB::BREAKPOINT_INFO breakPointInfo = {};
                breakPointInfo.nAddress = nExceptionAddress;
                breakPointInfo.nProcessID = getXInfoDB()->getProcessInfo()->nProcessID;
                breakPointInfo.nThreadID = pDebugEvent->dwThreadId;
                breakPointInfo.hThread = getXInfoDB()->findThreadInfoByID(pDebugEvent->dwThreadId).hThread;
                breakPointInfo.hProcess = getXInfoDB()->getProcessInfo()->hProcess;
                breakPointInfo.bpType = XInfoDB::BPT_CODE_SOFTWARE_INT3;  // TODO Check
                breakPointInfo.bpInfo = XInfoDB::BPI_SYSTEM;

                _eventBreakPoint(&breakPointInfo);

                //                if(bThreadsSuspended)
                //                {
                //                    getXInfoDB()->resumeOtherThreads(breakPointInfo.nThreadID);
                //                }

                //                nResult=DBG_EXCEPTION_NOT_HANDLED; // TODO change the Value
                nResult = DBG_CONTINUE;
            }
        }
    } else if ((nExceptionCode == EXCEPTION_SINGLE_STEP) || (nExceptionCode == 0x4000001e)) {
        // 4000001e WOW64 single step exception
        // Single step
        if (g_mapThreadBPToRestore.contains(pDebugEvent->dwThreadId)) {
            QString sGUID = g_mapThreadBPToRestore.value(pDebugEvent->dwThreadId);
            getXInfoDB()->enableBreakPoint(sGUID);
            g_mapThreadBPToRestore.remove(pDebugEvent->dwThreadId);  // mb TODO multi values

            nResult = DBG_CONTINUE;
        }

        X_HANDLE hThread = getXInfoDB()->findThreadInfoByID(pDebugEvent->dwThreadId).hThread;

        if (getXInfoDB()->getThreadBreakpoints()->contains(hThread)) {
            XInfoDB::BREAKPOINT stepBP = getXInfoDB()->getThreadBreakpoints()->value(hThread);

            if ((stepBP.bpInfo == XInfoDB::BPI_STEPINTO) || (stepBP.bpInfo == XInfoDB::BPI_STEPOVER)) {
                getXInfoDB()->getThreadBreakpoints()->remove(hThread);

                getXInfoDB()->suspendAllThreads();

                XInfoDB::BREAKPOINT_INFO breakPointInfo = {};
                breakPointInfo.nAddress = nExceptionAddress;
                breakPointInfo.nProcessID = getXInfoDB()->getProcessInfo()->nProcessID;
                breakPointInfo.nThreadID = pDebugEvent->dwThreadId;
                breakPointInfo.hThread = hThread;
                breakPointInfo.hProcess = getXInfoDB()->getProcessInfo()->hProcess;
                breakPointInfo.bpType = stepBP.bpType;
                breakPointInfo.bpInfo = stepBP.bpInfo;
                breakPointInfo.sInfo = stepBP.sInfo;

                _eventBreakPoint(&breakPointInfo);
            } else if ((stepBP.bpInfo == XInfoDB::BPI_TRACEINTO) || (stepBP.bpInfo == XInfoDB::BPI_TRACEOVER)) {
                // TODO
                // Check suspend threads
                getXInfoDB()->suspendAllThreads();

                if (false)  // TODO Check trace conditions
                {
                    if (stepBP.bpInfo == XInfoDB::BPI_TRACEINTO) {
                        getXInfoDB()->stepInto_Handle(hThread, stepBP.bpInfo, false);
                    } else if (stepBP.bpInfo == XInfoDB::BPI_TRACEOVER) {
                        getXInfoDB()->stepOver_Handle(hThread, stepBP.bpInfo, false);
                    }

                    getXInfoDB()->resumeAllThreads();
                } else {
                    getXInfoDB()->getThreadBreakpoints()->remove(hThread);

                    XInfoDB::BREAKPOINT_INFO breakPointInfo = {};
                    breakPointInfo.nAddress = nExceptionAddress;
                    breakPointInfo.nProcessID = getXInfoDB()->getProcessInfo()->nProcessID;
                    breakPointInfo.nThreadID = pDebugEvent->dwThreadId;
                    breakPointInfo.hThread = hThread;
                    breakPointInfo.hProcess = getXInfoDB()->getProcessInfo()->hProcess;
                    breakPointInfo.bpType = stepBP.bpType;
                    breakPointInfo.bpInfo = stepBP.bpInfo;
                    breakPointInfo.sInfo = stepBP.sInfo;

                    _eventBreakPoint(&breakPointInfo);
                }
            }

            nResult = DBG_CONTINUE;
        } else {
            XInfoDB::BREAKPOINT bp = getXInfoDB()->findBreakPointByExceptionAddress(nExceptionAddress, XInfoDB::BPT_CODE_SOFTWARE_INT1);

            if (bp.sUUID != "") {
                _handleBreakpoint(bp.nAddress, pDebugEvent->dwThreadId, XInfoDB::BPT_CODE_SOFTWARE_INT1);

                nResult = DBG_CONTINUE;
            }
        }
    } else if (nExceptionCode == EXCEPTION_PRIV_INSTRUCTION) {
        if (getXInfoDB()->findBreakPointByAddress(nExceptionAddress, XInfoDB::BPT_CODE_SOFTWARE_HLT).nAddress == nExceptionAddress) {
            _handleBreakpoint(nExceptionAddress, pDebugEvent->dwThreadId, XInfoDB::BPT_CODE_SOFTWARE_HLT);
            nResult = DBG_CONTINUE;
        } else if (getXInfoDB()->findBreakPointByAddress(nExceptionAddress, XInfoDB::BPT_CODE_SOFTWARE_CLI).nAddress == nExceptionAddress) {
            _handleBreakpoint(nExceptionAddress, pDebugEvent->dwThreadId, XInfoDB::BPT_CODE_SOFTWARE_CLI);
            nResult = DBG_CONTINUE;
        } else if (getXInfoDB()->findBreakPointByAddress(nExceptionAddress, XInfoDB::BPT_CODE_SOFTWARE_STI).nAddress == nExceptionAddress) {
            _handleBreakpoint(nExceptionAddress, pDebugEvent->dwThreadId, XInfoDB::BPT_CODE_SOFTWARE_STI);
            nResult = DBG_CONTINUE;
        } else if (getXInfoDB()->findBreakPointByAddress(nExceptionAddress, XInfoDB::BPT_CODE_SOFTWARE_INSB).nAddress == nExceptionAddress) {
            _handleBreakpoint(nExceptionAddress, pDebugEvent->dwThreadId, XInfoDB::BPT_CODE_SOFTWARE_INSB);
            nResult = DBG_CONTINUE;
        } else if (getXInfoDB()->findBreakPointByAddress(nExceptionAddress, XInfoDB::BPT_CODE_SOFTWARE_INSD).nAddress == nExceptionAddress) {
            _handleBreakpoint(nExceptionAddress, pDebugEvent->dwThreadId, XInfoDB::BPT_CODE_SOFTWARE_INSD);
            nResult = DBG_CONTINUE;
        } else if (getXInfoDB()->findBreakPointByAddress(nExceptionAddress, XInfoDB::BPT_CODE_SOFTWARE_OUTSB).nAddress == nExceptionAddress) {
            _handleBreakpoint(nExceptionAddress, pDebugEvent->dwThreadId, XInfoDB::BPT_CODE_SOFTWARE_OUTSB);
            nResult = DBG_CONTINUE;
        } else if (getXInfoDB()->findBreakPointByAddress(nExceptionAddress, XInfoDB::BPT_CODE_SOFTWARE_OUTSD).nAddress == nExceptionAddress) {
            _handleBreakpoint(nExceptionAddress, pDebugEvent->dwThreadId, XInfoDB::BPT_CODE_SOFTWARE_OUTSD);
            nResult = DBG_CONTINUE;
        }
    } else if (nExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
        if (getXInfoDB()->findBreakPointByAddress(nExceptionAddress, XInfoDB::BPT_CODE_SOFTWARE_UD0).nAddress == nExceptionAddress) {
            _handleBreakpoint(nExceptionAddress, pDebugEvent->dwThreadId, XInfoDB::BPT_CODE_SOFTWARE_UD0);
            nResult = DBG_CONTINUE;
        } else if (getXInfoDB()->findBreakPointByAddress(nExceptionAddress, XInfoDB::BPT_CODE_SOFTWARE_UD2).nAddress == nExceptionAddress) {
            _handleBreakpoint(nExceptionAddress, pDebugEvent->dwThreadId, XInfoDB::BPT_CODE_SOFTWARE_UD2);
            nResult = DBG_CONTINUE;
        }
    }


    //    qDebug("on_EXCEPTION_DEBUG_EVENT");
    //    qDebug("dwFirstChance %x",pDebugEvent->u.Exception.dwFirstChance);
    //    qDebug("ExceptionAddress %x",pDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress);
    //    qDebug("ExceptionCode %x",pDebugEvent->u.Exception.ExceptionRecord.ExceptionCode);
    //    qDebug("ExceptionFlags %x",pDebugEvent->u.Exception.ExceptionRecord.ExceptionFlags);
    //    qDebug("ExceptionRecord %x",pDebugEvent->u.Exception.ExceptionRecord.ExceptionRecord);
    //    qDebug("NumberParameters %x",pDebugEvent->u.Exception.ExceptionRecord.NumberParameters);

    //    for(qint32 i=0;i<pDebugEvent->u.Exception.ExceptionRecord.NumberParameters;i++)
    //    {
    //        qDebug("ExceptionInformation %x: %x",i,pDebugEvent->u.Exception.ExceptionRecord.ExceptionInformation[i]);
    //    }

    //    getXInfoDB()->setThreadStatus(pDebugEvent->dwThreadId, XInfoDB::THREAD_STATUS_RUNNING); // TODO Check

    return nResult;
}

quint32 XWindowsDebugger::on_CREATE_THREAD_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent)
{
    XInfoDB::THREAD_INFO threadInfo = {};
    threadInfo.nThreadID = pDebugEvent->dwThreadId;
    threadInfo.hThread = pDebugEvent->u.CreateThread.hThread;
    threadInfo.nStartAddress = (qint64)pDebugEvent->u.CreateThread.lpStartAddress;
    threadInfo.nThreadLocalBase = (qint64)pDebugEvent->u.CreateThread.lpThreadLocalBase;
    threadInfo.threadStatus = XInfoDB::THREAD_STATUS_RUNNING;
    getXInfoDB()->addThreadInfo(&threadInfo);

    emit eventCreateThread(&threadInfo);

    return DBG_CONTINUE;
}

quint32 XWindowsDebugger::on_CREATE_PROCESS_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent)
{
    XInfoDB::PROCESS_INFO processInfo = {};
    processInfo.nProcessID = pDebugEvent->dwProcessId;
    processInfo.nMainThreadID = pDebugEvent->dwThreadId;
    processInfo.hProcess = pDebugEvent->u.CreateProcessInfo.hProcess;
    processInfo.hMainThread = pDebugEvent->u.CreateProcessInfo.hThread;
    processInfo.nImageBase = (qint64)(pDebugEvent->u.CreateProcessInfo.lpBaseOfImage);
    processInfo.nImageSize = XProcess::getRegionAllocationSize(processInfo.hProcess, processInfo.nImageBase);
    processInfo.nStartAddress = (qint64)(pDebugEvent->u.CreateProcessInfo.lpStartAddress);  // TODO Check value
    processInfo.sFileName = XProcess::getFileNameByHandle(pDebugEvent->u.CreateProcessInfo.hFile);
    processInfo.sBaseFileName = XBinary::getBaseFileName(processInfo.sFileName);
    processInfo.nThreadLocalBase = (qint64)(pDebugEvent->u.CreateProcessInfo.lpThreadLocalBase);

    //    QFile file;
    //    file.setFileName(processInfo.sFileName);

    //    if(file.open(QIODevice::ReadOnly))
    //    {
    //        XPE pe(&file);

    //        if(pe.isValid())
    //        {
    //            XBinary::_MEMORY_MAP memoryMap=pe.getMemoryMap();
    //            processInfo.listSymbolRecords=pe.getSymbolRecords(&memoryMap);
    //        }

    //        file.close();
    //    }

    getXInfoDB()->setProcessInfo(processInfo);

    XInfoDB::THREAD_INFO threadInfo = {};
    threadInfo.nThreadID = pDebugEvent->dwThreadId;
    threadInfo.hThread = pDebugEvent->u.CreateProcessInfo.hThread;
    threadInfo.nStartAddress = (qint64)(pDebugEvent->u.CreateProcessInfo.lpStartAddress);
    threadInfo.nThreadLocalBase = (qint64)(pDebugEvent->u.CreateProcessInfo.lpThreadLocalBase);
    threadInfo.threadStatus = XInfoDB::THREAD_STATUS_RUNNING;
    getXInfoDB()->addThreadInfo(&threadInfo);

    if (g_bBreakpointEntryPoint) {
        getXInfoDB()->addBreakPoint((qint64)(pDebugEvent->u.CreateProcessInfo.lpStartAddress), XInfoDB::BPT_CODE_SOFTWARE_DEFAULT, XInfoDB::BPI_PROGRAMENTRYPOINT, 1);
    }
    // TODO DLLMain

    emit eventCreateProcess(&processInfo);

    return DBG_CONTINUE;
}

quint32 XWindowsDebugger::on_EXIT_THREAD_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent)
{
    XInfoDB::THREAD_INFO threadInfo = getXInfoDB()->findThreadInfoByID((qint64)(pDebugEvent->dwThreadId));
    getXInfoDB()->removeThreadInfo(threadInfo.nThreadID);

    XInfoDB::EXITTHREAD_INFO exitThreadInfo = {};
    exitThreadInfo.nThreadID = pDebugEvent->dwThreadId;
    exitThreadInfo.nExitCode = pDebugEvent->u.ExitThread.dwExitCode;

    emit eventExitThread(&exitThreadInfo);

    return DBG_CONTINUE;
}

quint32 XWindowsDebugger::on_EXIT_PROCESS_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent)
{
    XInfoDB::EXITPROCESS_INFO exitProcessInfo = {};
    exitProcessInfo.nProcessID = pDebugEvent->dwProcessId;
    exitProcessInfo.nThreadID = pDebugEvent->dwThreadId;
    exitProcessInfo.nExitCode = pDebugEvent->u.ExitProcess.dwExitCode;

    XInfoDB::THREAD_INFO threadInfo = getXInfoDB()->findThreadInfoByID((qint64)(pDebugEvent->dwThreadId));
    getXInfoDB()->removeThreadInfo(threadInfo.nThreadID);

    emit eventExitProcess(&exitProcessInfo);

    setDebugActive(false);

    return DBG_CONTINUE;
}

quint32 XWindowsDebugger::on_LOAD_DLL_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent)
{
    XInfoDB::SHAREDOBJECT_INFO sharedObjectInfo = {};
    sharedObjectInfo.nImageBase = (qint64)(pDebugEvent->u.LoadDll.lpBaseOfDll);
    sharedObjectInfo.nImageSize = XProcess::getRegionAllocationSize(getXInfoDB()->getProcessInfo()->hProcess, sharedObjectInfo.nImageBase);
    sharedObjectInfo.sFileName = XProcess::getFileNameByHandle(pDebugEvent->u.LoadDll.hFile);
    sharedObjectInfo.sName = QFileInfo(sharedObjectInfo.sFileName).fileName().toUpper();

    getXInfoDB()->addSharedObjectInfo(&sharedObjectInfo);

    // mb TODO add api breakpoints If set

    emit eventLoadSharedObject(&sharedObjectInfo);

    return DBG_CONTINUE;
}

quint32 XWindowsDebugger::on_UNLOAD_DLL_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent)
{
    XInfoDB::SHAREDOBJECT_INFO sharedObjectInfo =
        getXInfoDB()->getSharedObjectInfos()->value((qint64)(pDebugEvent->u.UnloadDll.lpBaseOfDll));  // TODO make findByAddressFunction
    getXInfoDB()->removeSharedObjectInfo(&sharedObjectInfo);

    // XBinary::removeFunctionAddressesByModule(&g_mapFunctionAddresses,sharedObjectInfo.nImageBase);

    // mb TODO disable api breakpoints If Set

    emit eventUnloadSharedObject(&sharedObjectInfo);

    return DBG_CONTINUE;
}

quint32 XWindowsDebugger::on_OUTPUT_DEBUG_STRING_EVENT(DEBUG_EVENT *pDebugEvent)
{
    XInfoDB::DEBUGSTRING_INFO debugStringInfo = {};
    debugStringInfo.nThreadID = pDebugEvent->dwThreadId;

    if (pDebugEvent->u.DebugString.fUnicode) {
        debugStringInfo.sDebugString =
            getXInfoDB()->read_unicodeString((qint64)(pDebugEvent->u.DebugString.lpDebugStringData), pDebugEvent->u.DebugString.nDebugStringLength);
    } else {
        debugStringInfo.sDebugString =
            getXInfoDB()->read_ansiString((qint64)(pDebugEvent->u.DebugString.lpDebugStringData), pDebugEvent->u.DebugString.nDebugStringLength);
    }
#ifdef QT_DEBUG
    qDebug(debugStringInfo.sDebugString.toLatin1().data());
#endif
    emit eventDebugString(&debugStringInfo);

    return DBG_CONTINUE;
}

quint32 XWindowsDebugger::on_RIP_EVENT(DEBUG_EVENT *pDebugEvent)
{
#ifdef QT_DEBUG
    qDebug("on_RIP_EVENT");
#endif
    return DBG_CONTINUE;
}
