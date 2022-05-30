/* Copyright (c) 2020-2022 hors<horsicq@gmail.com>
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

XWindowsDebugger::XWindowsDebugger(QObject *pParent,XInfoDB *pXInfoDB) : XAbstractDebugger(pParent,pXInfoDB)
{
    XWindowsDebugger::cleanUp();
}

bool XWindowsDebugger::load()
{
    bool bResult=false;

    qint32 nFlags=DEBUG_PROCESS|DEBUG_ONLY_THIS_PROCESS|CREATE_SUSPENDED; // TODO check CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE;

    if(!(getOptions()->bShowConsole))
    {
        nFlags|=CREATE_NO_WINDOW; // NO Console
    }
    // TODO DLL

    PROCESS_INFORMATION processInfo={};
    STARTUPINFOW sturtupInfo={};

    // TODO 32/64 !!! do not load if not the same(WOW64)
    sturtupInfo.cb=sizeof(sturtupInfo);

    QString sArguments=QString("\"%1\" \"%2\"").arg(getOptions()->sFileName,getOptions()->sArguments);
    BOOL bCreateProcess=CreateProcessW((const wchar_t*)(getOptions()->sFileName.utf16()),(wchar_t*)sArguments.utf16(),nullptr,nullptr,0,nFlags,nullptr,nullptr,&sturtupInfo,&processInfo);

    if(bCreateProcess)
    {
        cleanUp();

    #ifndef Q_OS_WIN64
        setDisasmMode(XBinary::DM_X86_32);
    #else
        setDisasmMode(XBinary::DM_X86_64);
    #endif

        setTraceFileName(XBinary::getResultFileName(getOptions()->sFileName,"trace.txt"));

        bResult=true;
        DWORD dwProcessID=processInfo.dwProcessId;

        if(ResumeThread(processInfo.hThread)!=((DWORD)-1))
        {
            setDebugActive(true);

            while(isDebugActive())
            {
                DEBUG_EVENT dbgEvent={0};
                WaitForDebugEvent(&dbgEvent,INFINITE); // TODO Check return

                quint32 nStatus=DBG_CONTINUE;

                if(dbgEvent.dwProcessId==dwProcessID)
                {
                    if(dbgEvent.dwDebugEventCode==EXCEPTION_DEBUG_EVENT)
                    {
                        nStatus=on_EXCEPTION_DEBUG_EVENT(&dbgEvent);
                    }
                    else if(dbgEvent.dwDebugEventCode==CREATE_THREAD_DEBUG_EVENT)
                    {
                        nStatus=on_CREATE_THREAD_DEBUG_EVENT(&dbgEvent);
                    }
                    else if(dbgEvent.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT)
                    {
                        nStatus=on_CREATE_PROCESS_DEBUG_EVENT(&dbgEvent);
                    }
                    else if(dbgEvent.dwDebugEventCode==EXIT_THREAD_DEBUG_EVENT)
                    {
                        nStatus=on_EXIT_THREAD_DEBUG_EVENT(&dbgEvent);
                    }
                    else if(dbgEvent.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT)
                    {
                        nStatus=on_EXIT_PROCESS_DEBUG_EVENT(&dbgEvent);
                    }
                    else if(dbgEvent.dwDebugEventCode==LOAD_DLL_DEBUG_EVENT)
                    {
                        nStatus=on_LOAD_DLL_DEBUG_EVENT(&dbgEvent);
                    }
                    else if(dbgEvent.dwDebugEventCode==UNLOAD_DLL_DEBUG_EVENT)
                    {
                        nStatus=on_UNLOAD_DLL_DEBUG_EVENT(&dbgEvent);
                    }
                    else if(dbgEvent.dwDebugEventCode==OUTPUT_DEBUG_STRING_EVENT)
                    {
                        nStatus=on_OUTPUT_DEBUG_STRING_EVENT(&dbgEvent);
                    }
                    else if(dbgEvent.dwDebugEventCode==RIP_EVENT)
                    {
                        nStatus=on_RIP_EVENT(&dbgEvent);
                    }
                }

                ContinueDebugEvent(dbgEvent.dwProcessId,dbgEvent.dwThreadId,nStatus);
            }
        }
    }
    else
    {
        _messageString(MT_ERROR,QString("%1: %2").arg(tr("Cannot load file")).arg(getOptions()->sFileName));
    }

    return bResult;
}

bool XWindowsDebugger::stop()
{
    return (bool)TerminateProcess(getXInfoDB()->getProcessInfo()->hProcess,0);
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
#ifndef Q_OS_WIN64
    sResult="386";
#else
    sResult="AMD64";
#endif
    return sResult;
}

XBinary::MODE XWindowsDebugger::getMode()
{
    XBinary::MODE result=XBinary::MODE_32;
#ifndef Q_OS_WIN64
    result=XBinary::MODE_32;
#else
    result=XBinary::MODE_64;
#endif
    return result;
}

quint32 XWindowsDebugger::on_EXCEPTION_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent)
{
    quint32 nResult=DBG_EXCEPTION_NOT_HANDLED;

    quint32 nExceptionCode=pDebugEvent->u.Exception.ExceptionRecord.ExceptionCode;
    quint64 nExceptionAddress=(qint64)(pDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress);

    XInfoDB::BREAKPOINT_INFO breakPointInfo={};

    breakPointInfo.nAddress=nExceptionAddress;
    breakPointInfo.nProcessID=getXInfoDB()->getProcessInfo()->nProcessID;
    breakPointInfo.nThreadID=pDebugEvent->dwThreadId;
    breakPointInfo.hThread=getXInfoDB()->findThreadInfoByID(pDebugEvent->dwThreadId).hThread;
    breakPointInfo.hProcess=getXInfoDB()->getProcessInfo()->hProcess;

    if((nExceptionCode==EXCEPTION_BREAKPOINT)||(nExceptionCode==0x4000001f)) // 4000001f WOW64 breakpoint
    {
        if(getXInfoDB()->isBreakPointPresent(nExceptionAddress,XInfoDB::BPT_CODE_SOFTWARE))
        {
            bool bThreadsSuspended=getXInfoDB()->suspendOtherThreads(breakPointInfo.hThread);

            XInfoDB::BREAKPOINT _currentBP=getXInfoDB()->findBreakPointByAddress(nExceptionAddress);

            getXInfoDB()->setCurrentIntructionPointer(breakPointInfo.hThread,nExceptionAddress); // go to prev instruction address

            getXInfoDB()->removeBreakPoint(nExceptionAddress,_currentBP.bpType);

            if(getXInfoDB()->getFunctionHookInfos()->contains(_currentBP.sInfo))
            {
                // TODO handle_Kernel32_GetProcAddress

                if(_currentBP.bpInfo==XInfoDB::BPI_FUNCTIONENTER)
                {
                    QString sUUID=XBinary::generateUUID();
                    XInfoDB::FUNCTION_INFO functionInfo=getXInfoDB()->getFunctionInfo(breakPointInfo.hThread,_currentBP.sInfo);

                    g_mapFunctionInfos.insert(sUUID,functionInfo);

                    emit eventFunctionEnter(&functionInfo);

                    getXInfoDB()->addBreakPoint(functionInfo.nRetAddress,XInfoDB::BPT_CODE_SOFTWARE,XInfoDB::BPI_FUNCTIONLEAVE,1,_currentBP.sInfo,sUUID);
                }
                else if(_currentBP.bpInfo==XInfoDB::BPI_FUNCTIONLEAVE)
                {
                    XInfoDB::FUNCTION_INFO functionInfo=g_mapFunctionInfos.value(_currentBP.sGUID);

                    emit eventFunctionLeave(&functionInfo);

                    g_mapFunctionInfos.remove(_currentBP.sGUID);
                }
            }
            else
            {
                breakPointInfo.bpType=_currentBP.bpType;
                breakPointInfo.bpInfo=_currentBP.bpInfo;
                breakPointInfo.sInfo=_currentBP.sInfo;

                if(!(getXInfoDB()->getThreadBreakpoints()->contains(pDebugEvent->dwThreadId))) // If not step. For step there is an another callback
                {
                    emit eventBreakPoint(&breakPointInfo);
                }
            }

            if(_currentBP.nCount!=-1)
            {
                _currentBP.nCount--;
            }

            if(_currentBP.nCount)
            {
                g_mapThreadBPToRestore.insert(pDebugEvent->dwThreadId,_currentBP);
                getXInfoDB()->_setStep(breakPointInfo.hThread);
            }

            if(bThreadsSuspended)
            {
                getXInfoDB()->resumeOtherThreads(breakPointInfo.hThread);
            }

            nResult=DBG_CONTINUE;
        }
        else
        {
            if(getOptions()->bBreakpointOnSystem)
            {
                qDebug("SYSTEM BP SOFTWARE");
                breakPointInfo.bpType=XInfoDB::BPT_CODE_SOFTWARE;
                breakPointInfo.bpInfo=XInfoDB::BPI_SYSTEM;

                emit eventBreakPoint(&breakPointInfo);
            }
        }
    }
    else if((nExceptionCode==EXCEPTION_SINGLE_STEP)||(nExceptionCode==0x4000001e)) // 4000001e WOW64 single step exception
    {
        // Single step
        if(g_mapThreadBPToRestore.contains(pDebugEvent->dwThreadId))
        {
            XInfoDB::BREAKPOINT _currentBP=g_mapThreadBPToRestore.value(pDebugEvent->dwThreadId);
            getXInfoDB()->addBreakPoint(_currentBP.nAddress,_currentBP.bpType,_currentBP.bpInfo,_currentBP.nCount,_currentBP.sInfo);
            g_mapThreadBPToRestore.remove(pDebugEvent->dwThreadId);

            nResult=DBG_CONTINUE;
        }

        if(getXInfoDB()->getThreadBreakpoints()->contains(pDebugEvent->dwThreadId))
        {
            XInfoDB::BREAKPOINT stepBP=getXInfoDB()->getThreadBreakpoints()->value(pDebugEvent->dwThreadId);

            getXInfoDB()->getThreadBreakpoints()->remove(pDebugEvent->dwThreadId);

            bool bThreadsSuspended=getXInfoDB()->suspendOtherThreads(breakPointInfo.hThread);

            breakPointInfo.bpType=stepBP.bpType;
            breakPointInfo.bpInfo=stepBP.bpInfo;
            breakPointInfo.sInfo=stepBP.sInfo;

            emit eventBreakPoint(&breakPointInfo);

            if(bThreadsSuspended)
            {
                getXInfoDB()->resumeOtherThreads(breakPointInfo.hThread);
            }

            nResult=DBG_CONTINUE;
        }

        if(getOptions()->bBreakpointOnSystem)
        {
            qDebug("SYSTEM BP HARDWARE");
            breakPointInfo.bpType=XInfoDB::BPT_CODE_HARDWARE;
            breakPointInfo.bpInfo=XInfoDB::BPI_SYSTEM;

            emit eventBreakPoint(&breakPointInfo);
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

    return nResult;
}

quint32 XWindowsDebugger::on_CREATE_THREAD_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent)
{
    XInfoDB::THREAD_INFO threadInfo={};
    threadInfo.nThreadID=pDebugEvent->dwThreadId;
    threadInfo.hThread=pDebugEvent->u.CreateThread.hThread;
    threadInfo.nStartAddress=(qint64)pDebugEvent->u.CreateThread.lpStartAddress;
    threadInfo.nThreadLocalBase=(qint64)pDebugEvent->u.CreateThread.lpThreadLocalBase;
    getXInfoDB()->addThreadInfo(&threadInfo);

    emit eventCreateThread(&threadInfo);

    return DBG_CONTINUE;
}

quint32 XWindowsDebugger::on_CREATE_PROCESS_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent)
{
    XInfoDB::PROCESS_INFO processInfo={};
    processInfo.nProcessID=pDebugEvent->dwProcessId;
    processInfo.nMainThreadID=pDebugEvent->dwThreadId;
    processInfo.hProcess=pDebugEvent->u.CreateProcessInfo.hProcess;
    processInfo.hMainThread=pDebugEvent->u.CreateProcessInfo.hThread;
    processInfo.nImageBase=(qint64)(pDebugEvent->u.CreateProcessInfo.lpBaseOfImage);
    processInfo.nImageSize=XProcess::getRegionAllocationSize(processInfo.hProcess,processInfo.nImageBase);
    processInfo.nStartAddress=(qint64)(pDebugEvent->u.CreateProcessInfo.lpStartAddress); // TODO Check value
    processInfo.sFileName=XProcess::getFileNameByHandle(pDebugEvent->u.CreateProcessInfo.hFile);
    processInfo.sBaseFileName=XBinary::getBaseFileName(processInfo.sFileName);
    processInfo.nThreadLocalBase=(qint64)(pDebugEvent->u.CreateProcessInfo.lpThreadLocalBase);

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

    XInfoDB::THREAD_INFO threadInfo={};
    threadInfo.nThreadID=pDebugEvent->dwThreadId;
    threadInfo.hThread=pDebugEvent->u.CreateProcessInfo.hThread;
    threadInfo.nStartAddress=(qint64)(pDebugEvent->u.CreateProcessInfo.lpStartAddress);
    threadInfo.nThreadLocalBase=(qint64)(pDebugEvent->u.CreateProcessInfo.lpThreadLocalBase);
    getXInfoDB()->addThreadInfo(&threadInfo);

    if(getOptions()->bBreakpointOnProgramEntryPoint)
    {
        getXInfoDB()->addBreakPoint((qint64)(pDebugEvent->u.CreateProcessInfo.lpStartAddress),XInfoDB::BPT_CODE_SOFTWARE,XInfoDB::BPI_PROGRAMENTRYPOINT,1);
    }
    // TODO DLLMain

    emit eventCreateProcess(&processInfo);

    return DBG_CONTINUE;
}

quint32 XWindowsDebugger::on_EXIT_THREAD_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent)
{
    XInfoDB::THREAD_INFO threadInfo=getXInfoDB()->findThreadInfoByID((qint64)(pDebugEvent->dwThreadId));
    getXInfoDB()->removeThreadInfo(threadInfo.nThreadID);

    XInfoDB::EXITTHREAD_INFO exitThreadInfo={};
    exitThreadInfo.nThreadID=pDebugEvent->dwThreadId;
    exitThreadInfo.nExitCode=pDebugEvent->u.ExitThread.dwExitCode;

    emit eventExitThread(&exitThreadInfo);

    return DBG_CONTINUE;
}

quint32 XWindowsDebugger::on_EXIT_PROCESS_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent)
{
    setDebugActive(false);

    XInfoDB::EXITPROCESS_INFO exitProcessInfo={};
    exitProcessInfo.nProcessID=pDebugEvent->dwProcessId;
    exitProcessInfo.nThreadID=pDebugEvent->dwThreadId;
    exitProcessInfo.nExitCode=pDebugEvent->u.ExitProcess.dwExitCode;

    XInfoDB::THREAD_INFO threadInfo=getXInfoDB()->findThreadInfoByID((qint64)(pDebugEvent->dwThreadId));
    getXInfoDB()->removeThreadInfo(threadInfo.nThreadID);

    emit eventExitProcess(&exitProcessInfo);

    return DBG_CONTINUE;
}

quint32 XWindowsDebugger::on_LOAD_DLL_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent)
{
    XInfoDB::SHAREDOBJECT_INFO sharedObjectInfo={};
    sharedObjectInfo.nImageBase=(qint64)(pDebugEvent->u.LoadDll.lpBaseOfDll);
    sharedObjectInfo.nImageSize=XProcess::getRegionAllocationSize(getXInfoDB()->getProcessInfo()->hProcess,sharedObjectInfo.nImageBase);
    sharedObjectInfo.sFileName=XProcess::getFileNameByHandle(pDebugEvent->u.LoadDll.hFile);
    sharedObjectInfo.sName=QFileInfo(sharedObjectInfo.sFileName).fileName().toUpper();

    getXInfoDB()->addSharedObjectInfo(&sharedObjectInfo);

    // mb TODO add api breakpoints If set

    emit eventLoadSharedObject(&sharedObjectInfo);

    return DBG_CONTINUE;
}

quint32 XWindowsDebugger::on_UNLOAD_DLL_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent)
{
    XInfoDB::SHAREDOBJECT_INFO sharedObjectInfo=getXInfoDB()->getSharedObjectInfos()->value((qint64)(pDebugEvent->u.UnloadDll.lpBaseOfDll)); // TODO make findByAddressFunction
    getXInfoDB()->removeSharedObjectInfo(&sharedObjectInfo);

    // XBinary::removeFunctionAddressesByModule(&g_mapFunctionAddresses,sharedObjectInfo.nImageBase);

    // mb TODO disable api breakpoints If Set

    emit eventUnloadSharedObject(&sharedObjectInfo);

    return DBG_CONTINUE;
}

quint32 XWindowsDebugger::on_OUTPUT_DEBUG_STRING_EVENT(DEBUG_EVENT *pDebugEvent)
{
    XInfoDB::DEBUGSTRING_INFO debugStringInfo={};
    debugStringInfo.nThreadID=pDebugEvent->dwThreadId;

    if(pDebugEvent->u.DebugString.fUnicode)
    {
        debugStringInfo.sDebugString=getXInfoDB()->read_unicodeString((qint64)(pDebugEvent->u.DebugString.lpDebugStringData),pDebugEvent->u.DebugString.nDebugStringLength);
    }
    else
    {
        debugStringInfo.sDebugString=getXInfoDB()->read_ansiString((qint64)(pDebugEvent->u.DebugString.lpDebugStringData),pDebugEvent->u.DebugString.nDebugStringLength);
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
