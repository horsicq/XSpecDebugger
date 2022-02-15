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

XWindowsDebugger::XWindowsDebugger(QObject *pParent) : XAbstractDebugger(pParent)
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
    return (bool)TerminateProcess(getProcessInfo()->hProcessMemoryIO,0);
}

void XWindowsDebugger::cleanUp()
{
    XWindowsDebugger::stop();

    XAbstractDebugger::cleanUp();
    setDebugActive(false);
    g_mapThreadBPToRestore.clear();
    g_mapThreadSteps.clear();
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

QList<XBinary::SYMBOL_RECORD> XWindowsDebugger::loadSymbols(QString sFileName, qint64 nModuleAddress)
{
    QList<XBinary::SYMBOL_RECORD> listResult;

    QFile file;
    file.setFileName(sFileName);

    if(file.open(QIODevice::ReadOnly))
    {
        XPE pe(&file,false,nModuleAddress);

        if(pe.isValid())
        {
            XBinary::_MEMORY_MAP memoryMap=pe.getMemoryMap();
            listResult=pe.getSymbolRecords(&memoryMap);
        }

        file.close();
    }

    return listResult;
}

QMap<QString, XBinary::XVARIANT> XWindowsDebugger::getRegisters(XProcess::HANDLEID handleID, REG_OPTIONS regOptions)
{
    QMap<QString, XBinary::XVARIANT> mapResult;

    if(handleID.hHandle)
    {
        CONTEXT context={0};
        context.ContextFlags=CONTEXT_ALL; // All registers TODO Check regOptions | CONTEXT_FLOATING_POINT | CONTEXT_EXTENDED_REGISTERS;

        if(GetThreadContext(handleID.hHandle,&context))
        {
            XBinary::XVARIANT xVariant={};
            xVariant.bIsBigEndian=false;

            if(regOptions.bGeneral)
            {
                xVariant={};
            #ifndef Q_OS_WIN64
                xVariant.mode=XBinary::MODE_32;
                xVariant.var.v_uint32=(quint32)(context.Eax);
                mapResult.insert("EAX",xVariant);
                xVariant.var.v_uint32=(quint32)(context.Ebx);
                mapResult.insert("EBX",xVariant);
                xVariant.var.v_uint32=(quint32)(context.Ecx);
                mapResult.insert("ECX",xVariant);
                xVariant.var.v_uint32=(quint32)(context.Edx);
                mapResult.insert("EDX",xVariant);
                xVariant.var.v_uint32=(quint32)(context.Ebp);
                mapResult.insert("EBP",xVariant);
                xVariant.var.v_uint32=(quint32)(context.Esp);
                mapResult.insert("ESP",xVariant);
                xVariant.var.v_uint32=(quint32)(context.Esi);
                mapResult.insert("ESI",xVariant);
                xVariant.var.v_uint32=(quint32)(context.Edi);
                mapResult.insert("EDI",xVariant);
            #else
                xVariant.mode=XBinary::MODE_64;
                xVariant.var.v_uint64=(quint64)(context.Rax);
                mapResult.insert("RAX",xVariant);
                xVariant.var.v_uint64=(quint64)(context.Rbx);
                mapResult.insert("RBX",xVariant);
                xVariant.var.v_uint64=(quint64)(context.Rcx);
                mapResult.insert("RCX",xVariant);
                xVariant.var.v_uint64=(quint64)(context.Rdx);
                mapResult.insert("RDX",xVariant);
                xVariant.var.v_uint64=(quint64)(context.Rbp);
                mapResult.insert("RBP",xVariant);
                xVariant.var.v_uint64=(quint64)(context.Rsp);
                mapResult.insert("RSP",xVariant);
                xVariant.var.v_uint64=(quint64)(context.Rsi);
                mapResult.insert("RSI",xVariant);
                xVariant.var.v_uint64=(quint64)(context.Rdi);
                mapResult.insert("RDI",xVariant);
                xVariant.var.v_uint64=(quint64)(context.R8);
                mapResult.insert("R8",xVariant);
                xVariant.var.v_uint64=(quint64)(context.R9);
                mapResult.insert("R9",xVariant);
                xVariant.var.v_uint64=(quint64)(context.R10);
                mapResult.insert("R10",xVariant);
                xVariant.var.v_uint64=(quint64)(context.R11);
                mapResult.insert("R11",xVariant);
                xVariant.var.v_uint64=(quint64)(context.R12);
                mapResult.insert("R12",xVariant);
                xVariant.var.v_uint64=(quint64)(context.R13);
                mapResult.insert("R13",xVariant);
                xVariant.var.v_uint64=(quint64)(context.R14);
                mapResult.insert("R14",xVariant);
                xVariant.var.v_uint64=(quint64)(context.R15);
                mapResult.insert("R15",xVariant);
            #endif
            }

            if(regOptions.bIP)
            {
                xVariant={};
            #ifndef Q_OS_WIN64
                xVariant.mode=XBinary::MODE_32;
                xVariant.var.v_uint32=(quint32)(context.Eip);
                mapResult.insert("EIP",xVariant);
            #else
                xVariant.mode=XBinary::MODE_64;
                xVariant.var.v_uint64=(quint64)(context.Rip);
                mapResult.insert("RIP",xVariant);
            #endif
            }

            if(regOptions.bFlags)
            {
                xVariant={};

                xVariant.mode=XBinary::MODE_32;
                xVariant.var.v_uint32=(quint32)(context.EFlags);
                mapResult.insert("EFLAGS",xVariant);

                xVariant={};
                xVariant.mode=XBinary::MODE_BIT;
                xVariant.var.v_bool=(bool)((context.EFlags)&0x0001);
                mapResult.insert("CF",xVariant);
                xVariant.var.v_bool=(bool)((context.EFlags)&0x0004);
                mapResult.insert("PF",xVariant);
                xVariant.var.v_bool=(bool)((context.EFlags)&0x0010);
                mapResult.insert("AF",xVariant);
                xVariant.var.v_bool=(bool)((context.EFlags)&0x0040);
                mapResult.insert("ZF",xVariant);
                xVariant.var.v_bool=(bool)((context.EFlags)&0x0080);
                mapResult.insert("SF",xVariant);
                xVariant.var.v_bool=(bool)((context.EFlags)&0x0100);
                mapResult.insert("TF",xVariant);
                xVariant.var.v_bool=(bool)((context.EFlags)&0x0200);
                mapResult.insert("IF",xVariant);
                xVariant.var.v_bool=(bool)((context.EFlags)&0x0400);
                mapResult.insert("DF",xVariant);
                xVariant.var.v_bool=(bool)((context.EFlags)&0x0800);
                mapResult.insert("OF",xVariant);
            }

            if(regOptions.bSegments)
            {
                xVariant={};

                xVariant.mode=XBinary::MODE_16;
                xVariant.var.v_uint16=(quint16)(context.SegGs);
                mapResult.insert("GS",xVariant);
                xVariant.var.v_uint16=(quint16)(context.SegFs);
                mapResult.insert("FS",xVariant);
                xVariant.var.v_uint16=(quint16)(context.SegEs);
                mapResult.insert("ES",xVariant);
                xVariant.var.v_uint16=(quint16)(context.SegDs);
                mapResult.insert("DS",xVariant);
                xVariant.var.v_uint16=(quint16)(context.SegCs);
                mapResult.insert("CS",xVariant);
                xVariant.var.v_uint16=(quint16)(context.SegSs);
                mapResult.insert("SS",xVariant);
            }

            if(regOptions.bDebug)
            {
                xVariant={};
            #ifndef Q_OS_WIN64
                xVariant.mode=XBinary::MODE_32;
                xVariant.var.v_uint32=(quint32)(context.Dr0);
                mapResult.insert("DR0",xVariant);
                xVariant.var.v_uint32=(quint32)(context.Dr1);
                mapResult.insert("DR1",xVariant);
                xVariant.var.v_uint32=(quint32)(context.Dr2);
                mapResult.insert("DR2",xVariant);
                xVariant.var.v_uint32=(quint32)(context.Dr3);
                mapResult.insert("DR3",xVariant);
                xVariant.var.v_uint32=(quint32)(context.Dr6);
                mapResult.insert("DR6",xVariant);
                xVariant.var.v_uint32=(quint32)(context.Dr7);
                mapResult.insert("DR7",xVariant);
            #else
                xVariant.mode=XBinary::MODE_64;
                xVariant.var.v_uint64=(quint64)(context.Dr0);
                mapResult.insert("DR0",xVariant);
                xVariant.var.v_uint64=(quint64)(context.Dr0);
                mapResult.insert("DR1",xVariant);
                xVariant.var.v_uint64=(quint64)(context.Dr0);
                mapResult.insert("DR2",xVariant);
                xVariant.var.v_uint64=(quint64)(context.Dr0);
                mapResult.insert("DR3",xVariant);
                xVariant.var.v_uint64=(quint64)(context.Dr0);
                mapResult.insert("DR6",xVariant);
                xVariant.var.v_uint64=(quint64)(context.Dr0);
                mapResult.insert("DR7",xVariant);
            #endif
            }

            if(regOptions.bFloat)
            {
                xVariant={};
                xVariant.mode=XBinary::MODE_128;
            #if defined(Q_PROCESSOR_X86_64)
                xVariant.var.v_uint128.low=(quint64)(context.FltSave.FloatRegisters[0].Low);
                xVariant.var.v_uint128.high=(quint64)(context.FltSave.FloatRegisters[0].High);
                mapResult.insert("ST0",xVariant);
                xVariant.var.v_uint128.low=(quint64)(context.FltSave.FloatRegisters[1].Low);
                xVariant.var.v_uint128.high=(quint64)(context.FltSave.FloatRegisters[1].High);
                mapResult.insert("ST1",xVariant);
                xVariant.var.v_uint128.low=(quint64)(context.FltSave.FloatRegisters[2].Low);
                xVariant.var.v_uint128.high=(quint64)(context.FltSave.FloatRegisters[2].High);
                mapResult.insert("ST2",xVariant);
                xVariant.var.v_uint128.low=(quint64)(context.FltSave.FloatRegisters[3].Low);
                xVariant.var.v_uint128.high=(quint64)(context.FltSave.FloatRegisters[3].High);
                mapResult.insert("ST3",xVariant);
                xVariant.var.v_uint128.low=(quint64)(context.FltSave.FloatRegisters[4].Low);
                xVariant.var.v_uint128.high=(quint64)(context.FltSave.FloatRegisters[4].High);
                mapResult.insert("ST4",xVariant);
                xVariant.var.v_uint128.low=(quint64)(context.FltSave.FloatRegisters[5].Low);
                xVariant.var.v_uint128.high=(quint64)(context.FltSave.FloatRegisters[5].High);
                mapResult.insert("ST5",xVariant);
                xVariant.var.v_uint128.low=(quint64)(context.FltSave.FloatRegisters[6].Low);
                xVariant.var.v_uint128.high=(quint64)(context.FltSave.FloatRegisters[6].High);
                mapResult.insert("ST6",xVariant);
                xVariant.var.v_uint128.low=(quint64)(context.FltSave.FloatRegisters[7].Low);
                xVariant.var.v_uint128.high=(quint64)(context.FltSave.FloatRegisters[7].High);
                mapResult.insert("ST7",xVariant);
            #endif
            }

            if(regOptions.bXMM)
            {
                xVariant={};
                xVariant.mode=XBinary::MODE_128;
            #if defined(Q_PROCESSOR_X86_64)
                xVariant.var.v_uint128.low=(quint64)(context.FltSave.XmmRegisters[0].Low);
                xVariant.var.v_uint128.high=(quint64)(context.FltSave.XmmRegisters[0].High);
                mapResult.insert("XMM0",xVariant);
                xVariant.var.v_uint128.low=(quint64)(context.FltSave.XmmRegisters[1].Low);
                xVariant.var.v_uint128.high=(quint64)(context.FltSave.XmmRegisters[1].High);
                mapResult.insert("XMM1",xVariant);
                xVariant.var.v_uint128.low=(quint64)(context.FltSave.XmmRegisters[2].Low);
                xVariant.var.v_uint128.high=(quint64)(context.FltSave.XmmRegisters[2].High);
                mapResult.insert("XMM2",xVariant);
                xVariant.var.v_uint128.low=(quint64)(context.FltSave.XmmRegisters[3].Low);
                xVariant.var.v_uint128.high=(quint64)(context.FltSave.XmmRegisters[3].High);
                mapResult.insert("XMM3",xVariant);
                xVariant.var.v_uint128.low=(quint64)(context.FltSave.XmmRegisters[4].Low);
                xVariant.var.v_uint128.high=(quint64)(context.FltSave.XmmRegisters[4].High);
                mapResult.insert("XMM4",xVariant);
                xVariant.var.v_uint128.low=(quint64)(context.FltSave.XmmRegisters[5].Low);
                xVariant.var.v_uint128.high=(quint64)(context.FltSave.XmmRegisters[5].High);
                mapResult.insert("XMM5",xVariant);
                xVariant.var.v_uint128.low=(quint64)(context.FltSave.XmmRegisters[6].Low);
                xVariant.var.v_uint128.high=(quint64)(context.FltSave.XmmRegisters[6].High);
                mapResult.insert("XMM6",xVariant);
                xVariant.var.v_uint128.low=(quint64)(context.FltSave.XmmRegisters[7].Low);
                xVariant.var.v_uint128.high=(quint64)(context.FltSave.XmmRegisters[7].High);
                mapResult.insert("XMM7",xVariant);
                xVariant.var.v_uint128.low=(quint64)(context.FltSave.XmmRegisters[8].Low);
                xVariant.var.v_uint128.high=(quint64)(context.FltSave.XmmRegisters[8].High);
                mapResult.insert("XMM8",xVariant);
                xVariant.var.v_uint128.low=(quint64)(context.FltSave.XmmRegisters[9].Low);
                xVariant.var.v_uint128.high=(quint64)(context.FltSave.XmmRegisters[9].High);
                mapResult.insert("XMM9",xVariant);
                xVariant.var.v_uint128.low=(quint64)(context.FltSave.XmmRegisters[10].Low);
                xVariant.var.v_uint128.high=(quint64)(context.FltSave.XmmRegisters[10].High);
                mapResult.insert("XMM10",xVariant);
                xVariant.var.v_uint128.low=(quint64)(context.FltSave.XmmRegisters[11].Low);
                xVariant.var.v_uint128.high=(quint64)(context.FltSave.XmmRegisters[11].High);
                mapResult.insert("XMM11",xVariant);
                xVariant.var.v_uint128.low=(quint64)(context.FltSave.XmmRegisters[12].Low);
                xVariant.var.v_uint128.high=(quint64)(context.FltSave.XmmRegisters[12].High);
                mapResult.insert("XMM12",xVariant);
                xVariant.var.v_uint128.low=(quint64)(context.FltSave.XmmRegisters[13].Low);
                xVariant.var.v_uint128.high=(quint64)(context.FltSave.XmmRegisters[13].High);
                mapResult.insert("XMM13",xVariant);
                xVariant.var.v_uint128.low=(quint64)(context.FltSave.XmmRegisters[14].Low);
                xVariant.var.v_uint128.high=(quint64)(context.FltSave.XmmRegisters[14].High);
                mapResult.insert("XMM14",xVariant);
                xVariant.var.v_uint128.low=(quint64)(context.FltSave.XmmRegisters[15].Low);
                xVariant.var.v_uint128.high=(quint64)(context.FltSave.XmmRegisters[15].High);
                mapResult.insert("XMM15",xVariant);
            #endif
    //            mapResult.insert("MxCsr",(quint32)(context.MxCsr));
            }

        #ifdef QT_DEBUG
    //        qDebug("DebugControl %s",XBinary::valueToHex((quint64)(context.DebugControl)).toLatin1().data());
    //        qDebug("LastBranchToRip %s",XBinary::valueToHex((quint64)(context.LastBranchToRip)).toLatin1().data());
    //        qDebug("LastBranchFromRip %s",XBinary::valueToHex((quint64)(context.LastBranchFromRip)).toLatin1().data());
    //        qDebug("LastExceptionToRip %s",XBinary::valueToHex((quint64)(context.LastExceptionToRip)).toLatin1().data());
    //        qDebug("LastExceptionFromRip %s",XBinary::valueToHex((quint64)(context.LastExceptionFromRip)).toLatin1().data());
         #if defined(Q_PROCESSOR_X86_64)
            qDebug("P1Home %s",XBinary::valueToHex((quint64)(context.P1Home)).toLatin1().data());
            qDebug("P2Home %s",XBinary::valueToHex((quint64)(context.P2Home)).toLatin1().data());
            qDebug("P3Home %s",XBinary::valueToHex((quint64)(context.P3Home)).toLatin1().data());
            qDebug("P4Home %s",XBinary::valueToHex((quint64)(context.P4Home)).toLatin1().data());
            qDebug("P5Home %s",XBinary::valueToHex((quint64)(context.P5Home)).toLatin1().data());
            qDebug("P6Home %s",XBinary::valueToHex((quint64)(context.P6Home)).toLatin1().data());
            qDebug("ContextFlags %s",XBinary::valueToHex((quint32)(context.ContextFlags)).toLatin1().data());
            qDebug("MxCsr %s",XBinary::valueToHex((quint32)(context.MxCsr)).toLatin1().data());
         #endif
        #endif
        }
    }
    else if(handleID.nID)
    {
        handleID.hHandle=XProcess::openThread(handleID.nID);

        if(handleID.hHandle)
        {
            mapResult=getRegisters(handleID,regOptions);

            XProcess::closeThread(handleID.hHandle);
        }
    }

    return mapResult;
}

bool XWindowsDebugger::_setStep(XProcess::HANDLEID handleID)
{
    bool bResult=false;

    if(handleID.hHandle)
    {
        CONTEXT context={0};
        context.ContextFlags=CONTEXT_CONTROL; // EFLAGS

        if(GetThreadContext(handleID.hHandle,&context))
        {
            if(!(context.EFlags&0x100))
            {
                context.EFlags|=0x100;
            }

            if(SetThreadContext(handleID.hHandle,&context))
            {
                bResult=true;
            }
        }
    }
    else if(handleID.nID)
    {
        handleID.hHandle=XProcess::openThread(handleID.nID);

        if(handleID.hHandle)
        {
            bResult=_setStep(handleID);

            XProcess::closeThread(handleID.hHandle);
        }
    }

    return bResult;
}

quint32 XWindowsDebugger::on_EXCEPTION_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent)
{
    quint32 nResult=DBG_EXCEPTION_NOT_HANDLED;

    quint32 nExceptionCode=pDebugEvent->u.Exception.ExceptionRecord.ExceptionCode;
    quint64 nExceptionAddress=(qint64)(pDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress);

    XProcess::HANDLEID handleIDThread={};
    handleIDThread.hHandle=getThreadInfos()->value(pDebugEvent->dwThreadId).hThread;
    handleIDThread.nID=pDebugEvent->dwThreadId;

    XProcess::HANDLEID handleIDProcess={};
    handleIDProcess.hHandle=getProcessInfo()->hProcessMemoryIO;
    handleIDProcess.nID=getProcessInfo()->nProcessID;

    if((nExceptionCode==EXCEPTION_BREAKPOINT)||(nExceptionCode==0x4000001f)) // 4000001f WOW64 breakpoint
    {
        if(getSoftwareBreakpoints()->contains(nExceptionAddress))
        {
            bool bThreadsSuspended=suspendOtherThreads(handleIDThread);

            BREAKPOINT _currentBP=getSoftwareBreakpoints()->value(nExceptionAddress);

            setCurrentAddress(handleIDThread,nExceptionAddress); // go to prev instruction address

            removeBP(nExceptionAddress,_currentBP.bpType);

            if(getFunctionHookInfos()->contains(_currentBP.sInfo))
            {
                // TODO handle_Kernel32_GetProcAddress

                if(_currentBP.bpInfo==BPI_FUNCTIONENTER)
                {
                    QString sUUID=XBinary::generateUUID();
                    FUNCTION_INFO functionInfo=getFunctionInfo(handleIDThread,_currentBP.sInfo);

                    g_mapFunctionInfos.insert(sUUID,functionInfo);

                    emit eventFunctionEnter(&functionInfo);

                    setBP(functionInfo.nRetAddress,BPT_CODE_SOFTWARE,BPI_FUNCTIONLEAVE,1,_currentBP.sInfo,sUUID);
                }
                else if(_currentBP.bpInfo==BPI_FUNCTIONLEAVE)
                {
                    FUNCTION_INFO functionInfo=g_mapFunctionInfos.value(_currentBP.sGUID);

                    emit eventFunctionLeave(&functionInfo);

                    g_mapFunctionInfos.remove(_currentBP.sGUID);
                }
            }
            else
            {
                XAbstractDebugger::BREAKPOINT_INFO breakPointInfo={};

                breakPointInfo.nAddress=nExceptionAddress;
                breakPointInfo.bpType=_currentBP.bpType;
                breakPointInfo.bpInfo=_currentBP.bpInfo;
                breakPointInfo.sInfo=_currentBP.sInfo;
                breakPointInfo.handleThread=handleIDThread;
                breakPointInfo.handleProcessMemoryIO=handleIDProcess;
                breakPointInfo.handleProcessMemoryQuery=handleIDProcess;

                if(!g_mapThreadSteps.contains(pDebugEvent->dwThreadId)) // If not step. For step there is an another callback
                {
                    if(breakPointInfo.bpInfo==BPI_PROGRAMENTRYPOINT)
                    {
                        emit eventProgramEntryPoint(&breakPointInfo); // TODO for DLL
                    }
                    else if(breakPointInfo.bpInfo==BPI_TLSFUNCTION)
                    {
                        emit eventTLSFunction(&breakPointInfo); // TODO
                        // TODO set BP on next TLS function
                    }
                    else if(breakPointInfo.bpInfo==BPI_STEPOVER)
                    {
                        emit eventStepOver(&breakPointInfo);
                    }
                    else
                    {
                        emit eventBreakPoint(&breakPointInfo);
                    }
                }
            }

            if(_currentBP.nCount!=-1)
            {
                _currentBP.nCount--;
            }

            if(_currentBP.nCount)
            {
                g_mapThreadBPToRestore.insert(pDebugEvent->dwThreadId,_currentBP);
                _setStep(handleIDThread);
            }

            if(bThreadsSuspended)
            {
                resumeOtherThreads(handleIDThread);
            }

            nResult=DBG_CONTINUE;
        }
    }
    else if((nExceptionCode==EXCEPTION_SINGLE_STEP)||(nExceptionCode==0x4000001e)) // 4000001e WOW64 single step exception
    {
        // Single step
        if(g_mapThreadBPToRestore.contains(pDebugEvent->dwThreadId))
        {
            BREAKPOINT _currentBP=g_mapThreadBPToRestore.value(pDebugEvent->dwThreadId);
            setBP(_currentBP.nAddress,_currentBP.bpType,_currentBP.bpInfo,_currentBP.nCount,_currentBP.sInfo);
            g_mapThreadBPToRestore.remove(pDebugEvent->dwThreadId);

            nResult=DBG_CONTINUE;
        }

        if(g_mapThreadSteps.contains(pDebugEvent->dwThreadId))
        {
            BREAKPOINT stepBP=g_mapThreadSteps.value(pDebugEvent->dwThreadId);

            g_mapThreadSteps.remove(pDebugEvent->dwThreadId);

            bool bThreadsSuspended=suspendOtherThreads(handleIDThread);

            XAbstractDebugger::BREAKPOINT_INFO breakPointInfo={};

            breakPointInfo.nAddress=nExceptionAddress;
            breakPointInfo.bpType=stepBP.bpType;
            breakPointInfo.bpInfo=stepBP.bpInfo;
            breakPointInfo.handleThread=handleIDThread;
            breakPointInfo.handleProcessMemoryIO=handleIDProcess;
            breakPointInfo.sInfo=stepBP.sInfo;

            if(breakPointInfo.bpInfo==BPI_STEP)
            {
                emit eventStep(&breakPointInfo);
            }
            else if(breakPointInfo.bpInfo==BPI_STEPINTO)
            {
                emit eventStepInto(&breakPointInfo);
            }
            else if(breakPointInfo.bpInfo==BPI_STEPOVER)
            {
                emit eventStepOver(&breakPointInfo);
            }

            if(bThreadsSuspended)
            {
                resumeOtherThreads(handleIDThread);
            }

            nResult=DBG_CONTINUE;
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
    THREAD_INFO threadInfo={};
    threadInfo.nThreadID=pDebugEvent->dwThreadId;
    threadInfo.hThread=pDebugEvent->u.CreateThread.hThread;
    threadInfo.nStartAddress=(qint64)pDebugEvent->u.CreateThread.lpStartAddress;
    threadInfo.nThreadLocalBase=(qint64)pDebugEvent->u.CreateThread.lpThreadLocalBase;
    addThreadInfo(&threadInfo);

    emit eventCreateThread(&threadInfo);

    return DBG_CONTINUE;
}

quint32 XWindowsDebugger::on_CREATE_PROCESS_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent)
{
    PROCESS_INFO processInfo={};
    processInfo.nProcessID=pDebugEvent->dwProcessId;
    processInfo.nThreadID=pDebugEvent->dwThreadId;
    processInfo.hProcessMemoryIO=pDebugEvent->u.CreateProcessInfo.hProcess;
    processInfo.hProcessMemoryQuery=pDebugEvent->u.CreateProcessInfo.hProcess;
    processInfo.hMainThread=pDebugEvent->u.CreateProcessInfo.hThread;
    processInfo.nImageBase=(qint64)(pDebugEvent->u.CreateProcessInfo.lpBaseOfImage);
    processInfo.nImageSize=XProcess::getRegionAllocationSize(processInfo.hProcessMemoryIO,processInfo.nImageBase);
    processInfo.nStartAddress=(qint64)(pDebugEvent->u.CreateProcessInfo.lpStartAddress); // TODO Check value
    processInfo.sFileName=XProcess::getFileNameByHandle(pDebugEvent->u.CreateProcessInfo.hFile);
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

    setProcessInfo(&processInfo);

    THREAD_INFO threadInfo={};
    threadInfo.nThreadID=pDebugEvent->dwThreadId;
    threadInfo.hThread=pDebugEvent->u.CreateProcessInfo.hThread;
    threadInfo.nStartAddress=(qint64)(pDebugEvent->u.CreateProcessInfo.lpStartAddress);
    threadInfo.nThreadLocalBase=(qint64)(pDebugEvent->u.CreateProcessInfo.lpThreadLocalBase);
    addThreadInfo(&threadInfo);

    if(getOptions()->bBreakpointOnProgramEntryPoint)
    {
        setBP((qint64)(pDebugEvent->u.CreateProcessInfo.lpStartAddress),BPT_CODE_SOFTWARE,BPI_PROGRAMENTRYPOINT,1);
    }
    // TODO DLLMain

    emit eventCreateProcess(&processInfo);

    return DBG_CONTINUE;
}

quint32 XWindowsDebugger::on_EXIT_THREAD_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent)
{
    THREAD_INFO threadInfo=getThreadInfos()->value((qint64)(pDebugEvent->dwThreadId));
    removeThreadInfo(&threadInfo);

    EXITTHREAD_INFO exitThreadInfo={};
    exitThreadInfo.nThreadID=pDebugEvent->dwThreadId;
    exitThreadInfo.nExitCode=pDebugEvent->u.ExitThread.dwExitCode;

    emit eventExitThread(&exitThreadInfo);

    return DBG_CONTINUE;
}

quint32 XWindowsDebugger::on_EXIT_PROCESS_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent)
{
    setDebugActive(false);

    EXITPROCESS_INFO exitProcessInfo={};
    exitProcessInfo.nProcessID=pDebugEvent->dwProcessId;
    exitProcessInfo.nThreadID=pDebugEvent->dwThreadId;
    exitProcessInfo.nExitCode=pDebugEvent->u.ExitProcess.dwExitCode;

    THREAD_INFO threadInfo=getThreadInfos()->value((qint64)(pDebugEvent->dwThreadId));
    removeThreadInfo(&threadInfo);

    emit eventExitProcess(&exitProcessInfo);

    return DBG_CONTINUE;
}

quint32 XWindowsDebugger::on_LOAD_DLL_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent)
{
    SHAREDOBJECT_INFO sharedObjectInfo={};
    sharedObjectInfo.nImageBase=(qint64)(pDebugEvent->u.LoadDll.lpBaseOfDll);
    sharedObjectInfo.nImageSize=XProcess::getRegionAllocationSize(getProcessInfo()->hProcessMemoryQuery,sharedObjectInfo.nImageBase);
    sharedObjectInfo.sFileName=XProcess::getFileNameByHandle(pDebugEvent->u.LoadDll.hFile);
    sharedObjectInfo.sName=QFileInfo(sharedObjectInfo.sFileName).fileName().toUpper();

    addSharedObjectInfo(&sharedObjectInfo);

    // mb TODO add api breakpoints If set

    emit eventLoadSharedObject(&sharedObjectInfo);

    return DBG_CONTINUE;
}

quint32 XWindowsDebugger::on_UNLOAD_DLL_DEBUG_EVENT(DEBUG_EVENT *pDebugEvent)
{
    SHAREDOBJECT_INFO sharedObjectInfo=getSharedObjectInfos()->value((qint64)(pDebugEvent->u.UnloadDll.lpBaseOfDll));
    removeSharedObjectInfo(&sharedObjectInfo);

//    XBinary::removeFunctionAddressesByModule(&g_mapFunctionAddresses,sharedObjectInfo.nImageBase);

    // mb TODO disable api breakpoints If Set

    emit eventUnloadSharedObject(&sharedObjectInfo);

    return DBG_CONTINUE;
}

quint32 XWindowsDebugger::on_OUTPUT_DEBUG_STRING_EVENT(DEBUG_EVENT *pDebugEvent)
{
    DEBUGSTRING_INFO debugStringInfo={};
    debugStringInfo.nThreadID=pDebugEvent->dwThreadId;

    if(pDebugEvent->u.DebugString.fUnicode)
    {
        debugStringInfo.sDebugString=read_unicodeString((qint64)(pDebugEvent->u.DebugString.lpDebugStringData),pDebugEvent->u.DebugString.nDebugStringLength);
    }
    else
    {
        debugStringInfo.sDebugString=read_ansiString((qint64)(pDebugEvent->u.DebugString.lpDebugStringData),pDebugEvent->u.DebugString.nDebugStringLength);
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
