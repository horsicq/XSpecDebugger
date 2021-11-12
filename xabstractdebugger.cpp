// copyright (c) 2020-2021 hors<horsicq@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
#include "xabstractdebugger.h"

XAbstractDebugger::XAbstractDebugger(QObject *pParent) : QObject(pParent)
{
    g_handle=0;
}

bool XAbstractDebugger::stop()
{
    return false;
}

void XAbstractDebugger::cleanUp()
{
    g_processInfo={};
    g_mapSharedObjectInfos.clear();
    XCapstone::closeHandle(&g_handle);
}

void XAbstractDebugger::setDisasmMode(XBinary::DM disasmMode)
{
    XCapstone::openHandle(disasmMode,&g_handle,true);
}

void XAbstractDebugger::setTraceFileName(QString sTraceFileName)
{
    g_sTraceFileName=sTraceFileName;
}

void XAbstractDebugger::clearTraceFile()
{
    if(g_sTraceFileName!="")
    {
        XBinary::clearFile(g_sTraceFileName);
    }
}

void XAbstractDebugger::writeToTraceFile(QString sString)
{
    if(g_sTraceFileName!="")
    {
        XBinary::appendToFile(g_sTraceFileName,sString);
    }
}

void XAbstractDebugger::setOptions(XAbstractDebugger::OPTIONS options)
{
    g_options=options;
}

XAbstractDebugger::OPTIONS *XAbstractDebugger::getOptions()
{
    return &g_options;
}

void XAbstractDebugger::setProcessInfo(XAbstractDebugger::PROCESS_INFO *pProcessInfo)
{
    g_processInfo=*pProcessInfo;
}

XAbstractDebugger::PROCESS_INFO *XAbstractDebugger::getProcessInfo()
{
    return &g_processInfo;
}

void XAbstractDebugger::_messageString(XAbstractDebugger::MT messageType, QString sText)
{
#ifdef QT_DEBUG
    qDebug("%s",sText.toLatin1().data());
#endif
    emit messageString(messageType,sText);
}

void XAbstractDebugger::addSharedObjectInfo(XAbstractDebugger::SHAREDOBJECT_INFO *pSharedObjectInfo)
{
    g_mapSharedObjectInfos.insert(pSharedObjectInfo->nImageBase,*pSharedObjectInfo);
}

void XAbstractDebugger::removeSharedObjectInfo(SHAREDOBJECT_INFO *pSharedObjectInfo)
{
    g_mapSharedObjectInfos.remove(pSharedObjectInfo->nImageBase);
}

void XAbstractDebugger::addThreadInfo(XAbstractDebugger::THREAD_INFO *pThreadInfo)
{
    g_mapThreadInfos.insert(pThreadInfo->nThreadID,*pThreadInfo);
}

void XAbstractDebugger::removeThreadInfo(XAbstractDebugger::THREAD_INFO *pThreadInfo)
{
    g_mapThreadInfos.remove(pThreadInfo->nThreadID);
}

void XAbstractDebugger::_addBreakpoint(XAbstractDebugger::BREAKPOINT *pBreakpoint)
{
    // TODO BP Types
    if(pBreakpoint->bpType==BPT_CODE_SOFTWARE)
    {
        g_mapSoftwareBreakpoints.insert(pBreakpoint->nAddress,*pBreakpoint);
    }
    else if(pBreakpoint->bpType==BPT_CODE_HARDWARE)
    {
        g_mapHardwareBreakpoints.insert(pBreakpoint->nAddress,*pBreakpoint);
    }
}

void XAbstractDebugger::_removeBreakpoint(XAbstractDebugger::BREAKPOINT *pBreakpoint)
{
    if(pBreakpoint->bpType==BPT_CODE_SOFTWARE)
    {
        g_mapSoftwareBreakpoints.remove(pBreakpoint->nAddress);
    }
    else if(pBreakpoint->bpType==BPT_CODE_HARDWARE)
    {
        g_mapHardwareBreakpoints.remove(pBreakpoint->nAddress);
    }
}

bool XAbstractDebugger::setBP(qint64 nAddress, XAbstractDebugger::BPT bpType, XAbstractDebugger::BPI bpInfo, qint32 nCount, QString sInfo, QString sGUID)
{
    bool bResult=true;

    if(bpType==BPT_CODE_SOFTWARE)
    {
        if(!g_mapSoftwareBreakpoints.contains(nAddress))
        {
            BREAKPOINT bp={};
            bp.nAddress=nAddress;
            bp.nSize=1;
            bp.nCount=nCount;
            bp.bpInfo=bpInfo;
            bp.bpType=bpType;
            bp.sInfo=sInfo;
            bp.sGUID=sGUID;

            bp.nOrigDataSize=1;

            if(read_array(nAddress,bp.origData,bp.nOrigDataSize)==bp.nOrigDataSize)
            {
                if(write_array(nAddress,(char *)"\xCC",bp.nOrigDataSize)) // TODO Check if x86
                {
                    _addBreakpoint(&bp);

                    bResult=true;
                }
            }
        }
    }
    else if(bpType==BPT_CODE_HARDWARE)
    {
        // TODO
    }

    return bResult;
}

bool XAbstractDebugger::removeBP(qint64 nAddress, BPT bpType)
{
    bool bResult=true;

    if(bpType==BPT_CODE_SOFTWARE)
    {
        if(g_mapSoftwareBreakpoints.contains(nAddress))
        {
            BREAKPOINT bp=g_mapSoftwareBreakpoints.value(nAddress);

            if(write_array(nAddress,(char *)bp.origData,bp.nOrigDataSize)) // TODO Check
            {
                _removeBreakpoint(&bp);

                bResult=true;
            }
        }
    }
    else if(bpType==BPT_CODE_HARDWARE)
    {
        // TODO
    }

    return bResult;
}

bool XAbstractDebugger::setSoftwareBreakpoint(qint64 nAddress, qint32 nCount, QString sInfo)
{
    return setBP(nAddress,BPT_CODE_SOFTWARE,BPI_USER,nCount,sInfo);
}

bool XAbstractDebugger::removeSoftwareBreakpoint(qint64 nAddress)
{
    return removeBP(nAddress,BPT_CODE_SOFTWARE);
}

bool XAbstractDebugger::isSoftwareBreakpointPresent(qint64 nAddress)
{
    return g_mapSoftwareBreakpoints.contains(nAddress);
}

bool XAbstractDebugger::setFunctionHook(QString sFunctionName)
{
    bool bResult=false;

    qint64 nFunctionAddress=getFunctionAddress(sFunctionName);

    if(nFunctionAddress!=-1)
    {
        bResult=setBP(nFunctionAddress,BPT_CODE_SOFTWARE,BPI_FUNCTIONENTER,-1,sFunctionName);

        FUNCTIONHOOK_INFO functionhook_info={};
        functionhook_info.sName=sFunctionName;
        functionhook_info.nAddress=nFunctionAddress;

        g_mapFunctionHookInfos.insert(sFunctionName,functionhook_info);
    }

    return bResult;
}

bool XAbstractDebugger::removeFunctionHook(QString sFunctionName)
{
    bool bResult=false;
    // TODO Check !!!
    for(QMap<qint64,BREAKPOINT>::iterator it=g_mapSoftwareBreakpoints.begin();it!=g_mapSoftwareBreakpoints.end();)
    {
        if(it.value().sInfo==sFunctionName)
        {
            it=g_mapSoftwareBreakpoints.erase(it);
        }
        else
        {
            ++it;
        }
    }

    if(g_mapFunctionHookInfos.contains(sFunctionName))
    {
        g_mapFunctionHookInfos.remove(sFunctionName);

        bResult=true;
    }

    return bResult;
}

qint64 XAbstractDebugger::getFunctionAddress(QString sFunctionName)
{
    qint64 nResult=-1;

    QString sLibrary=sFunctionName.section("#",0,0);
    QString sFunction=sFunctionName.section("#",1,1);
    qint32 nOrdinal=sFunction.toULongLong();

    SHAREDOBJECT_INFO sharedObjectInfo=findSharedInfoByName(sLibrary);

    if(sharedObjectInfo.sName!="")
    {
        QList<XBinary::SYMBOL_RECORD> listSymbols=loadSymbols(sharedObjectInfo.sFileName,sharedObjectInfo.nImageBase); // TODO Cache

        XBinary::SYMBOL_RECORD functionAddress={};

        if(nOrdinal)
        {
            functionAddress=XBinary::findSymbolByOrdinal(&listSymbols,nOrdinal);
        }
        else
        {
            functionAddress=XBinary::findSymbolByName(&listSymbols,sFunction);
        }

        if(functionAddress.nAddress)
        {
            nResult=functionAddress.nAddress;
        }
    }

    return nResult;
}

QString XAbstractDebugger::getAddressSymbolString(qint64 nAddress)
{
    QString sResult;

    SHAREDOBJECT_INFO sharedObjectInfo=findSharedInfoByAddress(nAddress);

    if(sharedObjectInfo.sName!="")
    {
        sResult+=sharedObjectInfo.sName+".";

        QList<XBinary::SYMBOL_RECORD> listSymbols=loadSymbols(sharedObjectInfo.sFileName,sharedObjectInfo.nImageBase); // TODO Cache

        XBinary::SYMBOL_RECORD functionAddress=XBinary::findSymbolByAddress(&listSymbols,nAddress);

        if(functionAddress.nAddress)
        {
            // mb TODO ordinals
            sResult+=functionAddress.sName;
        }
        else
        {
            sResult+=XBinary::valueToHex(nAddress);
        }
    }
    else
    {
        sResult=XBinary::valueToHex(nAddress);
    }

    return sResult;
}

QList<XBinary::SYMBOL_RECORD> XAbstractDebugger::loadSymbols(QString sFileName,qint64 nModuleAddress)
{
    QList<XBinary::SYMBOL_RECORD> listReturn;

    // TODO

    return listReturn;
}

QList<XBinary::MEMORY_REPLACE> XAbstractDebugger::getMemoryReplaces()
{
    QList<XBinary::MEMORY_REPLACE> listResult;

    QMapIterator<qint64,BREAKPOINT> i(g_mapSoftwareBreakpoints);
    while (i.hasNext())
    {
        i.next();
        BREAKPOINT breakPoint=i.value();

        if(breakPoint.nOrigDataSize)
        {
            XBinary::MEMORY_REPLACE record={};
            record.nAddress=breakPoint.nAddress;
            record.baOriginal=QByteArray(breakPoint.origData,breakPoint.nOrigDataSize);
            record.nSize=record.baOriginal.size();

            listResult.append(record);
        }
    }

    return listResult;
}

QMap<qint64, XAbstractDebugger::SHAREDOBJECT_INFO> *XAbstractDebugger::getSharedObjectInfos()
{
    return &g_mapSharedObjectInfos;
}

QMap<qint64, XAbstractDebugger::THREAD_INFO> *XAbstractDebugger::getThreadInfos()
{
    return &g_mapThreadInfos;
}

QMap<qint64, XAbstractDebugger::BREAKPOINT> *XAbstractDebugger::getSoftwareBreakpoints()
{
    return &g_mapSoftwareBreakpoints;
}

QMap<qint64, XAbstractDebugger::BREAKPOINT> *XAbstractDebugger::getHardwareBreakpoints()
{
    return &g_mapHardwareBreakpoints;
}

QMap<QString, XAbstractDebugger::FUNCTIONHOOK_INFO> *XAbstractDebugger::getFunctionHookInfos()
{
    return &g_mapFunctionHookInfos;
}

XAbstractDebugger::SHAREDOBJECT_INFO XAbstractDebugger::findSharedInfoByName(QString sName)
{
    SHAREDOBJECT_INFO result={};

    for(QMap<qint64,SHAREDOBJECT_INFO>::iterator it=g_mapSharedObjectInfos.begin();it!=g_mapSharedObjectInfos.end();)
    {
        if(it.value().sName==sName)
        {
            result=it.value();

            break;
        }

        ++it;
    }

    return result;
}

XAbstractDebugger::SHAREDOBJECT_INFO XAbstractDebugger::findSharedInfoByAddress(qint64 nAddress)
{
    SHAREDOBJECT_INFO result={};

    for(QMap<qint64,SHAREDOBJECT_INFO>::iterator it=g_mapSharedObjectInfos.begin();it!=g_mapSharedObjectInfos.end();)
    {
        SHAREDOBJECT_INFO record=it.value();

        if((record.nImageBase<=nAddress)&&(record.nImageBase+record.nImageSize>nAddress))
        {
            result=record;

            break;
        }

        ++it;
    }

    return result;
}

quint8 XAbstractDebugger::read_uint8(qint64 nAddress)
{
    return XProcess::read_uint8(g_processInfo.hProcess,nAddress);
}

quint16 XAbstractDebugger::read_uint16(qint64 nAddress)
{
    return XProcess::read_uint16(g_processInfo.hProcess,nAddress);
}

quint32 XAbstractDebugger::read_uint32(qint64 nAddress)
{
    return XProcess::read_uint32(g_processInfo.hProcess,nAddress);
}

quint64 XAbstractDebugger::read_uint64(qint64 nAddress)
{
    return XProcess::read_uint64(g_processInfo.hProcess,nAddress);
}

void XAbstractDebugger::write_uint8(qint64 nAddress, quint8 nValue)
{
    XProcess::write_uint8(g_processInfo.hProcess,nAddress,nValue);
}

void XAbstractDebugger::write_uint16(qint64 nAddress, quint16 nValue)
{
    XProcess::write_uint16(g_processInfo.hProcess,nAddress,nValue);
}

void XAbstractDebugger::write_uint32(qint64 nAddress, quint32 nValue)
{
    XProcess::write_uint32(g_processInfo.hProcess,nAddress,nValue);
}

void XAbstractDebugger::write_uint64(qint64 nAddress, quint64 nValue)
{
    XProcess::write_uint64(g_processInfo.hProcess,nAddress,nValue);
}

qint64 XAbstractDebugger::read_array(qint64 nAddress, char *pData, qint64 nSize)
{
    return XProcess::read_array(g_processInfo.hProcess,nAddress,pData,nSize);
}

qint64 XAbstractDebugger::write_array(qint64 nAddress, char *pData, qint64 nSize)
{
    return XProcess::write_array(g_processInfo.hProcess,nAddress,pData,nSize);
}

QByteArray XAbstractDebugger::read_array(qint64 nAddress, qint32 nSize)
{
    return XProcess::read_array(g_processInfo.hProcess,nAddress,nSize);
}

QString XAbstractDebugger::read_ansiString(qint64 nAddress, qint64 nMaxSize)
{
    return XProcess::read_ansiString(g_processInfo.hProcess,nAddress,nMaxSize);
}

QString XAbstractDebugger::read_unicodeString(qint64 nAddress, qint64 nMaxSize)
{
    return XProcess::read_unicodeString(g_processInfo.hProcess,nAddress,nMaxSize);
}

bool XAbstractDebugger::suspendThread(void *hThread)
{
    bool bResult=false;
#ifdef Q_OS_WIN
    bResult=(SuspendThread(hThread)!=((DWORD)-1));
#endif
    return bResult;
}

bool XAbstractDebugger::resumeThread(void *hThread)
{
    bool bResult=false;
#ifdef Q_OS_WIN
    bResult=(ResumeThread(hThread)!=((DWORD)-1));
#endif
    return bResult;
}

bool XAbstractDebugger::suspendOtherThreads(void *hCurrentThread)
{
    bool bResult=false;

    QList<THREAD_INFO> listThreads=g_mapThreadInfos.values();

    qint32 nCount=listThreads.count();

    // Suspend all other threads
    for(qint32 i=0;i<nCount;i++)
    {
        if(hCurrentThread!=listThreads.at(i).hThread)
        {
            suspendThread(listThreads.at(i).hThread);

            bResult=true;
        }
    }

    return bResult;
}

bool XAbstractDebugger::resumeOtherThreads(void *hCurrentThread)
{
    bool bResult=false;

    QList<THREAD_INFO> listThreads=g_mapThreadInfos.values();

    qint32 nCount=listThreads.count();

    // Resume all other threads
    for(qint32 i=0;i<nCount;i++)
    {
        if(hCurrentThread!=listThreads.at(i).hThread)
        {
            resumeThread(listThreads.at(i).hThread);

            bResult=true;
        }
    }

    return bResult;
}


bool XAbstractDebugger::setCurrentAddress(void *hThread, qint64 nAddress)
{
    bool bResult=false;
#ifdef Q_OS_WIN
    CONTEXT context={0};
    context.ContextFlags=CONTEXT_CONTROL; // EIP

    if(GetThreadContext(hThread,&context))
    {
#ifndef Q_OS_WIN64
        context.Eip=nAddress;
#else
        context.Rip=nAddress;
#endif
        if(SetThreadContext(hThread,&context))
        {
            bResult=true;
        }
    }
#endif
    return bResult;
}

qint64 XAbstractDebugger::getCurrentAddress(void *hThread)
{
    qint64 nAddress=0;
#ifdef Q_OS_WIN
    CONTEXT context={0};
    context.ContextFlags=CONTEXT_CONTROL; // EIP

    if(GetThreadContext(hThread,&context))
    {
#ifndef Q_OS_WIN64
        nAddress=context.Eip;
#else
        nAddress=context.Rip;
#endif
    }
#endif
    return nAddress;
}

bool XAbstractDebugger::_setStep(void *hThread)
{
    bool bResult=false;
#ifdef Q_OS_WIN
    CONTEXT context={0};
    context.ContextFlags=CONTEXT_CONTROL; // EFLAGS

    if(GetThreadContext(hThread,&context))
    {
        if(!(context.EFlags&0x100))
        {
            context.EFlags|=0x100;
        }

        if(SetThreadContext(hThread,&context))
        {
            bResult=true;
        }
    }
#endif
    return bResult;
}

bool XAbstractDebugger::setSingleStep(void *hThread, QString sInfo)
{
    BREAKPOINT breakPoint={};
    breakPoint.bpType=BPT_CODE_HARDWARE;
    breakPoint.bpInfo=BPI_STEP;
    breakPoint.sInfo=sInfo;

    g_mapThreadSteps.insert(hThread,breakPoint);

    return _setStep(hThread);
}

QMap<QString, XBinary::XVARIANT> XAbstractDebugger::getRegisters(void *hThread, REG_OPTIONS regOptions)
{
    QMap<QString, XBinary::XVARIANT> mapResult;
#ifdef Q_OS_WIN
    CONTEXT context={0};
    context.ContextFlags=CONTEXT_ALL; // All registers TODO Check regOptions | CONTEXT_FLOATING_POINT | CONTEXT_EXTENDED_REGISTERS;

    if(GetThreadContext(hThread,&context))
    {
        XBinary::XVARIANT xVariant={};
        xVariant.bIsBigEndian=false;

        if(regOptions.bGeneral)
        {
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
            xVariant.mode=XBinary::MODE_32;
            xVariant.var.v_uint32=(quint32)(context.EFlags);
            mapResult.insert("EFLAGS",xVariant);

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
            xVariant.mode=XBinary::MODE_128;

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
        }

        if(regOptions.bXMM)
        {
            xVariant.mode=XBinary::MODE_128;
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

//            mapResult.insert("MxCsr",(quint32)(context.MxCsr));
        }

    #ifdef QT_DEBUG
//        qDebug("DebugControl %s",XBinary::valueToHex((quint64)(context.DebugControl)).toLatin1().data());
//        qDebug("LastBranchToRip %s",XBinary::valueToHex((quint64)(context.LastBranchToRip)).toLatin1().data());
//        qDebug("LastBranchFromRip %s",XBinary::valueToHex((quint64)(context.LastBranchFromRip)).toLatin1().data());
//        qDebug("LastExceptionToRip %s",XBinary::valueToHex((quint64)(context.LastExceptionToRip)).toLatin1().data());
//        qDebug("LastExceptionFromRip %s",XBinary::valueToHex((quint64)(context.LastExceptionFromRip)).toLatin1().data());

        qDebug("P1Home %s",XBinary::valueToHex((quint64)(context.P1Home)).toLatin1().data());
        qDebug("P2Home %s",XBinary::valueToHex((quint64)(context.P2Home)).toLatin1().data());
        qDebug("P3Home %s",XBinary::valueToHex((quint64)(context.P3Home)).toLatin1().data());
        qDebug("P4Home %s",XBinary::valueToHex((quint64)(context.P4Home)).toLatin1().data());
        qDebug("P5Home %s",XBinary::valueToHex((quint64)(context.P5Home)).toLatin1().data());
        qDebug("P6Home %s",XBinary::valueToHex((quint64)(context.P6Home)).toLatin1().data());
        qDebug("ContextFlags %s",XBinary::valueToHex((quint32)(context.ContextFlags)).toLatin1().data());
        qDebug("MxCsr %s",XBinary::valueToHex((quint32)(context.MxCsr)).toLatin1().data());

    #endif

    }
#endif
    return mapResult;
}

XAbstractDebugger::FUNCTION_INFO XAbstractDebugger::getFunctionInfo(void *hThread,QString sName)
{
    FUNCTION_INFO result={};

#ifdef Q_OS_WIN
    CONTEXT context={0};
    context.ContextFlags=CONTEXT_FULL; // Full

    if(GetThreadContext(hThread,&context))
    {
    #ifndef Q_OS_WIN64
        quint64 nSP=(quint32)(context.Esp);
        quint64 nIP=(quint32)(context.Eip);
    #else
        quint64 nSP=(quint64)(context.Rsp);
        quint64 nIP=(quint64)(context.Rip);
    #endif

        // TODO 64!
        result.nAddress=nIP;
        result.nRetAddress=read_uint32((quint32)nSP);
        result.nParameter0=read_uint32((quint32)(nSP+4+0*4));
        result.nParameter1=read_uint32((quint32)(nSP+4+1*4));
        result.nParameter2=read_uint32((quint32)(nSP+4+2*4));
        result.nParameter3=read_uint32((quint32)(nSP+4+3*4));
        result.nParameter4=read_uint32((quint32)(nSP+4+4*4));
        result.nParameter5=read_uint32((quint32)(nSP+4+5*4));
        result.nParameter6=read_uint32((quint32)(nSP+4+6*4));
        result.nParameter7=read_uint32((quint32)(nSP+4+7*4));
        result.nParameter8=read_uint32((quint32)(nSP+4+8*4));
        result.nParameter9=read_uint32((quint32)(nSP+4+9*4));
        result.sName=sName;
    }
#endif

    return result;
}

qint64 XAbstractDebugger::getRetAddress(void *hThread)
{
    qint64 nAddress=0;

#ifdef Q_OS_WIN
    CONTEXT context={0};
    context.ContextFlags=CONTEXT_CONTROL; // Full

    if(GetThreadContext(hThread,&context))
    {
    #ifndef Q_OS_WIN64
        quint64 nSP=(quint32)(context.Esp);
        nAddress=read_uint32((quint32)nSP);
    #else
        quint64 nSP=(quint64)(context.Rsp);
        nAddress=read_uint64((quint64)nSP);
    #endif
    }
#endif

    return nAddress;
}

XCapstone::DISASM_STRUCT XAbstractDebugger::disasm(qint64 nAddress)
{
    QByteArray baData=read_array(nAddress,15);

    return XCapstone::disasm(g_handle,nAddress,baData.data(),baData.size());
}

bool XAbstractDebugger::isUserCode(qint64 nAddress)
{
    bool bResult=false;

    if((g_processInfo.nImageBase<=nAddress)&&(g_processInfo.nImageBase+g_processInfo.nImageSize>nAddress))
    {
        bResult=true;
    }

    return bResult;
}

bool XAbstractDebugger::bIsSystemCode(qint64 nAddress)
{
    return findSharedInfoByAddress(nAddress).nImageBase;
}

bool XAbstractDebugger::dumpToFile(QString sFileName)
{
    bool bResult=false;

    XProcessDevice processDevice(this);

    if(processDevice.openHandle(g_processInfo.hProcess,g_processInfo.nImageBase,g_processInfo.nImageSize,QIODevice::ReadOnly))
    {
        XBinary binary(&processDevice,true,g_processInfo.nImageBase);

        bResult=binary.dumpToFile(sFileName,(qint64)0,(qint64)-1);
    }

    return bResult;
}

QString XAbstractDebugger::debugActionToString(DEBUG_ACTION debugAction)
{
    QString sResult;

    if(debugAction.type==DBT_SETSOFTWAREBREAKPOINT)
    {
        sResult=QString("SetSoftBP %1").arg(debugAction.var[0].toULongLong(),0,16);
    }
    else if(debugAction.type==DBT_REMOVESOFTWAREBREAKPOINT)
    {
        sResult=QString("RemoveSoftBP %1").arg(debugAction.var[0].toULongLong(),0,16);
    }

    // TODO

    return sResult;
}

XAbstractDebugger::DEBUG_ACTION XAbstractDebugger::stringToDebugAction(QString sString)
{
    DEBUG_ACTION result={};

    // TODO

    return result;
}

bool XAbstractDebugger::stepInto(void *hThread)
{
    BREAKPOINT breakPoint={};
    breakPoint.bpType=BPT_CODE_HARDWARE;
    breakPoint.bpInfo=BPI_STEPINTO;

    g_mapThreadSteps.insert(hThread,breakPoint);

    return _setStep(hThread);
}

bool XAbstractDebugger::stepOver(void *hThread)
{
    bool bResult=false;

    qint64 nAddress=getCurrentAddress(hThread);
    QByteArray baData=read_array(nAddress,15);

    XCapstone::OPCODE_ID opcodeID=XCapstone::getOpcodeID(g_handle,nAddress,baData.data(),baData.size());

//    if(XCapstone::isRetOpcode(opcodeID.nOpcodeID)||XCapstone::isJmpOpcode(opcodeID.nOpcodeID))
//    {
//        BREAKPOINT breakPoint={};
//        breakPoint.bpType=BPT_CODE_HARDWARE;
//        breakPoint.bpInfo=BPI_STEPOVER;

//        g_mapThreadSteps.insert(hThread,breakPoint);

//        return _setStep(hThread);
//    }
//    else
//    {
//        bResult=setBP(nAddress+opcodeID.nSize,BPT_CODE_SOFTWARE,BPI_STEPOVER,1);
//    }

    if(XCapstone::isCallOpcode(opcodeID.nOpcodeID))
    {
        bResult=setBP(nAddress+opcodeID.nSize,BPT_CODE_SOFTWARE,BPI_STEPOVER,1);
    }
    else
    {
        BREAKPOINT breakPoint={};
        breakPoint.bpType=BPT_CODE_HARDWARE;
        breakPoint.bpInfo=BPI_STEPOVER;

        g_mapThreadSteps.insert(hThread,breakPoint);

        return _setStep(hThread);
    }

    return bResult;
}

char *XAbstractDebugger::allocateAnsiStringMemory(QString sFileName)
{
    char *pResult=nullptr;

    qint32 nSize=sFileName.length();

    pResult=new char[nSize+1];
    XBinary::_zeroMemory(pResult,nSize+1);
    XBinary::_copyMemory(pResult,sFileName.toLatin1().data(),nSize);

    return pResult;
}

void XAbstractDebugger::process()
{
    load();
}

