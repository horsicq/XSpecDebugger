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

    int nCount=listThreads.count();

    // Suspend all other threads
    for(int i=0;i<nCount;i++)
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

    int nCount=listThreads.count();

    // Resume all other threads
    for(int i=0;i<nCount;i++)
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
    g_mapThreadSteps.insert(hThread,sInfo);

    return _setStep(hThread);
}

QMap<QString, QVariant> XAbstractDebugger::getRegisters(void *hThread, REG_OPTIONS regOptions)
{
    QMap<QString, QVariant> mapResult;
#ifdef Q_OS_WIN
    CONTEXT context={0};
    context.ContextFlags=CONTEXT_ALL; // All registers

    if(GetThreadContext(hThread,&context))
    {
        // TODO 64
        mapResult.insert("DR0",(quint32)(context.Dr0));
        mapResult.insert("DR1",(quint32)(context.Dr1));
        mapResult.insert("DR2",(quint32)(context.Dr2));
        mapResult.insert("DR3",(quint32)(context.Dr3));
        mapResult.insert("DR6",(quint32)(context.Dr6));
        mapResult.insert("DR7",(quint32)(context.Dr7));
        mapResult.insert("GS",(quint32)(context.SegGs));
        mapResult.insert("FS",(quint32)(context.SegFs));
        mapResult.insert("ES",(quint32)(context.SegEs));
        mapResult.insert("DS",(quint32)(context.SegDs));
        mapResult.insert("CS",(quint32)(context.SegCs));
        mapResult.insert("SS",(quint32)(context.SegSs));
    #ifndef Q_OS_WIN64
        mapResult.insert("EDI",(quint32)(context.Edi));
        mapResult.insert("ESI",(quint32)(context.Esi));
        mapResult.insert("EBX",(quint32)(context.Ebx));
        mapResult.insert("EDX",(quint32)(context.Edx));
        mapResult.insert("ECX",(quint32)(context.Ecx));
        mapResult.insert("EAX",(quint32)(context.Eax));
        mapResult.insert("EBP",(quint32)(context.Ebp));
        mapResult.insert("EIP",(quint32)(context.Eip));
        mapResult.insert("ESP",(quint32)(context.Esp));
    #else
        mapResult.insert("RDI",(quint32)(context.Rdi));
        mapResult.insert("RSI",(quint32)(context.Rsi));
        mapResult.insert("RBX",(quint32)(context.Rbx));
        mapResult.insert("RDX",(quint32)(context.Rdx));
        mapResult.insert("RCX",(quint32)(context.Rcx));
        mapResult.insert("RAX",(quint32)(context.Rax));
        mapResult.insert("RBP",(quint32)(context.Rbp));
        mapResult.insert("RIP",(quint32)(context.Rip));
        mapResult.insert("RSP",(quint32)(context.Rsp));

        mapResult.insert("R8",(quint32)(context.R8));
        mapResult.insert("R9",(quint32)(context.R9));
        mapResult.insert("R10",(quint32)(context.R10));
        mapResult.insert("R11",(quint32)(context.R11));
        mapResult.insert("R12",(quint32)(context.R12));
        mapResult.insert("R13",(quint32)(context.R13));
        mapResult.insert("R14",(quint32)(context.R14));
        mapResult.insert("R15",(quint32)(context.R15));
    #endif
        mapResult.insert("EFLAGS",(quint32)(context.EFlags));
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
    return setSingleStep(hThread);
}

bool XAbstractDebugger::stepOver(void *hThread)
{
    bool bResult=false;

    qint64 nAddress=getCurrentAddress(hThread);
    QByteArray baData=read_array(nAddress,15);

    XCapstone::OPCODE_ID opcodeID=XCapstone::getOpcodeID(g_handle,nAddress,baData.data(),baData.size());

    if(XCapstone::isRetOpcode(opcodeID.nOpcodeID)||XCapstone::isJmpOpcode(opcodeID.nOpcodeID))
    {
        bResult=setSingleStep(hThread);
    }
    else
    {
        bResult=setBP(nAddress+opcodeID.nSize,BPT_CODE_SOFTWARE,BPI_STEPOVER,1);
    }

    return bResult;
}

void XAbstractDebugger::process()
{
    load();
}

