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
#include "xabstractdebugger.h"

XAbstractDebugger::XAbstractDebugger(QObject *pParent) : QObject(pParent)
{
    g_handle=0;
    g_bIsDebugActive=false;
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

void XAbstractDebugger::_messageString(XAbstractDebugger::MT messageType,QString sText)
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

bool XAbstractDebugger::setBP(quint64 nAddress,XAbstractDebugger::BPT bpType,XAbstractDebugger::BPI bpInfo,qint32 nCount,QString sInfo,QString sGUID)
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

bool XAbstractDebugger::removeBP(quint64 nAddress,BPT bpType)
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

bool XAbstractDebugger::setSoftwareBreakpoint(quint64 nAddress,qint32 nCount,QString sInfo)
{
    return setBP(nAddress,BPT_CODE_SOFTWARE,BPI_USER,nCount,sInfo);
}

bool XAbstractDebugger::removeSoftwareBreakpoint(quint64 nAddress)
{
    return removeBP(nAddress,BPT_CODE_SOFTWARE);
}

bool XAbstractDebugger::isSoftwareBreakpointPresent(quint64 nAddress)
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
        QList<XBinary::SYMBOL_RECORD> listSymbols=loadSymbols(sharedObjectInfo.sFileName,sharedObjectInfo.nImageBase); // TODO Cache !!!

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

QString XAbstractDebugger::getAddressSymbolString(quint64 nAddress)
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

QMap<qint64,XAbstractDebugger::SHAREDOBJECT_INFO> *XAbstractDebugger::getSharedObjectInfos()
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

QMap<qint64,XAbstractDebugger::BREAKPOINT> *XAbstractDebugger::getHardwareBreakpoints()
{
    return &g_mapHardwareBreakpoints;
}

QMap<QString,XAbstractDebugger::FUNCTIONHOOK_INFO> *XAbstractDebugger::getFunctionHookInfos()
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

XAbstractDebugger::SHAREDOBJECT_INFO XAbstractDebugger::findSharedInfoByAddress(quint64 nAddress)
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

quint8 XAbstractDebugger::read_uint8(quint64 nAddress)
{
    return XProcess::read_uint8(g_processInfo.hProcessMemoryIO,nAddress);
}

quint16 XAbstractDebugger::read_uint16(quint64 nAddress)
{
    return XProcess::read_uint16(g_processInfo.hProcessMemoryIO,nAddress);
}

quint32 XAbstractDebugger::read_uint32(quint64 nAddress)
{
    return XProcess::read_uint32(g_processInfo.hProcessMemoryIO,nAddress);
}

quint64 XAbstractDebugger::read_uint64(quint64 nAddress)
{
    return XProcess::read_uint64(g_processInfo.hProcessMemoryIO,nAddress);
}

void XAbstractDebugger::write_uint8(quint64 nAddress,quint8 nValue)
{
    XProcess::write_uint8(g_processInfo.hProcessMemoryIO,nAddress,nValue);
}

void XAbstractDebugger::write_uint16(quint64 nAddress,quint16 nValue)
{
    XProcess::write_uint16(g_processInfo.hProcessMemoryIO,nAddress,nValue);
}

void XAbstractDebugger::write_uint32(quint64 nAddress,quint32 nValue)
{
    XProcess::write_uint32(g_processInfo.hProcessMemoryIO,nAddress,nValue);
}

void XAbstractDebugger::write_uint64(quint64 nAddress,quint64 nValue)
{
    XProcess::write_uint64(g_processInfo.hProcessMemoryIO,nAddress,nValue);
}

qint64 XAbstractDebugger::read_array(quint64 nAddress,char *pData,quint64 nSize)
{
    return XProcess::read_array(g_processInfo.hProcessMemoryIO,nAddress,pData,nSize);
}

qint64 XAbstractDebugger::write_array(quint64 nAddress,char *pData,quint64 nSize)
{
    return XProcess::write_array(g_processInfo.hProcessMemoryIO,nAddress,pData,nSize);
}

QByteArray XAbstractDebugger::read_array(quint64 nAddress, quint64 nSize)
{
    return XProcess::read_array(g_processInfo.hProcessMemoryIO,nAddress,nSize);
}

QString XAbstractDebugger::read_ansiString(quint64 nAddress, quint64 nMaxSize)
{
    return XProcess::read_ansiString(g_processInfo.hProcessMemoryIO,nAddress,nMaxSize);
}

QString XAbstractDebugger::read_unicodeString(quint64 nAddress, quint64 nMaxSize)
{
    return XProcess::read_unicodeString(g_processInfo.hProcessMemoryIO,nAddress,nMaxSize);
}

bool XAbstractDebugger::suspendThread(XProcess::HANDLEID handleID)
{
    bool bResult=false;
#ifdef Q_OS_WIN
    bResult=(SuspendThread(handleID.hHandle)!=((DWORD)-1));
#endif
//#ifdef Q_OS_LINUX
//    if(syscall(SYS_tgkill,g_processInfo.nProcessID,handleID.nID,SIGSTOP)!=-1)
//    {
//        bResult=true;
//    }
//    else
//    {
//        qDebug("Cannot stop thread");
//    }
//#endif
    return bResult;
}

bool XAbstractDebugger::resumeThread(XProcess::HANDLEID handleID)
{
    bool bResult=false;
#ifdef Q_OS_WIN
    bResult=(ResumeThread(handleID.hHandle)!=((DWORD)-1));
#endif
    return bResult;
}

bool XAbstractDebugger::suspendOtherThreads(XProcess::HANDLEID handleID)
{
    bool bResult=false;

    QList<THREAD_INFO> listThreads=g_mapThreadInfos.values();

    qint32 nCount=listThreads.count();

    // Suspend all other threads
    for(qint32 i=0;i<nCount;i++)
    {
        if(handleID.hHandle!=listThreads.at(i).hThread)
        {
            XProcess::HANDLEID _handleID={};
            _handleID.hHandle=listThreads.at(i).hThread;
            _handleID.nID=listThreads.at(i).nThreadID;

            suspendThread(_handleID);

            bResult=true;
        }
    }

    return bResult;
}

bool XAbstractDebugger::resumeOtherThreads(XProcess::HANDLEID handleID)
{
    bool bResult=false;

    QList<THREAD_INFO> listThreads=g_mapThreadInfos.values();

    qint32 nCount=listThreads.count();

    // Resume all other threads
    for(qint32 i=0;i<nCount;i++)
    {
        if(handleID.hHandle!=listThreads.at(i).hThread)
        {
            XProcess::HANDLEID _handleID={};
            _handleID.hHandle=listThreads.at(i).hThread;
            _handleID.nID=listThreads.at(i).nThreadID;

            resumeThread(_handleID);

            bResult=true;
        }
    }

    return bResult;
}


bool XAbstractDebugger::setCurrentAddress(XProcess::HANDLEID handleID,quint64 nAddress)
{
    bool bResult=false;
#ifdef Q_OS_WIN
    CONTEXT context={0};
    context.ContextFlags=CONTEXT_CONTROL; // EIP

    if(GetThreadContext(handleID.hHandle,&context))
    {
#ifndef Q_OS_WIN64
        context.Eip=nAddress;
#else
        context.Rip=nAddress;
#endif
        if(SetThreadContext(handleID.hHandle,&context))
        {
            bResult=true;
        }
    }
#endif
    return bResult;
}

qint64 XAbstractDebugger::getCurrentAddress(XProcess::HANDLEID handleID)
{
    quint64 nAddress=0;
#ifdef Q_OS_WIN
    CONTEXT context={0};
    context.ContextFlags=CONTEXT_CONTROL; // EIP

    if(GetThreadContext(handleID.hHandle,&context))
    {
#ifndef Q_OS_WIN64
        nAddress=context.Eip;
#else
        nAddress=context.Rip;
#endif
    }
#endif
#ifdef Q_OS_LINUX
    // TODO 32
    user_regs_struct regs={};

    errno=0;

    if(ptrace(PTRACE_GETREGS,handleID.nID,nullptr,&regs)!=-1)
    {
    #if defined(Q_PROCESSOR_X86_64)
        nAddress=regs.rip;
    #elif defined(Q_PROCESSOR_X86_32)
        nAddress=regs.eip;
    #endif
    }
#endif
    return nAddress;
}

bool XAbstractDebugger::_setStep(XProcess::HANDLEID handleID)
{
    bool bResult=false;

    return bResult;
}

bool XAbstractDebugger::setSingleStep(XProcess::HANDLEID handleID, QString sInfo)
{
    BREAKPOINT breakPoint={};
    breakPoint.bpType=BPT_CODE_HARDWARE;
    breakPoint.bpInfo=BPI_STEP;
    breakPoint.sInfo=sInfo;

    g_mapThreadSteps.insert(handleID.nID,breakPoint);

    return _setStep(handleID);
}

qint64 XAbstractDebugger::findAddressByException(qint64 nExeptionAddress)
{
    qint64 nResult=-1;

    QMapIterator<qint64,BREAKPOINT> i(g_mapSoftwareBreakpoints);
    while (i.hasNext())
    {
        i.next();
        BREAKPOINT breakPoint=i.value();

        if(breakPoint.nAddress==(nExeptionAddress-breakPoint.nOrigDataSize))
        {
            nResult=breakPoint.nAddress;

            break;
        }
    }

    return nResult;
}

XAbstractDebugger::REGISTERS XAbstractDebugger::getRegisters(XProcess::HANDLEID handleID, REG_OPTIONS regOptions)
{
    Q_UNUSED(handleID)
    Q_UNUSED(regOptions)

    XAbstractDebugger::REGISTERS result={};

    return result;
}

XAbstractDebugger::FUNCTION_INFO XAbstractDebugger::getFunctionInfo(XProcess::HANDLEID handleID,QString sName)
{
    FUNCTION_INFO result={};

#ifdef Q_OS_WIN
    CONTEXT context={0};
    context.ContextFlags=CONTEXT_FULL; // Full

    if(GetThreadContext(handleID.hHandle,&context))
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

qint64 XAbstractDebugger::getRetAddress(XProcess::HANDLEID handleID)
{
    qint64 nResult=0;

#ifdef Q_OS_WIN
    CONTEXT context={0};
    context.ContextFlags=CONTEXT_CONTROL;

    if(GetThreadContext(handleID.hHandle,&context))
    {
    #ifndef Q_OS_WIN64
        quint64 nSP=(quint32)(context.Esp);
        nResult=read_uint32((quint32)nSP);
    #else
        quint64 nSP=(quint64)(context.Rsp);
        nResult=read_uint64((quint64)nSP);
    #endif
    }
#endif

    return nResult;
}

qint64 XAbstractDebugger::getStackPointer(XProcess::HANDLEID handleID)
{
    qint64 nResult=0;

#ifdef Q_OS_WIN
    CONTEXT context={0};
    context.ContextFlags=CONTEXT_CONTROL;

    if(GetThreadContext(handleID.hHandle,&context))
    {
    #ifndef Q_OS_WIN64
        nResult=(quint32)(context.Esp);
    #else
        nResult=(quint64)(context.Rsp);
    #endif
    }
#endif

    return nResult;
}

XCapstone::DISASM_STRUCT XAbstractDebugger::disasm(quint64 nAddress)
{
    QByteArray baData=read_array(nAddress,15);

    return XCapstone::disasm(g_handle,nAddress,baData.data(),baData.size());
}

bool XAbstractDebugger::isUserCode(quint64 nAddress)
{
    bool bResult=false;

    if((g_processInfo.nImageBase<=nAddress)&&(g_processInfo.nImageBase+g_processInfo.nImageSize>nAddress))
    {
        bResult=true;
    }

    return bResult;
}

bool XAbstractDebugger::bIsSystemCode(quint64 nAddress)
{
    return findSharedInfoByAddress(nAddress).nImageBase;
}

bool XAbstractDebugger::dumpToFile(QString sFileName)
{
    bool bResult=false;

    XProcessDevice processDevice(this);

    if(processDevice.openHandle(g_processInfo.hProcessMemoryIO,g_processInfo.nImageBase,g_processInfo.nImageSize,QIODevice::ReadOnly))
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

bool XAbstractDebugger::stepInto(XProcess::HANDLEID handleID)
{
    BREAKPOINT breakPoint={};
    breakPoint.bpType=BPT_CODE_HARDWARE;
    breakPoint.bpInfo=BPI_STEPINTO;

    g_mapThreadSteps.insert(handleID.nID,breakPoint);

    return _setStep(handleID);
}

bool XAbstractDebugger::stepOver(XProcess::HANDLEID handleID)
{
    bool bResult=false;

    quint64 nAddress=getCurrentAddress(handleID);
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

        g_mapThreadSteps.insert(handleID.nID,breakPoint);

        return _setStep(handleID);
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

void XAbstractDebugger::setDebugActive(bool bState)
{
    g_bIsDebugActive=bState;
}

bool XAbstractDebugger::isDebugActive()
{
    return g_bIsDebugActive;
}

void XAbstractDebugger::process()
{
    load();
}

