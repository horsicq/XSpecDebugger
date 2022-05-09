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

XAbstractDebugger::XAbstractDebugger(QObject *pParent,XInfoDB *pXInfoDB) : QObject(pParent)
{
    g_handle=0;
    g_bIsDebugActive=false;
    g_pXInfoDB=pXInfoDB;
}

void XAbstractDebugger::setXInfoDB(XInfoDB *pXInfoDB)
{
    g_pXInfoDB=pXInfoDB;
}

XInfoDB *XAbstractDebugger::getXInfoDB()
{
    return g_pXInfoDB;
}

bool XAbstractDebugger::stop()
{
    return false;
}

void XAbstractDebugger::cleanUp()
{
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

void XAbstractDebugger::_messageString(XAbstractDebugger::MT messageType,QString sText)
{
#ifdef QT_DEBUG
    qDebug("%s",sText.toLatin1().data());
#endif
    emit messageString(messageType,sText);
}

qint64 XAbstractDebugger::getFunctionAddress(QString sFunctionName)
{
    qint64 nResult=-1;

    QString sLibrary=sFunctionName.section("#",0,0);
    QString sFunction=sFunctionName.section("#",1,1);
    qint32 nOrdinal=sFunction.toULongLong();

    XInfoDB::SHAREDOBJECT_INFO sharedObjectInfo=getXInfoDB()->findSharedInfoByName(sLibrary);

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

    XInfoDB::SHAREDOBJECT_INFO sharedObjectInfo=getXInfoDB()->findSharedInfoByAddress(nAddress);

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

    QList<XInfoDB::THREAD_INFO> *pListThreads=getXInfoDB()->getThreadInfos();

    qint32 nCount=pListThreads->count();

    // Suspend all other threads
    for(qint32 i=0;i<nCount;i++)
    {
        if(handleID.hHandle!=pListThreads->at(i).hThread)
        {
            XProcess::HANDLEID _handleID={};
            _handleID.hHandle=pListThreads->at(i).hThread;
            _handleID.nID=pListThreads->at(i).nThreadID;

            suspendThread(_handleID);

            bResult=true;
        }
    }

    return bResult;
}

bool XAbstractDebugger::resumeOtherThreads(XProcess::HANDLEID handleID)
{
    bool bResult=false;

    QList<XInfoDB::THREAD_INFO> *pListThreads=getXInfoDB()->getThreadInfos();

    qint32 nCount=pListThreads->count();

    // Resume all other threads
    for(qint32 i=0;i<nCount;i++)
    {
        if(handleID.hHandle!=pListThreads->at(i).hThread)
        {
            XProcess::HANDLEID _handleID={};
            _handleID.hHandle=pListThreads->at(i).hThread;
            _handleID.nID=pListThreads->at(i).nThreadID;

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

qint64 XAbstractDebugger::getCurrentAddress(void *hHandle,qint64 nID)
{
    XProcess::HANDLEID handleID={};

    handleID.hHandle=hHandle;
    handleID.nID=nID;

    return getCurrentAddress(handleID);
}

bool XAbstractDebugger::_setStep(XProcess::HANDLEID handleID)
{
    bool bResult=false;

    return bResult;
}

bool XAbstractDebugger::setSingleStep(XProcess::HANDLEID handleID,QString sInfo)
{
    XInfoDB::BREAKPOINT breakPoint={};
    breakPoint.bpType=XInfoDB::BPT_CODE_HARDWARE;
    breakPoint.bpInfo=XInfoDB::BPI_STEP;
    breakPoint.sInfo=sInfo;

    getXInfoDB()->getThreadBreakpoints()->insert(handleID.nID,breakPoint);

    return _setStep(handleID);
}

XInfoDB::FUNCTION_INFO XAbstractDebugger::getFunctionInfo(XProcess::HANDLEID handleID,QString sName)
{
    XInfoDB::FUNCTION_INFO result={};

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
        result.nRetAddress=getXInfoDB()->read_uint32((quint32)nSP);
        result.nParameter0=getXInfoDB()->read_uint32((quint32)(nSP+4+0*4));
        result.nParameter1=getXInfoDB()->read_uint32((quint32)(nSP+4+1*4));
        result.nParameter2=getXInfoDB()->read_uint32((quint32)(nSP+4+2*4));
        result.nParameter3=getXInfoDB()->read_uint32((quint32)(nSP+4+3*4));
        result.nParameter4=getXInfoDB()->read_uint32((quint32)(nSP+4+4*4));
        result.nParameter5=getXInfoDB()->read_uint32((quint32)(nSP+4+5*4));
        result.nParameter6=getXInfoDB()->read_uint32((quint32)(nSP+4+6*4));
        result.nParameter7=getXInfoDB()->read_uint32((quint32)(nSP+4+7*4));
        result.nParameter8=getXInfoDB()->read_uint32((quint32)(nSP+4+8*4));
        result.nParameter9=getXInfoDB()->read_uint32((quint32)(nSP+4+9*4));
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
        nResult=getXInfoDB()->read_uint32((quint32)nSP);
    #else
        quint64 nSP=(quint64)(context.Rsp);
        nResult=getXInfoDB()->read_uint64((quint64)nSP);
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
    QByteArray baData=getXInfoDB()->read_array(nAddress,15);

    return XCapstone::disasm(g_handle,nAddress,baData.data(),baData.size());
}

bool XAbstractDebugger::isUserCode(quint64 nAddress)
{
    bool bResult=false;

    if((getXInfoDB()->getProcessInfo()->nImageBase<=nAddress)&&(getXInfoDB()->getProcessInfo()->nImageBase+getXInfoDB()->getProcessInfo()->nImageSize>nAddress))
    {
        bResult=true;
    }

    return bResult;
}

bool XAbstractDebugger::bIsSystemCode(quint64 nAddress)
{
    return getXInfoDB()->findSharedInfoByAddress(nAddress).nImageBase;
}

bool XAbstractDebugger::dumpToFile(QString sFileName)
{
    bool bResult=false;

    XProcessDevice processDevice(this); // TODO -> XProcess

    if(processDevice.openHandle(getXInfoDB()->getProcessInfo()->hProcessMemoryIO,getXInfoDB()->getProcessInfo()->nImageBase,getXInfoDB()->getProcessInfo()->nImageSize,QIODevice::ReadOnly))
    {
        XBinary binary(&processDevice,true,getXInfoDB()->getProcessInfo()->nImageBase);

        bResult=binary.dumpToFile(sFileName,(qint64)0,(qint64)-1);
    }

    return bResult;
}

bool XAbstractDebugger::stepInto(XProcess::HANDLEID handleID)
{
    XInfoDB::BREAKPOINT breakPoint={};
    breakPoint.bpType=XInfoDB::BPT_CODE_HARDWARE;
    breakPoint.bpInfo=XInfoDB::BPI_STEPINTO;

    getXInfoDB()->getThreadBreakpoints()->insert(handleID.nID,breakPoint);

    return _setStep(handleID);
}

bool XAbstractDebugger::stepOver(XProcess::HANDLEID handleID)
{
    bool bResult=false;

    quint64 nAddress=getCurrentAddress(handleID);
    QByteArray baData=getXInfoDB()->read_array(nAddress,15);

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
        bResult=getXInfoDB()->addBreakPoint(nAddress+opcodeID.nSize,XInfoDB::BPT_CODE_SOFTWARE,XInfoDB::BPI_STEPOVER,1);
    }
    else
    {
        XInfoDB::BREAKPOINT breakPoint={};
        breakPoint.bpType=XInfoDB::BPT_CODE_HARDWARE;
        breakPoint.bpInfo=XInfoDB::BPI_STEPOVER;

        getXInfoDB()->getThreadBreakpoints()->insert(handleID.nID,breakPoint);

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

