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
#include "xlinuxdebugger.h"

XLinuxDebugger::XLinuxDebugger(QObject *pParent,XInfoDB *pXInfoDB) : XUnixDebugger(pParent,pXInfoDB)
{

}

bool XLinuxDebugger::load()
{
    bool bResult=false;

    QString sFileName=getOptions()->sFileName;
    QString sDirectory=getOptions()->sDirectory;

    quint32 nMapSize=0x1000;
    char *pMapMemory=(char *)mmap(nullptr,nMapSize,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);

    XBinary::_zeroMemory(pMapMemory,nMapSize);

    if(XBinary::isFileExists(sFileName))
    {
        qint32 nProcessID=fork();

        if(nProcessID==0)
        {
            // Child process
            ptrace(PTRACE_TRACEME,0,nullptr,nullptr);
            // TODO redirect I/O

            EXECUTEPROCESS ep=executeProcess(sFileName,sDirectory);

            XBinary::_copyMemory(pMapMemory,ep.sStatus.toLatin1().data(),ep.sStatus.toLatin1().size());

            abort();
        }
        else if(nProcessID>0)
        {
            // Parent
            // TODO
            // TODO init
        #ifdef QT_DEBUG
            qDebug("Forked");
            qDebug("nProcessID: %d",nProcessID);
        #endif

            QString sStatusString=pMapMemory;
            munmap(pMapMemory,nMapSize);

        #ifdef QT_DEBUG
            if(sStatusString!="")
            {
                qDebug("Status %s",sStatusString.toLatin1().data());
            }
        #endif

            bool _bIsInit=false;
            bool _bIsTemp=false;

            setDebugActive(true);

            while(isDebugActive())
            {
                bool bContinue=false;
                STATE _state=waitForSignal(nProcessID); // TODO result

                if(_state.debuggerStatus==DEBUGGER_STATUS_STOP)
                {
                    qDebug("process stoped: %x",_state.nCode);

                    bool bProcessEntryPoint=false;

                    if(!_bIsInit)
                    {
                        _bIsInit=true;
                        bProcessEntryPoint=true;

//                        setPtraceOptions(nProcessID); // Set options

                        XInfoDB::PROCESS_INFO processInfo={};

                        processInfo.nProcessID=nProcessID;
                        processInfo.nMainThreadID=nProcessID;
                        processInfo.sFileName=sFileName;
//                        processInfo.sBaseFileName;
//                        processInfo.nImageBase;
//                        processInfo.nImageSize;
//                        processInfo.nStartAddress;
//                        processInfo.nThreadLocalBase;
                        processInfo.hProcessMemoryIO=XProcess::openMemoryIO(nProcessID);
                        processInfo.hProcessMemoryQuery=XProcess::openMemoryQuery(nProcessID);
//                        processInfo.hMainThread;

                        getXInfoDB()->setProcessInfo(processInfo);

                        emit eventCreateProcess(&processInfo);

                        XInfoDB::THREAD_INFO threadInfo={};

                        threadInfo.nThreadID=nProcessID;

                        getXInfoDB()->addThreadInfo(&threadInfo);

                        emit eventCreateThread(&threadInfo);

                        // TODO Breakpoint to EntryPoint
                        // TODO add thread
                    }

                    if(_state.nCode==5)
                    {
                        qDebug("BREAKPOINT");

                        XInfoDB::BREAKPOINT_INFO breakPointInfo={};

                        breakPointInfo.nAddress=getXInfoDB()->getCurrentInstructionPointer(nProcessID);

                        if(bProcessEntryPoint)
                        {
                            breakPointInfo.bpType=XInfoDB::BPT_CODE_HARDWARE;
                            breakPointInfo.bpInfo=XInfoDB::BPI_PROCESSENTRYPOINT;
                        }

                        breakPointInfo.pHProcessMemoryIO=getXInfoDB()->getProcessInfo()->hProcessMemoryIO;
                        breakPointInfo.pHProcessMemoryQuery=getXInfoDB()->getProcessInfo()->hProcessMemoryQuery;
                        breakPointInfo.nProcessID=getXInfoDB()->getProcessInfo()->nProcessID;
                        breakPointInfo.nThreadID=getXInfoDB()->getProcessInfo()->nMainThreadID;

                        emit eventBreakPoint(&breakPointInfo);

//                        getXInfoDB()->_lockId(getXInfoDB()->getProcessInfo()->nMainThreadID);
//                        getXInfoDB()->_waitID(getXInfoDB()->getProcessInfo()->nMainThreadID);

//                        while()
//                        {
//                            QThread::msleep(10);
//                        }

                        if(bProcessEntryPoint)
                        {
                            bContinue=true;
                        }
                    }

                    if(!_bIsTemp)
                    {
//                        XProcess::HANDLEID handleThread={};
//                        handleThread.nID=getXInfoDB()->getProcessInfo()->nProcessID;

//                        getXInfoDB()->stepInto(handleThread);

//                        _bIsTemp=true;
                    }
                }
                else if(_state.debuggerStatus==DEBUGGER_STATUS_EXIT)
                {
                    qDebug("process exited with code %x",_state.nCode);
                    break;
                }

                if(bContinue)
                {
//                    continueThread(nProcessID);
                }

//                continueThread(nProcessID);
            }

//            qDebug("Address: %llX",getCurrentAddress(handleThreadID));

//            qint64 nCurrentAddress=getCurrentAddress(handleThreadID);

////            nCurrentAddress=0x10a0;
////            nCurrentAddress=0x7efe2684d100;

//            getXInfoDB()->addBreakPoint(nCurrentAddress,XInfoDB::BPT_CODE_SOFTWARE,XInfoDB::BPI_PROCESSENTRYPOINT);
////            _setStep(handleProcessID);

////            XProcess::closeMemoryIO(processInfo.hProcessIO);

////            // TODO eventCreateProcess
////            // TODO set on entryPoint
////            // TODO here set Breakpoints

//////            continueThread(processInfo.nProcessID);
////            XBinary::REG_OPTIONS regOptions={};
////            regOptions.bGeneral=true;
////            regOptions.bFlags=true;
////            regOptions.bFloat=true;
////            regOptions.bIP=true;
////            regOptions.bSegments=true;
////            regOptions.bXMM=true;

////            QMap<QString,XBinary::XVARIANT> mapRegisters;

////            mapRegisters=getRegisters(handleID,regOptions);

////            qDebug("RIP: %s",XBinary::valueToHex(mapRegisters.value("RIP").var.v_uint64).toLatin1().data());

////            _setStep(handleID);

////            mapRegisters=getRegisters(handleID,regOptions);

////            qDebug("RIP: %s",XBinary::valueToHex(mapRegisters.value("RIP").var.v_uint64).toLatin1().data());

//            // TODO debug loop

//            setDebugActive(true);

//            continueThread(processInfo.nProcessID);

////            int nTest=1;

//            while(isDebugActive())
//            {
//                qDebug("WAIT_0");
//                STATE state=waitForSignal(nProcessID);
//                qDebug("AddressXXX: %llX",getCurrentAddress(handleThreadID));

//                if(state.debuggerStatus==DEBUGGER_STATUS_SIGNAL)
//                {
//                    // TODO emit signal
//                    qDebug("process killed by signal %x",state.nCode);
//                    break;
//                }
//                else if(state.debuggerStatus==DEBUGGER_STATUS_EXIT)
//                {
//                    qDebug("process exited with code %x",state.nCode);
//                    break;
//                }
//                else if(state.debuggerStatus==DEBUGGER_STATUS_STOP)
//                {
//                    qDebug("process stoped: %x",state.nCode);

//                    if(state.nCode==5)
//                    {
//                        qDebug("BREAKPOINT");
//                        // TODO Breakpoint

//                        qint64 nExceptionAddress=findAddressByException(getCurrentAddress(handleThreadID)); // TODO rename

//                        if(nExceptionAddress!=-1)
//                        {
//                            XInfoDB::BREAKPOINT _currentBP=getXInfoDB()->findBreakPointByAddress(nExceptionAddress);
//                            getXInfoDB()->removeBreakPoint(nExceptionAddress,_currentBP.bpType);
//                            // TODO set currentAddress

//                            XInfoDB::BREAKPOINT_INFO breakPointInfo={};

//                            breakPointInfo.nAddress=nExceptionAddress;
//                            breakPointInfo.bpType=_currentBP.bpType;
//                            breakPointInfo.bpInfo=_currentBP.bpInfo;
//                            breakPointInfo.sInfo=_currentBP.sInfo;
////                            breakPointInfo.handleIDThread=handleIDThread;
//                            breakPointInfo.pHProcessMemoryIO=handleMemoryIO.hHandle;
//                            breakPointInfo.pHProcessMemoryQuery=handleMemoryQuery.hHandle;
//                            breakPointInfo.nThreadID=handleThreadID.nID;

//                            emit eventBreakPoint(&breakPointInfo);
//                            // TODO
//                            qDebug("BREAKPOINT START");
//                            qDebug("Current Address1: %llX",getCurrentAddress(handleThreadID));

////                            sleep(10);

//                            qDebug("BREAKPOINT END");
//                        }
//                        else
//                        {
//                            continueThread(handleThreadID.nID);
//                        }
//                    }
//                    else if(state.nCode==6)
//                    {
////                        continueThread(processInfo.nProcessID);
//                    }
//                }

////                int wait_status;
////                waitpid(processInfo.nProcessID,&wait_status,0);

//                qDebug("WAIT");

////                if(nTest>0)
////                {
////                    continueThread(processInfo.nProcessID);
////                    nTest--;
////                }
////                continueThread(processInfo.nProcessID);
////                break;
//            }

//            setDebugActive(false);
        }
        else if(nProcessID<0) // -1
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

void XLinuxDebugger::cleanUp()
{

}

QString XLinuxDebugger::getArch()
{
    // TODO
    return "AMD64";
}

XBinary::MODE XLinuxDebugger::getMode()
{
    // TODO
    return XBinary::MODE_64;
}
