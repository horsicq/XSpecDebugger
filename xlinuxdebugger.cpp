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

XLinuxDebugger::XLinuxDebugger(QObject *pParent) : XUnixDebugger(pParent)
{

}

bool XLinuxDebugger::load()
{
    bool bResult=false;

    QString sFileName=getOptions()->sFileName;

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

            EXECUTEPROCESS ep=executeProcess(sFileName);

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
        #endif

            QString sStatusString=pMapMemory;
            munmap(pMapMemory,nMapSize);

        #ifdef QT_DEBUG
            if(sStatusString!="")
            {
                qDebug("Status %s",sStatusString.toLatin1().data());
            }
        #endif

            // TODO wait

            waitForSignal(nProcessID); // TODO result

            setPtraceOptions(nProcessID); // Set options

            XProcess::HANDLEID handleThreadID={};
            handleThreadID.nID=nProcessID;

            XProcess::HANDLEID handleMemoryIO={};
            handleMemoryIO.nID=nProcessID;
            handleMemoryIO.hHandle=XProcess::openMemoryIO(nProcessID);

            XProcess::HANDLEID handleMemoryQuery={};
            handleMemoryQuery.nID=nProcessID;
            handleMemoryQuery.hHandle=XProcess::openMemoryQuery(nProcessID);

            XAbstractDebugger::PROCESS_INFO processInfo={};
            processInfo.nProcessID=nProcessID;
            processInfo.hProcessMemoryIO=handleMemoryIO.hHandle;
            processInfo.hProcessMemoryQuery=handleMemoryQuery.hHandle;
            // TODO more handles

            setProcessInfo(&processInfo);
            // TODO more
            // TODO show regs

            REG_OPTIONS regOptions={};
            regOptions.bGeneral=true;
            regOptions.bFlags=true;
            regOptions.bFloat=true;
            regOptions.bIP=true;
            regOptions.bSegments=true;
            regOptions.bXMM=true;

            emit eventCreateProcess(&processInfo);

            qDebug("Address: %llX",getCurrentAddress(handleThreadID));

            qint64 nCurrentAddress=getCurrentAddress(handleThreadID);

            setBP(nCurrentAddress,BPT_CODE_SOFTWARE,BPI_PROCESSENTRYPOINT);
//            _setStep(handleProcessID);

//            XProcess::closeMemoryIO(processInfo.hProcessIO);

//            // TODO eventCreateProcess
//            // TODO set on entryPoint
//            // TODO here set Breakpoints

////            continueThread(processInfo.nProcessID);

//            QMap<QString,XBinary::XVARIANT> mapRegisters;

//            mapRegisters=getRegisters(handleID,regOptions);

//            qDebug("RIP: %s",XBinary::valueToHex(mapRegisters.value("RIP").var.v_uint64).toLatin1().data());

//            _setStep(handleID);

//            mapRegisters=getRegisters(handleID,regOptions);

//            qDebug("RIP: %s",XBinary::valueToHex(mapRegisters.value("RIP").var.v_uint64).toLatin1().data());

            // TODO debug loop

            setDebugActive(true);

            continueThread(processInfo.nProcessID);

//            int nTest=1;

            while(isDebugActive())
            {
                qDebug("WAIT_0");
                STATE state=waitForSignal(nProcessID);
                qDebug("AddressXXX: %llX",getCurrentAddress(handleThreadID));

                if(state.debuggerStatus==DEBUGGER_STATUS_SIGNAL)
                {
                    // TODO emit signal
                    qDebug("process killed by signal %x",state.nCode);
                    break;
                }
                else if(state.debuggerStatus==DEBUGGER_STATUS_EXIT)
                {
                    qDebug("process exited with code %x",state.nCode);
                    break;
                }
                else if(state.debuggerStatus==DEBUGGER_STATUS_STOP)
                {
                    qDebug("process stoped: %x",state.nCode);

                    if(state.nCode==5)
                    {
                        qDebug("BREAKPOINT");
                        // TODO Breakpoint

                        qint64 nExceptionAddress=findAddressByException(getCurrentAddress(handleThreadID));

                        if(nExceptionAddress!=-1)
                        {
                            BREAKPOINT _currentBP=getSoftwareBreakpoints()->value(nExceptionAddress);
                            removeBP(nExceptionAddress,_currentBP.bpType);
                            // TODO set currentAddress

                            XAbstractDebugger::BREAKPOINT_INFO breakPointInfo={};

                            breakPointInfo.nAddress=nExceptionAddress;
                            breakPointInfo.bpType=_currentBP.bpType;
                            breakPointInfo.bpInfo=_currentBP.bpInfo;
                            breakPointInfo.sInfo=_currentBP.sInfo;
//                            breakPointInfo.handleIDThread=handleIDThread;
                            breakPointInfo.handleProcessMemoryIO=handleMemoryIO;
                            breakPointInfo.handleProcessMemoryQuery=handleMemoryQuery;
                            breakPointInfo.handleThread=handleThreadID;

                            emit eventBreakPoint(&breakPointInfo);
                            // TODO
                            qDebug("BREAKPOINT START");
                            qDebug("Current Address1: %llX",getCurrentAddress(handleThreadID));

                            sleep(10);

                            qDebug("BREAKPOINT END");
                        }
                        else
                        {
                            continueThread(handleThreadID.nID);
                        }
                    }
                }

//                int wait_status;
//                waitpid(processInfo.nProcessID,&wait_status,0);

                qDebug("WAIT");

//                if(nTest>0)
//                {
//                    continueThread(processInfo.nProcessID);
//                    nTest--;
//                }
//                continueThread(processInfo.nProcessID);
//                break;
            }

            setDebugActive(false);
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
