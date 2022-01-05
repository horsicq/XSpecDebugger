/* Copyright (c) 2020-2021 hors<horsicq@gmail.com>
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

            waitForSignal(nProcessID);

            setPtraceOptions(nProcessID); // Set options

            XAbstractDebugger::PROCESS_INFO processInfo={};
            processInfo.nProcessID=nProcessID;

            setProcessInfo(&processInfo);
            // TODO more
            // TODO show regs

            XProcess::HANDLEID handleID={};
            handleID.nID=nProcessID;

            REG_OPTIONS regOptions={};
            regOptions.bGeneral=true;
            regOptions.bFlags=true;
            regOptions.bFloat=true;
            regOptions.bIP=true;
            regOptions.bSegments=true;
            regOptions.bXMM=true;

            emit eventCreateProcess(&processInfo);

            // TODO eventCreateProcess
            // TODO set on entryPoint
            // TODO here set Breakpoints

//            continueThread(processInfo.nProcessID);

            QMap<QString,XBinary::XVARIANT> mapRegisters;

            mapRegisters=getRegisters(handleID,regOptions);

            qDebug("RIP: %s",XBinary::valueToHex(mapRegisters.value("RIP").var.v_uint64).toLatin1().data());

            _setStep(handleID);

            mapRegisters=getRegisters(handleID,regOptions);

            qDebug("RIP: %s",XBinary::valueToHex(mapRegisters.value("RIP").var.v_uint64).toLatin1().data());

            // TODO open memory
            // TODO debug loop

            setDebugActive(true);

//            int nTest=1;

            while(isDebugActive())
            {
                waitForSignal(nProcessID);
//                int wait_status;
//                waitpid(processInfo.nProcessID,&wait_status,0);

                qDebug("WAIT");

//                if(nTest>0)
//                {
//                    continueThread(processInfo.nProcessID);
//                    nTest--;
//                }
//                continueThread(processInfo.nProcessID);
                break;
            }
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
