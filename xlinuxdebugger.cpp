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
        int nPID=fork();

        if(nPID==0)
        {
            // Child process
            ptrace(PTRACE_TRACEME,0,nullptr,nullptr);
            // TODO redirect I/O

            EXECUTEPROCESS ep=executeProcess(sFileName);

            XBinary::_copyMemory(pMapMemory,ep.sStatus.toLatin1().data(),ep.sStatus.toLatin1().size());

            abort();
        }
        else if(nPID>0)
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

            pid_t ret;

            int nStatus=0;

            // TODO a function
            do
            {
                ret=waitpid(nPID,&nStatus,__WALL);
            }
            while((ret==-1)&&(errno==EINTR));

            if(ret==-1)
            {
                qDebug("waitpid failed: %s",strerror(errno));
            }
            else if(WIFEXITED(nStatus))
            {
                qDebug("process exited with code %x",WEXITSTATUS(nStatus));
            }
            else if(WIFSIGNALED(nStatus))
            {
                qDebug("process killed by signal %x",WTERMSIG(nStatus));
            }
            else if(WIFSTOPPED(nStatus)&&(WSTOPSIG(nStatus)==SIGABRT))
            {
                qDebug("process unexpectedly aborted");
            }
            // TODO fast events

            qDebug("STATUS: %x",nStatus);

            setPtraceOptions(nPID);

            // TODO Create process
            // TODO open memory
            // TODO debug loop
        }
        else if(nPID<0) // -1
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
