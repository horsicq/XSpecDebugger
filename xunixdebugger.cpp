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
#include "xunixdebugger.h"

XUnixDebugger::XUnixDebugger(QObject *pParent) : XAbstractDebugger(pParent)
{

}

XUnixDebugger::EXECUTEPROCESS XUnixDebugger::executeProcess(QString sFileName)
{
    EXECUTEPROCESS result={};

    char **ppArgv=new char *[2];

    ppArgv[0]=allocateAnsiStringMemory(sFileName);

#ifdef QT_DEBUG
    qDebug("FileName %s",ppArgv[0]);
#endif

    qint32 nRet=execv(ppArgv[0],ppArgv); // TODO Unicode

    if(nRet==-1)
    {
        result.sStatus=QString("execv() failed: %1").arg(strerror(errno));

    #ifdef QT_DEBUG
        qDebug("Status %s",result.sStatus.toLatin1().data());
    #endif
    }

    for(qint32 i=0;i<2;i++)
    {
        delete [] ppArgv[i];
    }

    delete [] ppArgv;

    return result;
}

void XUnixDebugger::setPtraceOptions(qint64 nThreadID)
{
    // TODO result bool
    long options=PTRACE_O_TRACECLONE;

    if(ptrace(PTRACE_SETOPTIONS,nThreadID,0,options)==-1)
    {
    #ifdef QT_DEBUG
        qDebug("Cannot PTRACE_SETOPTIONS");
    #endif
    }

    // mb TODO
}

void XUnixDebugger::waitForSignal(qint64 nProcessID)
{
    pid_t ret;

    int nStatus=0;

    // TODO a function
    do
    {
        ret=waitpid(nProcessID,&nStatus,__WALL);
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
}

void XUnixDebugger::continueThread(qint64 nThreadID)
{
    // TODO
    ptrace(PTRACE_CONT,nThreadID,0,0);
}
