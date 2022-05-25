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
#include "xunixdebugger.h"

XUnixDebugger::XUnixDebugger(QObject *pParent,XInfoDB *pXInfoDB) : XAbstractDebugger(pParent,pXInfoDB)
{

}

bool XUnixDebugger::stop()
{
    bool bResult=false;

    if(kill(getXInfoDB()->getProcessInfo()->nProcessID,SIGKILL)!=-1)
    {
        bResult=true;
    }

//    sleep(1000);

    return bResult;
}

void XUnixDebugger::cleanUp()
{
    XUnixDebugger::stop();

    if(getXInfoDB()->getProcessInfo()->hProcessMemoryIO)
    {
        XProcess::closeMemoryIO(getXInfoDB()->getProcessInfo()->hProcessMemoryIO);
        getXInfoDB()->getProcessInfo()->hProcessMemoryIO=0;
    }

    if(getXInfoDB()->getProcessInfo()->hProcessMemoryQuery)
    {
        XProcess::closeMemoryQuery(getXInfoDB()->getProcessInfo()->hProcessMemoryQuery);
        getXInfoDB()->getProcessInfo()->hProcessMemoryQuery=0;
    }
}

XUnixDebugger::EXECUTEPROCESS XUnixDebugger::executeProcess(QString sFileName,QString sDirectory)
{
    EXECUTEPROCESS result={};

//    if(chdir(qPrintable(sDirectory))==0)
    {
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
    }

    return result;
}

void XUnixDebugger::setPtraceOptions(qint64 nThreadID)
{
    // TODO getOptions !!!
    // TODO result bool
//    long options=PTRACE_O_TRACECLONE;
//    long options=PTRACE_O_EXITKILL|PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEFORK;
#if defined(Q_OS_LINUX)
    long options=PTRACE_O_EXITKILL|PTRACE_O_TRACECLONE;
    // PTRACE_O_TRACECLONE create thread

    if(ptrace(PTRACE_SETOPTIONS,nThreadID,0,options)==-1)
    {
    #ifdef QT_DEBUG
        qDebug("Cannot PTRACE_SETOPTIONS");
    #endif
    }
#endif
    // mb TODO
}

XUnixDebugger::STATE XUnixDebugger::waitForSignal(qint64 nProcessID)
{
    STATE result={};

    pid_t ret=0;
    qint32 nResult=0;

    // TODO a function
    do
    {
    #if defined(Q_OS_LINUX)
        ret=waitpid(nProcessID,&nResult,__WALL);
    #endif
    #if defined(Q_OS_OSX)
        ret=waitpid(nProcessID,&nResult,P_ALL);
    #endif
    }
    while((ret==-1)&&(errno==EINTR));

    if(ret==-1)
    {
        qDebug("waitpid failed: %s",strerror(errno));
    }

    if(WIFSTOPPED(nResult))
    {
        result.debuggerStatus=DEBUGGER_STATUS_STOP;
        result.nCode=WSTOPSIG(nResult);

        if(WSTOPSIG(nResult)==SIGABRT)
        {
            qDebug("process unexpectedly aborted");
        }
        else
        {

        }
        qDebug("WSTOPSIG %x",WSTOPSIG(nResult));
    }
    else if(WIFEXITED(nResult))
    {
        result.debuggerStatus=DEBUGGER_STATUS_EXIT;
        result.nCode=WEXITSTATUS(nResult);
    }
    else if(WIFSIGNALED(nResult))
    {
        result.debuggerStatus=DEBUGGER_STATUS_SIGNAL;
        result.nCode=WTERMSIG(nResult);
    }
    // TODO fast events

    qDebug("STATUS: %x",nResult);

    return result;
}

void XUnixDebugger::continueThread(qint64 nThreadID)
{
    // TODO
#if defined(Q_OS_LINUX)
    if(ptrace(PTRACE_CONT,nThreadID,0,0))
    {
        int wait_status;
        waitpid(nThreadID,&wait_status,0);
    }
#endif
#if defined(Q_OS_OSX)
    ptrace(PT_CONTINUE,nThreadID,0,0);
#endif

//    int wait_status;
//    waitpid(nThreadID,&wait_status,0);
    // TODO result
}

bool XUnixDebugger::resumeThread(XProcess::HANDLEID handleID)
{
    bool bResult=false;
#if defined(Q_OS_LINUX)
    if(ptrace(PTRACE_CONT,handleID.nID,0,0))
    {
        int wait_status;
        waitpid(handleID.nID,&wait_status,0);
    }
#endif
    return bResult;
}

bool XUnixDebugger::_setStep(XProcess::HANDLEID handleID)
{
    // TODO handle return
    bool bResult=true;
#if defined(Q_OS_LINUX)
    ptrace(PTRACE_SINGLESTEP,handleID.nID,0,0);
#endif
#if defined(Q_OS_OSX)
    ptrace(PT_STEP,handleID.nID,0,0);
#endif
//    int wait_status;
//    waitpid(handleID.nID,&wait_status,0);
//    // TODO result

    return bResult;
}
