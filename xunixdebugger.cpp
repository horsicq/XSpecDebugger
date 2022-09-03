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
    g_pTimer=nullptr;
}

bool XUnixDebugger::run()
{
    // TODO

    return false;
}

bool XUnixDebugger::stop()
{
    bool bResult=false;

    if(kill(getXInfoDB()->getProcessInfo()->nProcessID,SIGKILL)!=-1)
    {
        stopDebugLoop();

        setDebugActive(false);

        bResult=true;
    }

    return bResult;
}

void XUnixDebugger::cleanUp()
{
    XUnixDebugger::stop();
    XUnixDebugger::wait();
    // TODO stopDebugEvent
#ifdef Q_OS_LINUX
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
#endif
}

XUnixDebugger::EXECUTEPROCESS XUnixDebugger::executeProcess(QString sFileName,QString sDirectory)
{
    EXECUTEPROCESS result={};

    result.sStatus="Error";
#ifdef Q_OS_MAC
    if(::chdir(qPrintable(sDirectory))==0)
#endif
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

XUnixDebugger::STATE XUnixDebugger::waitForSignal(qint64 nProcessID,qint32 nOptions)
{
    STATE result={};

    pid_t nThreadId=0;
    qint32 nResult=0;

    // TODO a function
    // TODO Clone event
    do
    {
        nThreadId=waitpid(nProcessID,&nResult,nOptions);
    }
    while((nThreadId==-1)&&(errno==EINTR));

    if(nThreadId<0)
    {
        qDebug("waitpid failed: %s",strerror(errno));
    }

    if(nThreadId>0)
    {
        result.nThreadId=nThreadId;

        siginfo_t sigInfo={};

        if(ptrace(PTRACE_GETSIGINFO,nThreadId,0,&sigInfo)<0)
        {
            qDebug("Error: %s",strerror(errno));
        }

        qDebug("si_code: %x",sigInfo.si_code);
        qDebug("si_errno: %x",sigInfo.si_errno);
        qDebug("si_signo: %x",sigInfo.si_signo);

        qDebug("si_pid: %x",sigInfo.si_pid);
        qDebug("si_uid: %x",sigInfo.si_uid);
        qDebug("si_timerid: %x",sigInfo.si_timerid);
        qDebug("si_overrun: %x",sigInfo.si_overrun);

        qDebug("si_status: %x",sigInfo.si_status);
        qDebug("si_utime: %lx",sigInfo.si_utime);
        qDebug("si_stime: %lx",sigInfo.si_stime);

        qDebug("si_value: %llx",(quint64)sigInfo.si_value.sival_int);
        qDebug("si_int: %x",sigInfo.si_int);
        qDebug("si_ptr: %llx",(quint64)sigInfo.si_ptr);

        qDebug("si_addr: %llx",(quint64)sigInfo.si_addr);
        qDebug("si_addr_lsb: %x",sigInfo.si_addr_lsb);
        qDebug("si_lower: %llx",(quint64)sigInfo.si_lower);
        qDebug("si_upper: %llx",(quint64)sigInfo.si_upper);
        qDebug("si_pkey: %x",sigInfo.si_pkey);
        qDebug("si_band: %lx",sigInfo.si_band);
        qDebug("si_fd: %x",sigInfo.si_fd);

        qDebug("si_call_addr: %llx",(quint64)sigInfo.si_call_addr);
        qDebug("si_syscall: %x",sigInfo.si_syscall);
        qDebug("si_arch: %x",sigInfo.si_arch);

        // 80 = SI_KERNEL

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
    }

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

void XUnixDebugger::startDebugLoop()
{
    stopDebugLoop();

    g_pTimer=new QTimer(this);

    connect(g_pTimer,SIGNAL(timeout()),this,SLOT(_debugEvent()));

    g_pTimer->start(N_N_DEDELAY);
}

void XUnixDebugger::stopDebugLoop()
{
    if(g_pTimer)
    {
        g_pTimer->stop();

        delete g_pTimer;

        g_pTimer=nullptr;
    }
}

bool XUnixDebugger::stepIntoById(X_ID nThreadId,XInfoDB::BPI bpInfo)
{
    return getXInfoDB()->stepIntoById(nThreadId,bpInfo,true);
}

bool XUnixDebugger::stepOverById(X_ID nThreadId,XInfoDB::BPI bpInfo)
{
    return getXInfoDB()->stepOverById(nThreadId,bpInfo,true);
}

void XUnixDebugger::_debugEvent()
{
    if(isDebugActive())
    {
        qint64 nId=getXInfoDB()->getProcessInfo()->nProcessID;

        STATE state=waitForSignal(nId,__WALL|WNOHANG);

        if(state.debuggerStatus==DEBUGGER_STATUS_STOP)
        {
            XInfoDB::BREAKPOINT_INFO breakPointInfo={};

            breakPointInfo.nAddress=getXInfoDB()->getCurrentInstructionPointerById(nId);
            breakPointInfo.bpType=XInfoDB::BPT_CODE_HARDWARE;
            breakPointInfo.bpInfo=XInfoDB::BPI_PROCESSENTRYPOINT;

            breakPointInfo.pHProcessMemoryIO=getXInfoDB()->getProcessInfo()->hProcessMemoryIO;
            breakPointInfo.pHProcessMemoryQuery=getXInfoDB()->getProcessInfo()->hProcessMemoryQuery;
            breakPointInfo.nProcessID=getXInfoDB()->getProcessInfo()->nProcessID;
            breakPointInfo.nThreadID=getXInfoDB()->getProcessInfo()->nMainThreadID;

            emit eventBreakPoint(&breakPointInfo);
        }
    }
}
