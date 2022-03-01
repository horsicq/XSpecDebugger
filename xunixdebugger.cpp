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

XUnixDebugger::XUnixDebugger(QObject *pParent) : XAbstractDebugger(pParent)
{

}

bool XUnixDebugger::stop()
{
    bool bResult=false;

    if(kill(getProcessInfo()->nProcessID,SIGKILL)!=-1)
    {
        bResult=true;
    }

//    sleep(1000);

    return bResult;
}

void XUnixDebugger::cleanUp()
{
    XUnixDebugger::stop();

    if(getProcessInfo()->hProcessMemoryIO)
    {
        XProcess::closeMemoryIO(getProcessInfo()->hProcessMemoryIO);
        getProcessInfo()->hProcessMemoryIO=0;
    }

    if(getProcessInfo()->hProcessMemoryQuery)
    {
        XProcess::closeMemoryQuery(getProcessInfo()->hProcessMemoryQuery);
        getProcessInfo()->hProcessMemoryQuery=0;
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
    ptrace(PTRACE_CONT,nThreadID,0,0);
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

XAbstractDebugger::REGISTERS XUnixDebugger::getRegisters(XProcess::HANDLEID handleID,REG_OPTIONS regOptions)
{
    XAbstractDebugger::REGISTERS result={};
#if defined(Q_OS_LINUX)
    user_regs_struct regs={};
//    user_regs_struct regs;
    errno=0;

    if(ptrace(PTRACE_GETREGS,handleID.nID,nullptr,&regs)!=-1)
    {
        if(regOptions.bGeneral)
        {
            result.RAX=regs.rax;
            result.RBX=(quint64)(regs.rbx);
            result.RCX=(quint64)(regs.rcx);
            result.RDX=(quint64)(regs.rdx);
            result.RBP=(quint64)(regs.rbp);
            result.RSP=(quint64)(regs.rsp);
            result.RSI=(quint64)(regs.rsi);
            result.RDI=(quint64)(regs.rdi);
            result.R8=(quint64)(regs.r8);
            result.R9=(quint64)(regs.r9);
            result.R10=(quint64)(regs.r10);
            result.R11=(quint64)(regs.r11);
            result.R12=(quint64)(regs.r12);
            result.R13=(quint64)(regs.r13);
            result.R14=(quint64)(regs.r14);
            result.R15=(quint64)(regs.r15);
        }

        if(regOptions.bIP)
        {
            result.RIP=(quint64)(regs.rip);
        }

        if(regOptions.bFlags)
        {
            result.EFLAGS=(quint32)(regs.eflags);
        }

        if(regOptions.bSegments)
        {
            result.GS=(quint16)(regs.gs);
            result.FS=(quint16)(regs.fs);
            result.ES=(quint16)(regs.es);
            result.DS=(quint16)(regs.ds);
            result.CS=(quint16)(regs.cs);
            result.SS=(quint16)(regs.ss);
        }
    }
    else
    {
        qDebug("errno: %s",strerror(errno));
    }

//    __extension__ unsigned long long int orig_rax;
//    __extension__ unsigned long long int fs_base;
//    __extension__ unsigned long long int gs_base;
#endif
    return result;
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
