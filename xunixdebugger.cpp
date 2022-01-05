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

    sleep(1000);

    return bResult;
}

void XUnixDebugger::cleanUp()
{
    XUnixDebugger::stop();
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
//    long options=PTRACE_O_TRACECLONE;
    long options=PTRACE_O_EXITKILL|PTRACE_O_TRACESYSGOOD|PTRACE_O_TRACEFORK;

    if(ptrace(PTRACE_SETOPTIONS,nThreadID,0,options)==-1)
    {
    #ifdef QT_DEBUG
        qDebug("Cannot PTRACE_SETOPTIONS");
    #endif
    }

    // mb TODO
}

qint32 XUnixDebugger::waitForSignal(qint64 nProcessID)
{
    qint32 nResult=0;

    pid_t ret=0;

    // TODO a function
    do
    {
        ret=waitpid(nProcessID,&nResult,__WALL);
    }
    while((ret==-1)&&(errno==EINTR));

    if(ret==-1)
    {
        qDebug("waitpid failed: %s",strerror(errno));
    }
    else if(WEXITSTATUS(nResult))
    {
        qDebug("WEXITSTATUS %x",WEXITSTATUS(nResult));
    }
    else if(WSTOPSIG(nResult))
    {
        qDebug("WSTOPSIG %x",WSTOPSIG(nResult));
    }
    else if(WTERMSIG(nResult))
    {
        qDebug("WTERMSIG %x",WTERMSIG(nResult));
    }
    else if(WIFEXITED(nResult))
    {
        qDebug("process exited with code %x",WEXITSTATUS(nResult));
    }
    else if(WIFSIGNALED(nResult))
    {
        qDebug("process killed by signal %x",WTERMSIG(nResult));
    }
    else if(WIFSTOPPED(nResult)&&(WSTOPSIG(nResult)==SIGABRT))
    {
        qDebug("process unexpectedly aborted");
    }
    else if(WIFCONTINUED(nResult))
    {
        qDebug("WIFCONTINUED %x",WIFCONTINUED(nResult));
    }
    // TODO fast events

    qDebug("STATUS: %x",nResult);

    return nResult;
}

void XUnixDebugger::continueThread(qint64 nThreadID)
{
    // TODO
    ptrace(PTRACE_CONT,nThreadID,0,0);

    int wait_status;
    waitpid(nThreadID,&wait_status,0);
    // TODO result
}

bool XUnixDebugger::resumeThread(XProcess::HANDLEID handleID)
{
    bool bResult=false;

    if(ptrace(PTRACE_CONT,handleID.nID,0,0))
    {
        int wait_status;
        waitpid(handleID.nID,&wait_status,0);
    }

    return bResult;
}

QMap<QString, XBinary::XVARIANT> XUnixDebugger::getRegisters(XProcess::HANDLEID handleID, REG_OPTIONS regOptions)
{
    QMap<QString, XBinary::XVARIANT> mapResult;

    user_regs_struct regs={};
//    user_regs_struct regs;
    errno=0;

    if(ptrace(PTRACE_GETREGS,handleID.nID,nullptr,&regs)!=-1)
    {
        XBinary::XVARIANT xVariant={};

        if(regOptions.bGeneral)
        {
            xVariant={};

            xVariant.bIsBigEndian=false; // TODO Check

            xVariant.mode=XBinary::MODE_64; // TODO Check
            xVariant.var.v_uint64=(quint64)(regs.rax);
            mapResult.insert("RAX",xVariant);
            xVariant.var.v_uint64=(quint64)(regs.rbx);
            mapResult.insert("RBX",xVariant);
            xVariant.var.v_uint64=(quint64)(regs.rcx);
            mapResult.insert("RCX",xVariant);
            xVariant.var.v_uint64=(quint64)(regs.rdx);
            mapResult.insert("RDX",xVariant);
            xVariant.var.v_uint64=(quint64)(regs.rbp);
            mapResult.insert("RBP",xVariant);
            xVariant.var.v_uint64=(quint64)(regs.rsp);
            mapResult.insert("RSP",xVariant);
            xVariant.var.v_uint64=(quint64)(regs.rsi);
            mapResult.insert("RSI",xVariant);
            xVariant.var.v_uint64=(quint64)(regs.rdi);
            mapResult.insert("RDI",xVariant);
            xVariant.var.v_uint64=(quint64)(regs.r8);
            mapResult.insert("R8",xVariant);
            xVariant.var.v_uint64=(quint64)(regs.r9);
            mapResult.insert("R9",xVariant);
            xVariant.var.v_uint64=(quint64)(regs.r10);
            mapResult.insert("R10",xVariant);
            xVariant.var.v_uint64=(quint64)(regs.r11);
            mapResult.insert("R11",xVariant);
            xVariant.var.v_uint64=(quint64)(regs.r12);
            mapResult.insert("R12",xVariant);
            xVariant.var.v_uint64=(quint64)(regs.r13);
            mapResult.insert("R13",xVariant);
            xVariant.var.v_uint64=(quint64)(regs.r14);
            mapResult.insert("R14",xVariant);
            xVariant.var.v_uint64=(quint64)(regs.r15);
            mapResult.insert("R15",xVariant);
        }

        if(regOptions.bIP)
        {
            xVariant={};
            xVariant.mode=XBinary::MODE_64;
            xVariant.var.v_uint64=(quint64)(regs.rip);
            mapResult.insert("RIP",xVariant);
        }

        if(regOptions.bFlags)
        {
            xVariant={};
            xVariant.mode=XBinary::MODE_32;
            xVariant.var.v_uint32=(quint32)(regs.eflags);
            mapResult.insert("EFLAGS",xVariant);

            xVariant={};
            xVariant.mode=XBinary::MODE_BIT;
            xVariant.var.v_bool=(bool)((regs.eflags)&0x0001);
            mapResult.insert("CF",xVariant);
            xVariant.var.v_bool=(bool)((regs.eflags)&0x0004);
            mapResult.insert("PF",xVariant);
            xVariant.var.v_bool=(bool)((regs.eflags)&0x0010);
            mapResult.insert("AF",xVariant);
            xVariant.var.v_bool=(bool)((regs.eflags)&0x0040);
            mapResult.insert("ZF",xVariant);
            xVariant.var.v_bool=(bool)((regs.eflags)&0x0080);
            mapResult.insert("SF",xVariant);
            xVariant.var.v_bool=(bool)((regs.eflags)&0x0100);
            mapResult.insert("TF",xVariant);
            xVariant.var.v_bool=(bool)((regs.eflags)&0x0200);
            mapResult.insert("IF",xVariant);
            xVariant.var.v_bool=(bool)((regs.eflags)&0x0400);
            mapResult.insert("DF",xVariant);
            xVariant.var.v_bool=(bool)((regs.eflags)&0x0800);
            mapResult.insert("OF",xVariant);
        }

        if(regOptions.bSegments)
        {
            xVariant={};
            xVariant.mode=XBinary::MODE_16;
            xVariant.var.v_uint16=(quint16)(regs.gs);
            mapResult.insert("GS",xVariant);
            xVariant.var.v_uint16=(quint16)(regs.fs);
            mapResult.insert("FS",xVariant);
            xVariant.var.v_uint16=(quint16)(regs.es);
            mapResult.insert("ES",xVariant);
            xVariant.var.v_uint16=(quint16)(regs.ds);
            mapResult.insert("DS",xVariant);
            xVariant.var.v_uint16=(quint16)(regs.cs);
            mapResult.insert("CS",xVariant);
            xVariant.var.v_uint16=(quint16)(regs.ss);
            mapResult.insert("SS",xVariant);
        }

    }
    else
    {
        qDebug("errno: %s",strerror(errno));
    }

//    __extension__ unsigned long long int orig_rax;
//    __extension__ unsigned long long int fs_base;
//    __extension__ unsigned long long int gs_base;

    return mapResult;
}

bool XUnixDebugger::_setStep(XProcess::HANDLEID handleID)
{
    bool bResult=true;

    ptrace(PTRACE_SINGLESTEP,handleID.nID,0,0);

    int wait_status;
    waitpid(handleID.nID,&wait_status,0);
    // TODO result

    return bResult;
}
