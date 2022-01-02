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
//    else if(WEXITSTATUS(nStatus))
//    {
//        qDebug("WEXITSTATUS %x",WEXITSTATUS(nStatus));
//    }
//    else if(WSTOPSIG(nStatus))
//    {
//        qDebug("WSTOPSIG %x",WSTOPSIG(nStatus));
//    }
//    else if(WTERMSIG(nStatus))
//    {
//        qDebug("WTERMSIG %x",WTERMSIG(nStatus));
//    }
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
    else if(WIFCONTINUED(nStatus))
    {
        qDebug("WIFCONTINUED %x",WIFCONTINUED(nStatus));
    }
    // TODO fast events

    qDebug("STATUS: %x",nStatus);
}

void XUnixDebugger::continueThread(qint64 nThreadID)
{
    // TODO
    ptrace(PTRACE_CONT,nThreadID,0,0);

    int wait_status;
    waitpid(nThreadID,&wait_status,0);
    // TODO result
}

QMap<QString, XBinary::XVARIANT> XUnixDebugger::getRegisters(XProcess::HANDLEID handleID, REG_OPTIONS regOptions)
{
    QMap<QString, XBinary::XVARIANT> mapResult;

    user_regs_struct regs={};
//    user_regs_struct regs;
    ptrace(PTRACE_GETREGS,handleID.nID,nullptr,regs);

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


//    __extension__ unsigned long long int r15;
//    __extension__ unsigned long long int r14;
//    __extension__ unsigned long long int r13;
//    __extension__ unsigned long long int r12;
//    __extension__ unsigned long long int rbp;
//    __extension__ unsigned long long int rbx;
//    __extension__ unsigned long long int r11;
//    __extension__ unsigned long long int r10;
//    __extension__ unsigned long long int r9;
//    __extension__ unsigned long long int r8;
//    __extension__ unsigned long long int rax;
//    __extension__ unsigned long long int rcx;
//    __extension__ unsigned long long int rdx;
//    __extension__ unsigned long long int rsi;
//    __extension__ unsigned long long int rdi;
//    __extension__ unsigned long long int orig_rax;
//    __extension__ unsigned long long int rip;
//    __extension__ unsigned long long int cs;
//    __extension__ unsigned long long int eflags;
//    __extension__ unsigned long long int rsp;
//    __extension__ unsigned long long int ss;
//    __extension__ unsigned long long int fs_base;
//    __extension__ unsigned long long int gs_base;
//    __extension__ unsigned long long int ds;
//    __extension__ unsigned long long int es;
//    __extension__ unsigned long long int fs;
//    __extension__ unsigned long long int gs;

    return mapResult;
}
