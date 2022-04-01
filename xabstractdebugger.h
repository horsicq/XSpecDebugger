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
#ifndef XABSTRACTDEBUGGER_H
#define XABSTRACTDEBUGGER_H

#include "xbinary.h"
#include "xcapstone.h"
#include "xprocess.h"
#include "xprocessdevice.h"

// TODO Attach
// TODO Detach
class XAbstractDebugger : public QObject
{
    Q_OBJECT
    
public:
    struct OPTIONS
    {
        QString sFileName;
        QString sDirectory;
        QString sArguments;
        bool bShowConsole;
        bool bBreakpointOnProgramEntryPoint;
        bool bBreakPointOnDLLMain;
        bool bBreakPointOnTLSFunction;      // For Windows TLS
    };

    struct REG_OPTIONS
    {
        bool bGeneral;
        bool bIP;
        bool bFlags;
        bool bSegments;
        bool bDebug;
        bool bFloat;
        bool bXMM;
    };

    enum MT
    {
        MT_UNKNOWN=0,
        MT_INFO,
        MT_WARNING,
        MT_ERROR
    };

    enum BPT
    {
        BPT_UNKNOWN=0,
        BPT_CODE_SOFTWARE,    // for X86 0xCC Check for ARM
        BPT_CODE_HARDWARE
    };

    enum BPI
    {
        BPI_UNKNOWN=0,
        BPI_USER,
        BPI_PROCESSENTRYPOINT,
        BPI_PROGRAMENTRYPOINT,
        BPI_TLSFUNCTION, // TODO
        BPI_FUNCTIONENTER,
        BPI_FUNCTIONLEAVE,
        BPI_STEP,
        BPI_STEPINTO,
        BPI_STEPOVER
    };

    struct BREAKPOINT
    {
        quint64 nAddress;
        qint64 nSize;
        qint32 nCount;
        BPT bpType;
        BPI bpInfo;
        QString sInfo;
        qint32 nOrigDataSize;
        char origData[4]; // TODO consts check
        QString sGUID;
    };

    struct THREAD_INFO
    {
        qint64 nThreadID;
        qint64 nThreadLocalBase;
        quint64 nStartAddress;
        void *hThread;
    };

    struct EXITTHREAD_INFO
    {
        qint64 nThreadID;
        qint64 nExitCode;
    };

    struct PROCESS_INFO
    {
        qint64 nProcessID;
        qint64 nThreadID;
        QString sFileName;
        quint64 nImageBase;
        quint64 nImageSize;
        quint64 nStartAddress;
        quint64 nThreadLocalBase;
        void *hProcessMemoryIO;
        void *hProcessMemoryQuery;
        void *hMainThread;
    };

    struct EXITPROCESS_INFO
    {
        qint64 nProcessID;
        qint64 nThreadID;
        qint64 nExitCode;
    };

    struct SHAREDOBJECT_INFO // DLL on Windows
    {
        QString sName;
        QString sFileName;
        quint64 nImageBase;
        quint64 nImageSize;
    };

    struct DEBUGSTRING_INFO
    {
        qint64 nThreadID;
        QString sDebugString;
    };

    struct BREAKPOINT_INFO
    {
        quint64 nAddress;
        BPT bpType;
        BPI bpInfo;
        QString sInfo;
        qint64 nProcessID;
        void *pHProcessMemoryIO;
        void *pHProcessMemoryQuery;
        qint64 nThreadID;
        void *pHThread;
    };

    struct PROCESSENTRY_INFO
    {
        quint64 nAddress;
    };

    struct FUNCTIONHOOK_INFO
    {
        QString sName;
        quint64 nAddress;
    };

    struct FUNCTION_INFO
    {
        QString sName;
        quint64 nAddress;
        qint64 nRetAddress;
        quint64 nParameter0;
        quint64 nParameter1;
        quint64 nParameter2;
        quint64 nParameter3;
        quint64 nParameter4;
        quint64 nParameter5;
        quint64 nParameter6;
        quint64 nParameter7;
        quint64 nParameter8;
        quint64 nParameter9;
    };

    enum DBT
    {
        DBT_UNKNOWN=0,
        DBT_SETSOFTWAREBREAKPOINT,
        DBT_REMOVESOFTWAREBREAKPOINT
    };

    struct DEBUG_ACTION
    {
        DBT type;
        QVariant var[4];
    };

    struct REGISTERS
    {
    #ifdef Q_PROCESSOR_X86_32
        quint32 EAX;
        quint32 ECX;
        quint32 EDX;
        quint32 EBX;
        quint32 ESP;
        quint32 EBP;
        quint32 ESI;
        quint32 EDI;
        quint32 EIP;
    #endif
    #ifdef Q_PROCESSOR_X86_64
        quint64 RAX;
        quint64 RCX;
        quint64 RDX;
        quint64 RBX;
        quint64 RSP;
        quint64 RBP;
        quint64 RSI;
        quint64 RDI;
        quint64 R8;
        quint64 R9;
        quint64 R10;
        quint64 R11;
        quint64 R12;
        quint64 R13;
        quint64 R14;
        quint64 R15;
        quint64 RIP;
    #endif
    #ifdef Q_PROCESSOR_X86
        quint32 EFLAGS;
        quint16 CS;
        quint16 DS;
        quint16 ES;
        quint16 FS;
        quint16 GS;
        quint16 SS;
    #endif
    #ifdef Q_PROCESSOR_X86_32
        quint32 DR[8];
    #endif
    #ifdef Q_PROCESSOR_X86_64
        quint64 DR[8];
    #endif
    };

    explicit XAbstractDebugger(QObject *pParent=nullptr);
    virtual bool load()=0;
    virtual bool stop();
    virtual void cleanUp();
    virtual QString getArch()=0;
    virtual XBinary::MODE getMode()=0;

    void setDisasmMode(XBinary::DM disasmMode);
    void setTraceFileName(QString sTraceFileName);
    void clearTraceFile();
    void writeToTraceFile(QString sString);

    void setOptions(OPTIONS options);
    OPTIONS *getOptions();

    void setProcessInfo(PROCESS_INFO *pProcessInfo);
    PROCESS_INFO *getProcessInfo();

    void _messageString(MT messageType,QString sText);

    void addSharedObjectInfo(SHAREDOBJECT_INFO *pSharedObjectInfo);
    void removeSharedObjectInfo(SHAREDOBJECT_INFO *pSharedObjectInfo);

    void addThreadInfo(THREAD_INFO *pThreadInfo);
    void removeThreadInfo(THREAD_INFO *pThreadInfo);

    void _addBreakpoint(BREAKPOINT *pBreakpoint);
    void _removeBreakpoint(BREAKPOINT *pBreakpoint);

    bool setBP(quint64 nAddress,BPT bpType=BPT_CODE_SOFTWARE,BPI bpInfo=BPI_UNKNOWN,qint32 nCount=-1,QString sInfo=QString(),QString sGUID=QString());
    bool removeBP(quint64 nAddress,BPT bpType);

    bool setSoftwareBreakpoint(quint64 nAddress,qint32 nCount=-1,QString sInfo=QString());
    bool removeSoftwareBreakpoint(quint64 nAddress);
    bool isSoftwareBreakpointPresent(quint64 nAddress);

    bool setFunctionHook(QString sFunctionName);
    bool removeFunctionHook(QString sFunctionName);

    qint64 getFunctionAddress(QString sFunctionName);
    QString getAddressSymbolString(quint64 nAddress);

    virtual QList<XBinary::SYMBOL_RECORD> loadSymbols(QString sFileName,qint64 nModuleAddress);

    QList<XBinary::MEMORY_REPLACE> getMemoryReplaces();

    QMap<qint64,SHAREDOBJECT_INFO> *getSharedObjectInfos();
    QMap<qint64,THREAD_INFO> *getThreadInfos();
    QMap<qint64,BREAKPOINT> *getSoftwareBreakpoints();
    QMap<qint64,BREAKPOINT> *getHardwareBreakpoints();
    QMap<QString,FUNCTIONHOOK_INFO> *getFunctionHookInfos();

    SHAREDOBJECT_INFO findSharedInfoByName(QString sName);
    SHAREDOBJECT_INFO findSharedInfoByAddress(quint64 nAddress);

    quint8 read_uint8(quint64 nAddress);
    quint16 read_uint16(quint64 nAddress);
    quint32 read_uint32(quint64 nAddress);
    quint64 read_uint64(quint64 nAddress);
    void write_uint8(quint64 nAddress,quint8 nValue);
    void write_uint16(quint64 nAddress,quint16 nValue);
    void write_uint32(quint64 nAddress,quint32 nValue);
    void write_uint64(quint64 nAddress,quint64 nValue);
    qint64 read_array(quint64 nAddress,char *pData,quint64 nSize);
    qint64 write_array(quint64 nAddress,char *pData,quint64 nSize);
    QByteArray read_array(quint64 nAddress,quint64 nSize);
    QString read_ansiString(quint64 nAddress,quint64 nMaxSize=256);
    QString read_unicodeString(quint64 nAddress,quint64 nMaxSize=256);

    bool suspendThread(XProcess::HANDLEID handleID);
    bool resumeThread(XProcess::HANDLEID handleID);
    bool suspendOtherThreads(XProcess::HANDLEID handleID);
    bool resumeOtherThreads(XProcess::HANDLEID handleID);

    bool setCurrentAddress(XProcess::HANDLEID handleID,quint64 nAddress);
    static qint64 getCurrentAddress(XProcess::HANDLEID handleID);
    virtual bool _setStep(XProcess::HANDLEID handleID);
    bool setSingleStep(XProcess::HANDLEID handleID,QString sInfo="");
    qint64 findAddressByException(qint64 nExeptionAddress);

    virtual REGISTERS getRegisters(XProcess::HANDLEID handleID,REG_OPTIONS regOptions);

    FUNCTION_INFO getFunctionInfo(XProcess::HANDLEID handleID,QString sName);
    qint64 getRetAddress(XProcess::HANDLEID handleID);
    qint64 getStackPointer(XProcess::HANDLEID handleID);

    XCapstone::DISASM_STRUCT disasm(quint64 nAddress);

    bool isUserCode(quint64 nAddress);
    bool bIsSystemCode(quint64 nAddress);

    bool dumpToFile(QString sFileName);

    static QString debugActionToString(DEBUG_ACTION debugAction);
    static DEBUG_ACTION stringToDebugAction(QString sString);

    bool stepInto(XProcess::HANDLEID handleID);
    bool stepOver(XProcess::HANDLEID handleID);

    char *allocateAnsiStringMemory(QString sFileName);

    void setDebugActive(bool bState);
    bool isDebugActive();

public slots:
    void process();

signals:
    void messageString(XAbstractDebugger::MT messageType,QString sText);

    void eventCreateProcess(XAbstractDebugger::PROCESS_INFO *pProcessInfo);
    void eventExitProcess(XAbstractDebugger::EXITPROCESS_INFO *pExitProcessInfo);
    void eventCreateThread(XAbstractDebugger::THREAD_INFO *pThreadInfo);
    void eventExitThread(XAbstractDebugger::EXITTHREAD_INFO *pExitThreadInfo);
    void eventLoadSharedObject(XAbstractDebugger::SHAREDOBJECT_INFO *pSharedObjectInfo);
    void eventUnloadSharedObject(XAbstractDebugger::SHAREDOBJECT_INFO *pSharedObjectInfo);
    void eventDebugString(XAbstractDebugger::DEBUGSTRING_INFO *pDebugString);
    void eventBreakPoint(XAbstractDebugger::BREAKPOINT_INFO *pBreakPointInfo);
    void eventProcessEntryPoint(XAbstractDebugger::BREAKPOINT_INFO *pBreakPointInfo); // Check windows set on startAddress
    void eventProgramEntryPoint(XAbstractDebugger::BREAKPOINT_INFO *pBreakPointInfo); // If options.bBreakpointOnTargetEntryPoint
    void eventTLSFunction(XAbstractDebugger::BREAKPOINT_INFO *pBreakPointInfo); // TODO
    void eventStep(XAbstractDebugger::BREAKPOINT_INFO *pBreakPointInfo);
    void eventStepInto(XAbstractDebugger::BREAKPOINT_INFO *pBreakPointInfo);
    void eventStepOver(XAbstractDebugger::BREAKPOINT_INFO *pBreakPointInfo);
    void eventFunctionEnter(XAbstractDebugger::FUNCTION_INFO *pFunctionInfo);
    void eventFunctionLeave(XAbstractDebugger::FUNCTION_INFO *pFunctionInfo);

protected:
    QMap<qint64,BREAKPOINT> g_mapThreadSteps; // mb TODO move to private set/get functions

private:
    OPTIONS g_options;
    PROCESS_INFO g_processInfo;
    QMap<qint64,SHAREDOBJECT_INFO> g_mapSharedObjectInfos;
    QMap<qint64,THREAD_INFO> g_mapThreadInfos;
    QMap<qint64,BREAKPOINT> g_mapSoftwareBreakpoints;
    QMap<qint64,BREAKPOINT> g_mapHardwareBreakpoints;
    QMap<QString,FUNCTIONHOOK_INFO> g_mapFunctionHookInfos;
    csh g_handle;
    QString g_sTraceFileName;
    bool g_bIsDebugActive;
};

#endif // XABSTRACTDEBUGGER_H
