/* Copyright (c) 2020-2023 hors<horsicq@gmail.com>
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
#include "xabstractdebugger.h"

XAbstractDebugger::XAbstractDebugger(QObject *pParent, XInfoDB *pXInfoDB) : QObject(pParent)
{
    g_handle = 0;
    g_bIsDebugActive = false;
    g_pXInfoDB = pXInfoDB;
}

void XAbstractDebugger::setXInfoDB(XInfoDB *pXInfoDB)
{
    g_pXInfoDB = pXInfoDB;
}

XInfoDB *XAbstractDebugger::getXInfoDB()
{
    return g_pXInfoDB;
}

bool XAbstractDebugger::run()
{
#ifdef QT_DEBUG
    qDebug("TODO XAbstractDebugger::run");
#endif

    return false;
}

bool XAbstractDebugger::stop()
{
#ifdef QT_DEBUG
    qDebug("TODO XAbstractDebugger::stop");
#endif

    return false;
}

void XAbstractDebugger::cleanUp()
{
    XCapstone::closeHandle(&g_handle);
}

void XAbstractDebugger::setDisasmMode(XBinary::DM disasmMode)
{
    XCapstone::openHandle(disasmMode, &g_handle, true);
}

void XAbstractDebugger::setTraceFileName(QString sTraceFileName)
{
    g_sTraceFileName = sTraceFileName;
}

void XAbstractDebugger::clearTraceFile()
{
    if (g_sTraceFileName != "") {
        XBinary::clearFile(g_sTraceFileName);
    }
}

void XAbstractDebugger::writeToTraceFile(QString sString)
{
    if (g_sTraceFileName != "") {
        XBinary::appendToFile(g_sTraceFileName, sString);
    }
}

void XAbstractDebugger::setOptions(XAbstractDebugger::OPTIONS options)
{
    g_options = options;
}

XAbstractDebugger::OPTIONS *XAbstractDebugger::getOptions()
{
    return &g_options;
}

void XAbstractDebugger::_messageString(XAbstractDebugger::MT messageType, QString sText)
{
#ifdef QT_DEBUG
    qDebug("%s", sText.toLatin1().data());
#endif
    emit messageString(messageType, sText);
}

qint64 XAbstractDebugger::getFunctionAddress(QString sFunctionName)
{
    qint64 nResult = -1;

    QString sLibrary = sFunctionName.section("#", 0, 0);
    QString sFunction = sFunctionName.section("#", 1, 1);
    //    qint32 nOrdinal=sFunction.toULongLong();

    XInfoDB::SHAREDOBJECT_INFO sharedObjectInfo = getXInfoDB()->findSharedInfoByName(sLibrary);

    if (sharedObjectInfo.sName != "") {
        // TODO Load symbols
        //        QList<XBinary::SYMBOL_RECORD> listSymbols=loadSymbols(sharedObjectInfo.sFileName,sharedObjectInfo.nImageBase); // TODO Cache !!!

        //        XBinary::SYMBOL_RECORD functionAddress={};

        //        if(nOrdinal)
        //        {
        //            functionAddress=XBinary::findSymbolByOrdinal(&listSymbols,nOrdinal);
        //        }
        //        else
        //        {
        //            functionAddress=XBinary::findSymbolByName(&listSymbols,sFunction);
        //        }

        //        if(functionAddress.nAddress)
        //        {
        //            nResult=functionAddress.nAddress;
        //        }
    }

    return nResult;
}

QString XAbstractDebugger::getAddressSymbolString(quint64 nAddress)
{
    QString sResult;

    XInfoDB::SHAREDOBJECT_INFO sharedObjectInfo = getXInfoDB()->findSharedInfoByAddress(nAddress);

    if (sharedObjectInfo.sName != "") {
        sResult += sharedObjectInfo.sName + ".";

        // TODO
        //        QList<XBinary::SYMBOL_RECORD> listSymbols=loadSymbols(sharedObjectInfo.sFileName,sharedObjectInfo.nImageBase); // TODO Cache

        //        XBinary::SYMBOL_RECORD functionAddress=XBinary::findSymbolByAddress(&listSymbols,nAddress);

        //        if(functionAddress.nAddress)
        //        {
        //            // mb TODO ordinals
        //            sResult+=functionAddress.sName;
        //        }
        //        else
        //        {
        //            sResult+=XBinary::valueToHex(nAddress);
        //        }
    } else {
        sResult = XBinary::valueToHex(nAddress);
    }

    return sResult;
}

qint64 XAbstractDebugger::getRetAddress(XProcess::HANDLEID handleID)
{
    qint64 nResult = 0;

#ifdef Q_OS_WIN
    CONTEXT context = {0};
    context.ContextFlags = CONTEXT_CONTROL;

    if (GetThreadContext(handleID.hHandle, &context)) {
#ifdef Q_PROCESSOR_X86_32
        quint64 nSP = (quint32)(context.Esp);
        nResult = getXInfoDB()->read_uint32((quint32)nSP);
#endif
#ifdef Q_PROCESSOR_X86_64
        quint64 nSP = (quint64)(context.Rsp);
        nResult = getXInfoDB()->read_uint64((quint64)nSP);
#endif
    }
#endif

    return nResult;
}

XCapstone::DISASM_STRUCT XAbstractDebugger::disasm(quint64 nAddress)
{
    QByteArray baData = getXInfoDB()->read_array(nAddress, 15);

    return XCapstone::disasm(g_handle, nAddress, baData.data(), baData.size());
}

bool XAbstractDebugger::isUserCode(quint64 nAddress)
{
    bool bResult = false;

    if ((getXInfoDB()->getProcessInfo()->nImageBase <= nAddress) &&
        (getXInfoDB()->getProcessInfo()->nImageBase + getXInfoDB()->getProcessInfo()->nImageSize > nAddress)) {
        bResult = true;
    }

    return bResult;
}

bool XAbstractDebugger::bIsSystemCode(quint64 nAddress)
{
    return getXInfoDB()->findSharedInfoByAddress(nAddress).nImageBase;
}

bool XAbstractDebugger::dumpToFile(QString sFileName)
{
    bool bResult = false;

    //    XProcessDevice processDevice(this); // TODO -> XProcess

    //    if(processDevice.openHandle(getXInfoDB()->getProcessInfo()->hProcess,getXInfoDB()->getProcessInfo()->nImageBase,getXInfoDB()->getProcessInfo()->nImageSize,QIODevice::ReadOnly))
    //    {
    //        XBinary binary(&processDevice,true,getXInfoDB()->getProcessInfo()->nImageBase);

    //        bResult=binary.dumpToFile(sFileName,(qint64)0,(qint64)-1);
    //    }

    return bResult;
}

bool XAbstractDebugger::stepIntoByHandle(X_HANDLE hThread, XInfoDB::BPI bpInfo)
{
    Q_UNUSED(hThread)
#ifdef QT_DEBUG
    qDebug("TODO XAbstractDebugger::stepIntoByHandle");
#endif

    return false;
}

bool XAbstractDebugger::stepIntoById(X_ID nThreadId, XInfoDB::BPI bpInfo)
{
    Q_UNUSED(nThreadId)
#ifdef QT_DEBUG
    qDebug("TODO XAbstractDebugger::stepIntoById");
#endif

    return false;
}

bool XAbstractDebugger::stepOverByHandle(X_HANDLE hThread, XInfoDB::BPI bpInfo)
{
    Q_UNUSED(hThread)
#ifdef QT_DEBUG
    qDebug("TODO XAbstractDebugger::stepIntoByHandle");
#endif

    return false;
}

bool XAbstractDebugger::stepOverById(X_ID nThreadId, XInfoDB::BPI bpInfo)
{
    Q_UNUSED(nThreadId)
#ifdef QT_DEBUG
    qDebug("TODO XAbstractDebugger::stepIntoById");
#endif

    return false;
}

bool XAbstractDebugger::stepInto()
{
#ifdef QT_DEBUG
    qDebug("TODO XAbstractDebugger::stepInto");
#endif

    return false;
}

bool XAbstractDebugger::stepOver()
{
#ifdef QT_DEBUG
    qDebug("TODO XAbstractDebugger::stepOver");
#endif

    return false;
}

void XAbstractDebugger::wait()
{
    while (isDebugActive()) {
//        QThread::msleep(100);
        _waitEvents();
    }
}

void XAbstractDebugger::_waitEvents()
{
    QTimer timer;
    timer.setSingleShot(true);

    QEventLoop loop;
    connect(&timer, SIGNAL(timeout()), &loop, SLOT(quit()));
    timer.start(100);  // use miliseconds
    loop.exec();
}

void XAbstractDebugger::_eventBreakPoint(XInfoDB::BREAKPOINT_INFO *pBreakPointInfo)
{
    getXInfoDB()->setCurrentThreadById(pBreakPointInfo->nThreadID);
#ifdef Q_OS_WIN
    getXInfoDB()->setCurrentThreadByHandle(pBreakPointInfo->hThread);
#endif
    emit eventBreakPoint(pBreakPointInfo);
}

char *XAbstractDebugger::allocateAnsiStringMemory(QString sFileName)
{
    char *pResult = nullptr;

    qint32 nSize = sFileName.length();

    pResult = new char[nSize + 1];
    XBinary::_zeroMemory(pResult, nSize + 1);
    XBinary::_copyMemory(pResult, sFileName.toLatin1().data(), nSize);

    return pResult;
}

void XAbstractDebugger::setDebugActive(bool bState)
{
    g_bIsDebugActive = bState;
}

bool XAbstractDebugger::isDebugActive()
{
    return g_bIsDebugActive;
}

void XAbstractDebugger::process()
{
#ifdef QT_DEBUG
    qDebug("Current thread: %d", QThread::currentThreadId());
#endif

    load();
}

void XAbstractDebugger::testSlot(X_ID nThreadId)
{
#ifdef QT_DEBUG
    qDebug("testSlot: Current thread: %d", QThread::currentThreadId());
#endif
#ifdef Q_OS_LINUX
    user_regs_struct regs = {};
    errno = 0;
    ptrace(PTRACE_GETREGS, nThreadId, nullptr, &regs);
    qDebug("ptrace failed: %s", strerror(errno));
#endif
}
