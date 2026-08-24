INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/xabstractdebugger.h \
    $$PWD/xdebuggerconsole.h

SOURCES += \
    $$PWD/xabstractdebugger.cpp \
    $$PWD/xdebuggerconsole.cpp

win32 {
    HEADERS += $$PWD/xwindowsdebugger.h
    SOURCES += $$PWD/xwindowsdebugger.cpp

    !contains(XCONFIG, xpe) {
        XCONFIG += xpe
        include($$PWD/../Formats/exec/xpe.pri)
    }
}

linux {
    HEADERS += \
        $$PWD/xunixdebugger.h \
        $$PWD/xlinuxdebugger.h

    SOURCES += \
        $$PWD/xunixdebugger.cpp \
        $$PWD/xlinuxdebugger.cpp

    !contains(XCONFIG, xelf) {
        XCONFIG += xelf
        include($$PWD/../Formats/exec/xelf.pri)
    }
}

osx {
    XOSXDEBUGGER_MIG_DIR = $$OUT_PWD/xosxdebugger_mig
    XOSXDEBUGGER_MIG_DEFS = $$PWD/xosxdebugger_mach_exc.defs
    xosxdebugger_mig.input = XOSXDEBUGGER_MIG_DEFS
    xosxdebugger_mig.output = $$XOSXDEBUGGER_MIG_DIR/mach_excServer.c
    xosxdebugger_mig.commands = mkdir -p $$shell_quote($$XOSXDEBUGGER_MIG_DIR) && \
        xcrun --sdk macosx mig \
        -header $$shell_quote($$XOSXDEBUGGER_MIG_DIR/mach_exc.h) \
        -server $$shell_quote($$XOSXDEBUGGER_MIG_DIR/mach_excServer.c) \
        -user $$shell_quote($$XOSXDEBUGGER_MIG_DIR/mach_excUser.c) \
        ${QMAKE_FILE_IN}
    xosxdebugger_mig.variable_out = SOURCES
    xosxdebugger_mig.CONFIG += target_predeps
    QMAKE_EXTRA_COMPILERS += xosxdebugger_mig

    HEADERS += \
        $$PWD/xunixdebugger.h \
        $$PWD/xosxdebugger.h

    SOURCES += \
        $$PWD/xunixdebugger.cpp \
        $$PWD/xosxdebugger.cpp

    !contains(XCONFIG, xmach) {
        XCONFIG += xmach
        include($$PWD/../Formats/exec/xmach.pri)
    }
}

!contains(XCONFIG, xprocess) {
    XCONFIG += xprocess
    include($$PWD/../XProcess/xprocess.pri)
}

!contains(XCONFIG, xcapstone) {
    XCONFIG += xcapstone
    include($$PWD/../XCapstone/xcapstone.pri)
}

!contains(XCONFIG, xbinary) {
    XCONFIG += xbinary
    include($$PWD/../Formats/xbinary.pri)
}

!contains(XCONFIG, xinfodb) {
    XCONFIG += xinfodb
    include($$PWD/../XInfoDB/xinfodb.pri)
}

!contains(XCONFIG, xoptions) {
    XCONFIG += xoptions
    include($$PWD/../XOptions/xoptions.pri)
}

DISTFILES += \
    $$PWD/LICENSE \
    $$PWD/README.md \
    $$PWD/xosxdebugger_mach_exc.defs
