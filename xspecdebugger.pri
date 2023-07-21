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
        include($$PWD/../Formats/xpe.pri)
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
        include($$PWD/../Formats/xelf.pri)
    }
}

osx {
    HEADERS += \
        $$PWD/xunixdebugger.h \
        $$PWD/xosxdebugger.h

    SOURCES += \
        $$PWD/xunixdebugger.cpp \
        $$PWD/xosxdebugger.cpp

    !contains(XCONFIG, xmach) {
        XCONFIG += xmach
        include($$PWD/../Formats/xmach.pri)
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
    $$PWD/README.md
