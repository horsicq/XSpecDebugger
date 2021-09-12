INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/xabstractdebugger.h

SOURCES += \
    $$PWD/xabstractdebugger.cpp

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
