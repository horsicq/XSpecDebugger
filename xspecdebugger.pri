INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/xabstractdebugger.h

SOURCES += \
    $$PWD/xabstractdebugger.cpp

win32 {
    HEADERS += $$PWD/xwindowsdebugger.h
    SOURCES += $$PWD/xwindowsdebugger.cpp
}

linux {
    HEADERS += $$PWD/xlinuxdebugger.h
    SOURCES += $$PWD/xlinuxdebugger.cpp
}

osx {
    HEADERS += $$PWD/xosxdebugger.h
    SOURCES += $$PWD/xosxdebugger.cpp
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

win32 {
    !contains(XCONFIG, xpe) {
        XCONFIG += xpe
        include($$PWD/../Formats/xpe.pri)
    }
}

linux {
    !contains(XCONFIG, xelf) {
        XCONFIG += xelf
        include($$PWD/../Formats/xelf.pri)
    }
}

osx {
    !contains(XCONFIG, xmach) {
        XCONFIG += xmach
        include($$PWD/../Formats/xmach.pri)
    }
}
