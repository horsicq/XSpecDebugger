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

!contains(XCONFIG, xpe) {
    XCONFIG += xpe
    include($$PWD/../Formats/xpe.pri)
}

!contains(XCONFIG, xelf) {
    XCONFIG += xelf
    include($$PWD/../Formats/xelf.pri)
}
