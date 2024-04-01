include_directories(${CMAKE_CURRENT_LIST_DIR})

include(${CMAKE_CURRENT_LIST_DIR}/../XProcess/xprocess.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../XCapstone/xcapstone.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../XInfoDB/xinfodb.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../XOptions/xoptions.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../Formats/xformats.cmake)

set(XPECDEBUGGER_SOURCES
    ${XPROCESS_SOURCES}
    ${XCAPSTONE_SOURCES}
    ${XINFODB_SOURCES}
    ${XOPTIONS_SOURCES}
    ${XFORMATS_SOURCES}
    ${CMAKE_CURRENT_LIST_DIR}/xabstractdebugger.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xabstractdebugger.h
    ${CMAKE_CURRENT_LIST_DIR}/xdebuggerconsole.cpp
    ${CMAKE_CURRENT_LIST_DIR}/xdebuggerconsole.h
)

if(WIN32)
    list(APPEND XPECDEBUGGER_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/xwindowsdebugger.cpp
        ${CMAKE_CURRENT_LIST_DIR}/xwindowsdebugger.h
    )
endif()

if (CMAKE_SYSTEM_NAME MATCHES "Linux")
    list(APPEND XPECDEBUGGER_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/xunixdebugger.cpp
        ${CMAKE_CURRENT_LIST_DIR}/xunixdebugger.h
        ${CMAKE_CURRENT_LIST_DIR}/xlinuxdebugger.cpp
        ${CMAKE_CURRENT_LIST_DIR}/xlinuxdebugger.h
    )
endif()

if(APPLE)
    list(APPEND XPECDEBUGGER_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/xunixdebugger.cpp
        ${CMAKE_CURRENT_LIST_DIR}/xunixdebugger.h
        ${CMAKE_CURRENT_LIST_DIR}/xosxdebugger.cpp
        ${CMAKE_CURRENT_LIST_DIR}/xosxdebugger.h
    )
endif()
