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
    if(NOT CMAKE_C_COMPILER_LOADED)
        enable_language(C)
    endif()

    find_program(XOSXDEBUGGER_MIG_EXECUTABLE mig)
    if(NOT XOSXDEBUGGER_MIG_EXECUTABLE)
        message(FATAL_ERROR "Cannot locate the Mach Interface Generator (mig)")
    endif()
    execute_process(
        COMMAND xcrun --sdk macosx --show-sdk-path
        OUTPUT_VARIABLE XOSXDEBUGGER_MIG_SYSROOT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    if(NOT XOSXDEBUGGER_MIG_SYSROOT)
        message(FATAL_ERROR "Cannot locate the macOS SDK required by mig")
    endif()

    set(XOSXDEBUGGER_MIG_DIR ${CMAKE_CURRENT_BINARY_DIR}/xosxdebugger_mig)
    file(MAKE_DIRECTORY ${XOSXDEBUGGER_MIG_DIR})
    set(XOSXDEBUGGER_MIG_OUTPUTS
        ${XOSXDEBUGGER_MIG_DIR}/mach_exc.h
        ${XOSXDEBUGGER_MIG_DIR}/mach_excServer.c
        ${XOSXDEBUGGER_MIG_DIR}/mach_excUser.c
    )
    add_custom_command(
        OUTPUT ${XOSXDEBUGGER_MIG_OUTPUTS}
        COMMAND ${XOSXDEBUGGER_MIG_EXECUTABLE} -isysroot ${XOSXDEBUGGER_MIG_SYSROOT} ${CMAKE_CURRENT_LIST_DIR}/xosxdebugger_mach_exc.defs
        WORKING_DIRECTORY ${XOSXDEBUGGER_MIG_DIR}
        DEPENDS ${CMAKE_CURRENT_LIST_DIR}/xosxdebugger_mach_exc.defs
        VERBATIM
    )
    set_source_files_properties(${XOSXDEBUGGER_MIG_OUTPUTS} PROPERTIES GENERATED TRUE)

    list(APPEND XPECDEBUGGER_SOURCES
        ${CMAKE_CURRENT_LIST_DIR}/xunixdebugger.cpp
        ${CMAKE_CURRENT_LIST_DIR}/xunixdebugger.h
        ${CMAKE_CURRENT_LIST_DIR}/xosxdebugger.cpp
        ${CMAKE_CURRENT_LIST_DIR}/xosxdebugger.h
        ${XOSXDEBUGGER_MIG_DIR}/mach_excServer.c
        ${XOSXDEBUGGER_MIG_DIR}/mach_exc.h
    )
endif()
