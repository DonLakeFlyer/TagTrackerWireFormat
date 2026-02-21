cmake_minimum_required(VERSION 3.16)
project(TagTrackerWireFormat LANGUAGES C)

include(CTest)

add_library(tagtracker_wireformat INTERFACE)
target_include_directories(tagtracker_wireformat
    INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

if(BUILD_TESTING)
    add_executable(tagtracker_wireformat_tests
        tests/test_zmq_iq_packet.c
    )
    target_link_libraries(tagtracker_wireformat_tests PRIVATE tagtracker_wireformat)
    add_test(NAME tagtracker_wireformat_tests COMMAND tagtracker_wireformat_tests)
endif()
