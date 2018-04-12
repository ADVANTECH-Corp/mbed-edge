file (GLOB SOURCES ./*.c)

include_directories (${CMAKE_CURRENT_LIST_DIR}/include)

add_executable (pt-example_1520 ${SOURCES})

add_definitions(-DMBED_CONF_MBED_TRACE_ENABLE=1)

target_include_directories (pt-example_1520 PUBLIC ${CMAKE_CURRENT_LIST_DIR})
target_link_libraries (pt-example_1520 pt-client mosquitto)
