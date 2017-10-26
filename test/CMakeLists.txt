cmake_minimum_required(VERSION 3.9)

include_directories (include)

set(SOURCES evhtp_test.c ${TEST_SOURCE_DIR}/include/test_evhtp.h ${PROJECT_SOURCE_DIR}/include/evhtp/evhtp.h)

add_executable(evhtp_test evhtp_test.c )
add_library(libevhtp STATIC IMPORTED)
set_target_properties(libevhtp PROPERTIES 
    IMPORTED_LOCATION ${CMAKE_BINARY_DIR}/libevhtp.a)
TARGET_LINK_LIBRARIES(evhtp_test libevhtp ${LIBEVHTP_EXTERNAL_LIBS} ${SYS_LIBS})

add_test(NAME evhtp_test 
         COMMAND evhtp_test
         WORKING_DIRECTORY ${TEST_SOURCE_DIR})

        
