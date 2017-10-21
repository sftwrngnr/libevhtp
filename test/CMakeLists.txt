cmake_minimum_required(VERSION 3.9)

include_directories (${TEST_SOURCE_DIR}/include)

set(SOURCES evhtp_test.c ${TEST_SOURCE_DIR}/include/test_evhtp.h ${PROJECT_SOURCE_DIR}/include/evhtp/evhtp.h)

add_executable(evhtp_test evhtp_test.c )

