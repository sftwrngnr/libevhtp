cmake_minimum_required(VERSION 3.9)

include_directories (${TEST_SOURCE_DIR}/src)
add_test(ehtp_test ehtp_test)
add_test(numtoa_test numtoa_test)
add_test(parser_test parser_test)
add_test(thread_test thread_test)

