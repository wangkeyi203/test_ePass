cmake_minimum_required(VERSION 3.4)
project(test_ePass)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ")

set(SOURCE_FILES main.cpp pam_test.cpp pam_test.h skf_test.h SKFAPI.h test.cpp)
add_executable(test_ePass ${SOURCE_FILES})