cmake_minimum_required (VERSION 2.8)
project (WKE_task1)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

set (srcs
    main.cpp
    util.cpp
)

set (hdrs
    hevd_comm.h
    util.h
)

add_executable (WKE_task1 ${hdrs} ${srcs})