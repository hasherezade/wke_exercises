cmake_minimum_required (VERSION 2.8)
project (WKE_stackov)

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

set (srcs
    main.cpp
)

set (hdrs
    payload.h
)

add_executable (WKE_stackov ${hdrs} ${srcs})