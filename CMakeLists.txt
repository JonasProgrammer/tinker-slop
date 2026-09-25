cmake_minimum_required(VERSION 4.4)
project(tinker_slop)

include(CTest)

set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(JSTS_BOOST_MIN 1.91.0)

option(JSTS_BOOST_USE_STATIC_LIBS "Prefer static Boost libraries" OFF)
option(JSTS_BUILD_JGS245_PORTS "Build the jgs245-ports tool" ON)

if(JSTS_BUILD_JGS245_PORTS)
    add_subdirectory(jgs245-ports)
endif()
