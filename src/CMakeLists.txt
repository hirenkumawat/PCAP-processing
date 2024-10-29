cmake_minimum_required(VERSION 3.10)
project(DOCA_SAMPLE VERSION 0.1.0 LANGUAGES C CXX)
# Read version number from file
file(READ "/opt/mellanox/doca/applications/VERSION" VERSION_CONTENT)
string(STRIP "${VERSION_CONTENT}" PROJECT_VERSION)
set(CMAKE_C_FLAGS_DEBUG "-D DOCA_ALLOW_EXPERIMENTAL_API -Wno-missing-braces")
set(CMAKE_CXX_FLAGS_DEBUG "-D DOCA_ALLOW_EXPERIMENTAL_API -Wno-missing-braces")
set(SAMPLE_NAME "regex_scan")
# Define source files
set(SAMPLE_SRCS
    ${SAMPLE_NAME}_sample.c
    ${SAMPLE_NAME}_main.c
    ../../common.c
    ../../../applications/common/src/utils.c
)
# Include directories
include_directories(
    /opt/mellanox/doca/include # Added this one myself, ninja wasn't finding some headers without it
    # ../.. /opt/mellanox/doca/
    # ../../..
    /opt/mellanox/doca/applications/common/src
)
# Find dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(DOCA REQUIRED doca)
if (DOCA_FOUND)
        set(DOCA_INCLUDE_DIRS ${DOCA_INCLUDE_DIRS})
        set(DOCA_LIBRARIES ${DOCA_LIBRARIES})
        message(STATUS "DOCA include directories: ${DOCA_INCLUDE_DIRS}")
        message(STATUS "DOCA libraries: ${DOCA_LIBRARIES}")
else()
        message(FATAL_ERROR "DOCA dependency not found")
endif()
set(DOCA_LIBRARY_DIRS "/opt/mellanox/doca/lib/aarch64-linux-gnu")
link_directories(${DOCA_LIBRARY_DIRS})
# Add executable
add_executable(doca_${SAMPLE_NAME} ${SAMPLE_SRCS})
target_include_directories(doca_${SAMPLE_NAME} PRIVATE ${DOCA_INCLUDE_DIRS})
target_link_libraries(doca_${SAMPLE_NAME} ${DOCA_LIBRARIES})
