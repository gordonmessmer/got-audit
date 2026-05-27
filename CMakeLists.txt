cmake_minimum_required(VERSION 3.15)
project(got-audit VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2")

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBELF REQUIRED libelf)

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${LIBELF_INCLUDE_DIRS}
)

add_executable(got-audit
    src/main.cpp
    src/elf_parser.cpp
    src/process_memory.cpp
    src/got_auditor.cpp
    src/report.cpp
)

target_link_libraries(got-audit
    ${LIBELF_LIBRARIES}
)

install(TARGETS got-audit DESTINATION bin)
install(FILES got-audit.1 DESTINATION share/man/man1)

# Enable testing
enable_testing()
add_test(NAME test_suite COMMAND ${CMAKE_SOURCE_DIR}/tests/run_tests.sh)
