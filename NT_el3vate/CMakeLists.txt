project(NT_el3vate)
cmake_minimum_required(VERSION 3.10)

if (Windows)
  set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif ()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)

include_directories(${CMAKE_CURRENT_LIST_DIR}/src)

file(
    GLOB
    NT_el3vate
    src/*.cpp
)

add_executable(NT_el3vate ${NT_el3vate})
target_include_directories(NT_el3vate PUBLIC
                           "${PROJECT_BINARY_DIR}"
                           )