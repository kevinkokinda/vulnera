cmake_minimum_required(VERSION 3.22)
project(spectre LANGUAGES CXX)

add_subdirectory(plugins/logger)
add_subdirectory(plugins/cred_stuffer)
add_subdirectory(plugins/git_leaker)
add_subdirectory(plugins/s3_scanner) 
add_subdirectory(plugins/ssrf_scanner) 
add_subdirectory(plugins/lfi_scanner) 
add_subdirectory(plugins/dependency_confusion)
add_subdirectory(plugins/crawler)
add_subdirectory(plugins/xss_hunter)

add_subdirectory(spectre-d)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/plugins)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(GNUInstallDirs)
install(TARGETS spectre-d RUNTIME DESTINATION bin) 