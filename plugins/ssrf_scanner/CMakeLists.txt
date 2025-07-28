cmake_minimum_required(VERSION 3.22)
project(ssrf_scanner)

cmake_policy(SET CMP0167 NEW)
find_package(Boost 1.71 REQUIRED CONFIG COMPONENTS system)
find_package(OpenSSL REQUIRED)

add_library(ssrf_scanner SHARED ssrf_scanner.cpp)

target_link_libraries(ssrf_scanner PRIVATE spectre_core cpr::cpr)

set_target_properties(ssrf_scanner PROPERTIES PREFIX "" INSTALL_RPATH "$ORIGIN/../lib" BUILD_WITH_INSTALL_RPATH TRUE)

install(TARGETS ssrf_scanner
    LIBRARY DESTINATION plugins
) 