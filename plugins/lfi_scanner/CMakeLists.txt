cmake_minimum_required(VERSION 3.22)
project(lfi_scanner)

cmake_policy(SET CMP0167 NEW)
find_package(Boost 1.71 REQUIRED CONFIG COMPONENTS system)
find_package(OpenSSL REQUIRED)
find_package(uriparser REQUIRED)

add_library(lfi_scanner SHARED lfi_scanner.cpp)

target_include_directories(lfi_scanner PRIVATE ${CMAKE_SOURCE_DIR}/spectre-d/include)

if(TARGET Boost::boost)
    target_link_libraries(lfi_scanner PRIVATE nlohmann_json::nlohmann_json Boost::boost Boost::system OpenSSL::SSL OpenSSL::Crypto spectre_core uriparser::uriparser)
else()
    target_include_directories(lfi_scanner PRIVATE ${Boost_INCLUDE_DIRS})
    target_link_libraries(lfi_scanner PRIVATE nlohmann_json::nlohmann_json ${Boost_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto spectre_core uriparser::uriparser)
endif()

set_target_properties(lfi_scanner PROPERTIES PREFIX "" INSTALL_RPATH "$ORIGIN/../lib" BUILD_WITH_INSTALL_RPATH TRUE)

install(TARGETS lfi_scanner
    LIBRARY DESTINATION plugins
) 