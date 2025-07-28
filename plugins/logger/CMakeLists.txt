cmake_minimum_required(VERSION 3.22)
project(logger LANGUAGES CXX)

find_package(Boost 1.71 REQUIRED CONFIG COMPONENTS system)
find_package(OpenSSL REQUIRED)

add_library(logger SHARED logger.cpp)

target_include_directories(logger PRIVATE ${CMAKE_SOURCE_DIR}/spectre-d/include)

if(TARGET Boost::boost)
    target_link_libraries(logger PRIVATE nlohmann_json::nlohmann_json Boost::boost Boost::system OpenSSL::SSL OpenSSL::Crypto spectre_core)
else()
    target_include_directories(logger PRIVATE ${Boost_INCLUDE_DIRS})
    target_link_libraries(logger PRIVATE nlohmann_json::nlohmann_json ${Boost_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto spectre_core)
endif()

set_target_properties(logger PROPERTIES PREFIX "" INSTALL_RPATH "$ORIGIN/../lib" BUILD_WITH_INSTALL_RPATH TRUE)

install(TARGETS logger
    LIBRARY DESTINATION plugins
) 