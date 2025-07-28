cmake_minimum_required(VERSION 3.22)
project(git_leaker)

cmake_policy(SET CMP0167 NEW)
find_package(Boost 1.71 REQUIRED CONFIG COMPONENTS system)
find_package(OpenSSL REQUIRED)

add_library(git_leaker SHARED git_leaker.cpp)

target_include_directories(git_leaker PRIVATE ${CMAKE_SOURCE_DIR}/spectre-d/include)

if(TARGET Boost::boost)
    target_link_libraries(git_leaker PRIVATE nlohmann_json::nlohmann_json Boost::boost Boost::system OpenSSL::SSL OpenSSL::Crypto spectre_core cpr::cpr)
else()
    target_include_directories(git_leaker PRIVATE ${Boost_INCLUDE_DIRS})
    target_link_libraries(git_leaker PRIVATE nlohmann_json::nlohmann_json ${Boost_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto spectre_core cpr::cpr)
endif()

set_target_properties(git_leaker PROPERTIES PREFIX "" INSTALL_RPATH "$ORIGIN/../lib" BUILD_WITH_INSTALL_RPATH TRUE)

install(TARGETS git_leaker
    LIBRARY DESTINATION plugins
) 