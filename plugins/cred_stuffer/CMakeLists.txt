cmake_minimum_required(VERSION 3.22)
project(cred_stuffer)

cmake_policy(SET CMP0167 NEW)
find_package(Boost 1.71 REQUIRED CONFIG COMPONENTS system)
find_package(OpenSSL REQUIRED)

add_library(cred_stuffer SHARED cred_stuffer.cpp)

target_include_directories(cred_stuffer PRIVATE ${CMAKE_SOURCE_DIR}/spectre-d/include)

if(TARGET Boost::boost)
    target_link_libraries(cred_stuffer PRIVATE nlohmann_json::nlohmann_json Boost::boost Boost::system OpenSSL::SSL OpenSSL::Crypto spectre_core)
else()
    target_include_directories(cred_stuffer PRIVATE ${Boost_INCLUDE_DIRS})
    target_link_libraries(cred_stuffer PRIVATE nlohmann_json::nlohmann_json ${Boost_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto spectre_core)
endif()

set_target_properties(cred_stuffer PROPERTIES PREFIX "" INSTALL_RPATH "$ORIGIN/../lib" BUILD_WITH_INSTALL_RPATH TRUE)

install(TARGETS cred_stuffer
    LIBRARY DESTINATION plugins
) 