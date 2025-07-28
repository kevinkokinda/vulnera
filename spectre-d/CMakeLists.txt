cmake_minimum_required(VERSION 3.22)
project(spectre-d LANGUAGES CXX)

cmake_policy(SET CMP0167 NEW)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Boost 1.71 REQUIRED CONFIG COMPONENTS system)
find_package(OpenSSL REQUIRED)

include(FetchContent)
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
    CMAKE_ARGS -DJSON_Install=OFF
)
FetchContent_MakeAvailable(nlohmann_json)

FetchContent_Declare(
    cpr
    GIT_REPOSITORY https://github.com/libcpr/cpr.git
    GIT_TAG 1.9.3
    CMAKE_ARGS -DCPR_INSTALL=OFF -DCURL_DISABLE_INSTALL=ON -DZLIB_NG_INSTALL=OFF
)
FetchContent_MakeAvailable(cpr)


add_library(spectre_core SHARED
    src/plugin_loader.cpp
    src/network_manager.cpp
    src/arweave_client.cpp
    src/tor_proxy.cpp
    src/websocket_server.cpp
    src/proof_queue.cpp
    src/canary_monitor.cpp
)

set_target_properties(spectre_core PROPERTIES POSITION_INDEPENDENT_CODE ON)

if(TARGET Boost::boost)
    target_link_libraries(spectre_core PUBLIC nlohmann_json::nlohmann_json cpr::cpr dl pthread Boost::boost Boost::system OpenSSL::SSL OpenSSL::Crypto)
else()
    target_link_libraries(spectre_core PUBLIC nlohmann_json::nlohmann_json cpr::cpr dl pthread OpenSSL::SSL OpenSSL::Crypto)
    target_include_directories(spectre_core PUBLIC ${Boost_INCLUDE_DIRS})
endif()
target_include_directories(spectre_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_include_directories(spectre_core INTERFACE include)

add_executable(spectre-d
    src/main.cpp
    src/http/http_server.cpp
)

target_link_libraries(spectre-d PRIVATE spectre_core)

install(TARGETS spectre-d DESTINATION bin)
install(TARGETS spectre_core LIBRARY DESTINATION lib)

set_target_properties(spectre-d PROPERTIES
    INSTALL_RPATH "$ORIGIN/../lib"
    BUILD_WITH_INSTALL_RPATH TRUE
)

# Find all plugins in the plugins directory
file(GLOB plugin_libs "plugins/*.so")

target_compile_options(spectre-d PRIVATE
    -Wall
    -Wextra
    -Wpedantic
    -Werror
)

# Plugin targets
add_library(sql_injector SHARED plugins/sql_injector.cpp)
target_link_libraries(sql_injector PRIVATE nlohmann_json::nlohmann_json Boost::boost Boost::system OpenSSL::SSL OpenSSL::Crypto spectre_core)
set_target_properties(sql_injector PROPERTIES PREFIX "" INSTALL_RPATH "$ORIGIN/../lib" BUILD_WITH_INSTALL_RPATH TRUE)

add_library(api_fuzzer SHARED plugins/api_fuzzer.cpp)
target_link_libraries(api_fuzzer PRIVATE nlohmann_json::nlohmann_json Boost::boost Boost::system OpenSSL::SSL OpenSSL::Crypto spectre_core)
set_target_properties(api_fuzzer PROPERTIES PREFIX "" INSTALL_RPATH "$ORIGIN/../lib" BUILD_WITH_INSTALL_RPATH TRUE)

install(TARGETS sql_injector xss_hunter api_fuzzer
    LIBRARY DESTINATION plugins
)

foreach(plugin_source ${plugin_sources})
    string(REPLACE ".cpp" "" plugin_name ${plugin_source})
    string(REPLACE "plugins/" "" plugin_name ${plugin_name})
    add_library(${plugin_name} SHARED ${plugin_source})
    target_link_libraries(${plugin_name} PRIVATE spectre_core cpr::cpr uriparser::uriparser)
    install(TARGETS ${plugin_name} DESTINATION bin/all_plugins)
endforeach()