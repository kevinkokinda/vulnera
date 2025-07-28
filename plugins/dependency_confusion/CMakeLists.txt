cmake_minimum_required(VERSION 3.10)
project(dependency_confusion)

add_library(dependency_confusion SHARED dependency_confusion.cpp)

target_link_libraries(dependency_confusion PRIVATE spectre_core)

set_target_properties(dependency_confusion PROPERTIES
    PREFIX ""
    SUFFIX ".so"
)

install(TARGETS dependency_confusion
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/plugins
)

set_target_properties(dependency_confusion PROPERTIES
    INSTALL_RPATH "$ORIGIN/../lib"
) 