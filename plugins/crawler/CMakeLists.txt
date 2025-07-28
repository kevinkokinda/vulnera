add_library(crawler SHARED crawler.cpp)

find_package(uriparser REQUIRED) # for URL parsing

target_link_libraries(crawler PRIVATE spectre_core cpr::cpr uriparser)

set_target_properties(crawler PROPERTIES PREFIX "" INSTALL_RPATH "$ORIGIN/../lib" BUILD_WITH_INSTALL_RPATH TRUE)

install(TARGETS crawler
    LIBRARY DESTINATION plugins
) 