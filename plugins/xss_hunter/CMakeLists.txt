add_library(xss_hunter SHARED xss_hunter.cpp)
target_link_libraries(xss_hunter PRIVATE spectre_core)
set_target_properties(xss_hunter PROPERTIES PREFIX "")
install(TARGETS xss_hunter DESTINATION plugins) 