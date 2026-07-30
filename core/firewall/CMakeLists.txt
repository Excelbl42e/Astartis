add_library(firewall_blocker OBJECT
    firewall_blocker.cpp
)

target_include_directories(firewall_blocker PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)

target_compile_definitions(firewall_blocker PUBLIC
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

# iphlpapi for GetAdaptersInfo / GetNetworkParams; ws2_32 for winsock types
target_link_libraries(firewall_blocker ws2_32 iphlpapi)
