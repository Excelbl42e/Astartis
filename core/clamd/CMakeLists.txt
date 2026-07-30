add_library(clamd_scanner OBJECT
    clamd_scanner.cpp
)

target_include_directories(clamd_scanner PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(clamd_scanner PUBLIC
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

# Winsock2 is needed for TCP socket calls
target_link_libraries(clamd_scanner ws2_32)
