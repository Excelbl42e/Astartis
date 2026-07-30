add_library(quarantine OBJECT
    quarantine.cpp
)

target_include_directories(quarantine PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)

target_compile_definitions(quarantine PUBLIC
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

# SHA-256 via OpenSSL; ws2_32 pulled in transitively but listed for clarity
target_link_libraries(quarantine OpenSSL::Crypto ws2_32)
