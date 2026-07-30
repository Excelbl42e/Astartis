add_library(unlock_protocol OBJECT
    unlock_protocol.cpp
)

target_include_directories(unlock_protocol PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)

target_compile_definitions(unlock_protocol PUBLIC
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
