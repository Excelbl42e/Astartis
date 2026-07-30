add_library(active_response OBJECT
    active_response.cpp
)

target_include_directories(active_response PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(active_response PUBLIC
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
