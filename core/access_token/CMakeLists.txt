add_library(access_token OBJECT
    access_token.cpp
)

target_include_directories(access_token PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(access_token PUBLIC
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
