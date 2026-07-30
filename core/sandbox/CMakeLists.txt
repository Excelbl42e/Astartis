add_library(sandbox OBJECT
    sandbox.cpp
)

target_include_directories(sandbox PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(sandbox PUBLIC
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
