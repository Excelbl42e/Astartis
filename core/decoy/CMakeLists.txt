add_library(decoy OBJECT
    decoy.cpp
)

target_include_directories(decoy PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(decoy PUBLIC
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
