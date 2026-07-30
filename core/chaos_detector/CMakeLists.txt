add_library(chaos_detector OBJECT
    chaos_detector.cpp
)

target_include_directories(chaos_detector PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(chaos_detector PUBLIC
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
