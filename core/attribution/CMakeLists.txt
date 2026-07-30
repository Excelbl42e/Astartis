add_library(attribution OBJECT
    attribution_report.cpp
)

target_include_directories(attribution PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(attribution PUBLIC
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
