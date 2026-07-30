add_library(rule_engine OBJECT
    rule_engine.cpp
)

target_include_directories(rule_engine PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(rule_engine PUBLIC
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
