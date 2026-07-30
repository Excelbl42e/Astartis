add_library(threat_level OBJECT
    threat_level.cpp
)

target_include_directories(threat_level PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(threat_level PUBLIC
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
