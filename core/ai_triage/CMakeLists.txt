add_library(ai_triage OBJECT
    ai_triage.cpp
)

target_include_directories(ai_triage PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}/../../bridge
)

target_compile_definitions(ai_triage PUBLIC
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_link_libraries(ai_triage ws2_32)
