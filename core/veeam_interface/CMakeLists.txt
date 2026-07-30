add_library(veeam_interface OBJECT
    veeam_interface.cpp
)

target_include_directories(veeam_interface PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)

target_compile_definitions(veeam_interface PUBLIC
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
