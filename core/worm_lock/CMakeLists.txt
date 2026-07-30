add_library(worm_lock OBJECT
    worm_lock.cpp
)

target_include_directories(worm_lock PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)
