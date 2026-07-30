add_library(version_store OBJECT
    version_store.cpp
)

target_include_directories(version_store PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(version_store
    OpenSSL::Crypto
)
