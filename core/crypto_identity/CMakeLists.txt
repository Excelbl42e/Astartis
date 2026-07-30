add_library(crypto_identity OBJECT
    crypto_identity.cpp
)

target_include_directories(crypto_identity PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(crypto_identity
    OpenSSL::Crypto
)
