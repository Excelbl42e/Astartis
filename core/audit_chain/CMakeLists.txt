# Audit Chain Module
# SHA-256 Merkle chain for tamper-evident logging

add_library(audit_chain OBJECT
    audit_chain.cpp
)

target_include_directories(audit_chain PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(audit_chain PUBLIC
    OpenSSL::Crypto
)