cmake_minimum_required(VERSION 3.15)

# ============================================================
# packet_sensor — Step 5 Npcap entropy detection module
# ============================================================

set(NPCAP_SDK_DIR "C:/npcap-sdk" CACHE PATH "Path to Npcap SDK root")

# Validate SDK presence at configure time to give a clear error.
if(NOT EXISTS "${NPCAP_SDK_DIR}/Include/pcap.h")
    message(FATAL_ERROR
        "Npcap SDK not found at ${NPCAP_SDK_DIR}.\n"
        "Set -DNPCAP_SDK_DIR=<path> to the extracted SDK root.\n"
        "Download from https://npcap.com/#download")
endif()

add_library(packet_sensor OBJECT
    packet_sensor.cpp
)

target_include_directories(packet_sensor PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${NPCAP_SDK_DIR}/Include
)

# Link against the x64 import library so the linker resolves pcap symbols.
# wpcap.dll is provided at runtime by the Npcap install.
target_link_libraries(packet_sensor PUBLIC
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    "${NPCAP_SDK_DIR}/Lib/x64/Packet.lib"
    ws2_32      # Winsock2 — required by pcap.h on Windows
    iphlpapi    # needed by some Npcap paths
)

# HAVE_REMOTE exposes the full WinPcap-compat API surface on Windows.
# NOMINMAX prevents the Windows.h min/max macros from clashing with std::min/max.
target_compile_definitions(packet_sensor PUBLIC
    HAVE_REMOTE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
