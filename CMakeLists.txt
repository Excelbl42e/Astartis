cmake_minimum_required(VERSION 3.15)
project(Astartis VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler flags
if(MSVC)
    add_compile_options(/W4 /utf-8)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Find OpenSSL for cryptographic operations
find_package(OpenSSL REQUIRED)

# Npcap SDK path — can be overridden with -DNPCAP_SDK_DIR=<path>
set(NPCAP_SDK_DIR "C:/npcap-sdk" CACHE PATH "Path to Npcap SDK root")

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/core)
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${NPCAP_SDK_DIR}/Include)

# Core library components
add_subdirectory(core/audit_chain)
add_subdirectory(core/version_store)
add_subdirectory(core/worm_lock)
add_subdirectory(core/crypto_identity)
add_subdirectory(core/packet_sensor)   # Step 5
add_subdirectory(core/threat_level)    # Step 6
add_subdirectory(core/rule_engine)     # Step 7
add_subdirectory(core/access_token)    # Step 8
add_subdirectory(core/sandbox)         # Step 9
add_subdirectory(core/decoy)           # Step 10
add_subdirectory(core/active_response) # Step 11
add_subdirectory(core/chaos_detector)  # Step 12
add_subdirectory(core/attribution)     # Step 13
add_subdirectory(core/clamd)           # Step 14
add_subdirectory(core/quarantine)      # Step 16 ST-3
add_subdirectory(core/firewall)        # Step 16 ST-4
add_subdirectory(core/unlock_protocol) # Step 17
add_subdirectory(core/ai_triage)       # Step 18
add_subdirectory(core/veeam_interface) # Step 19

# Main Astartis core library (grows as we add more components)
add_library(astartis_core STATIC
    $<TARGET_OBJECTS:audit_chain>
    $<TARGET_OBJECTS:version_store>
    $<TARGET_OBJECTS:worm_lock>
    $<TARGET_OBJECTS:crypto_identity>
    $<TARGET_OBJECTS:packet_sensor>
    $<TARGET_OBJECTS:threat_level>
    $<TARGET_OBJECTS:rule_engine>
    $<TARGET_OBJECTS:access_token>
    $<TARGET_OBJECTS:sandbox>
    $<TARGET_OBJECTS:decoy>
    $<TARGET_OBJECTS:active_response>
    $<TARGET_OBJECTS:chaos_detector>
    $<TARGET_OBJECTS:attribution>
    $<TARGET_OBJECTS:clamd_scanner>
    $<TARGET_OBJECTS:quarantine>
    $<TARGET_OBJECTS:firewall_blocker>
    $<TARGET_OBJECTS:unlock_protocol>
    $<TARGET_OBJECTS:ai_triage>
    $<TARGET_OBJECTS:veeam_interface>
)

target_link_libraries(astartis_core
    OpenSSL::Crypto
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    "${NPCAP_SDK_DIR}/Lib/x64/Packet.lib"
    ws2_32
    iphlpapi
)

target_compile_definitions(astartis_core PUBLIC
    HAVE_REMOTE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

# Enable testing
enable_testing()

# Test executable — Step 1: Audit Chain
add_executable(test_audit_chain
    tests/test_audit_chain.cpp
)

target_link_libraries(test_audit_chain
    astartis_core
    OpenSSL::Crypto
)

add_test(NAME AuditChainTest COMMAND test_audit_chain)

# Test executable — Step 2: Versioning Layer
add_executable(test_version_store
    tests/test_version_store.cpp
)

target_link_libraries(test_version_store
    astartis_core
    OpenSSL::Crypto
)

add_test(NAME VersionStoreTest COMMAND test_version_store)

# Test executable — Step 3: WORM Lockdown
add_executable(test_worm_lock
    tests/test_worm_lock.cpp
)

target_link_libraries(test_worm_lock
    astartis_core
    OpenSSL::Crypto
)

add_test(NAME WormLockTest COMMAND test_worm_lock)

# Test executable — Step 4: Cryptographic Identity
add_executable(test_crypto_identity
    tests/test_crypto_identity.cpp
)

target_link_libraries(test_crypto_identity
    astartis_core
    OpenSSL::Crypto
)

add_test(NAME CryptoIdentityTest COMMAND test_crypto_identity)

# Test executable — Step 5: Packet Sensor / Entropy Detection
add_executable(test_packet_sensor
    tests/test_packet_sensor.cpp
)

target_include_directories(test_packet_sensor PRIVATE
    ${NPCAP_SDK_DIR}/Include
)

target_compile_definitions(test_packet_sensor PRIVATE
    HAVE_REMOTE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_link_libraries(test_packet_sensor
    astartis_core
    OpenSSL::Crypto
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    "${NPCAP_SDK_DIR}/Lib/x64/Packet.lib"
    ws2_32
    iphlpapi
)

add_test(NAME PacketSensorTest COMMAND test_packet_sensor)

# Test executable — Step 6: Threat-Level State Machine
add_executable(test_threat_level
    tests/test_threat_level.cpp
)

target_link_libraries(test_threat_level
    astartis_core
    OpenSSL::Crypto
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    "${NPCAP_SDK_DIR}/Lib/x64/Packet.lib"
    ws2_32
    iphlpapi
)

add_test(NAME ThreatLevelTest COMMAND test_threat_level)

# Test executable — Step 7: Deterministic Rule Engine
add_executable(test_rule_engine
    tests/test_rule_engine.cpp
)

target_link_libraries(test_rule_engine
    astartis_core
    OpenSSL::Crypto
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    "${NPCAP_SDK_DIR}/Lib/x64/Packet.lib"
    ws2_32
    iphlpapi
)

add_test(NAME RuleEngineTest COMMAND test_rule_engine)

# Test executable — Step 8: Zero-Trust Access Token
add_executable(test_access_token
    tests/test_access_token.cpp
)

target_link_libraries(test_access_token
    astartis_core
    OpenSSL::Crypto
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    "${NPCAP_SDK_DIR}/Lib/x64/Packet.lib"
    ws2_32
    iphlpapi
)

add_test(NAME AccessTokenTest COMMAND test_access_token)

# Test executable — Step 9: Sandboxed Mirror Environment
add_executable(test_sandbox
    tests/test_sandbox.cpp
)

target_link_libraries(test_sandbox
    astartis_core
    OpenSSL::Crypto
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    "${NPCAP_SDK_DIR}/Lib/x64/Packet.lib"
    ws2_32
    iphlpapi
)

add_test(NAME SandboxTest COMMAND test_sandbox)

# Test executable — Step 10: Decoy Environment
add_executable(test_decoy
    tests/test_decoy.cpp
)

target_link_libraries(test_decoy
    astartis_core
    OpenSSL::Crypto
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    "${NPCAP_SDK_DIR}/Lib/x64/Packet.lib"
    ws2_32
    iphlpapi
)

add_test(NAME DecoyTest COMMAND test_decoy)

# Test executable — Step 11: Active Response
add_executable(test_active_response
    tests/test_active_response.cpp
)

target_link_libraries(test_active_response
    astartis_core
    OpenSSL::Crypto
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    "${NPCAP_SDK_DIR}/Lib/x64/Packet.lib"
    ws2_32
    iphlpapi
)

add_test(NAME ActiveResponseTest COMMAND test_active_response)

# Test executable -- Step 12: Chaos Detector
add_executable(test_chaos_detector
    tests/test_chaos_detector.cpp
)

target_link_libraries(test_chaos_detector
    astartis_core
    OpenSSL::Crypto
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    "${NPCAP_SDK_DIR}/Lib/x64/Packet.lib"
    ws2_32
    iphlpapi
)

add_test(NAME ChaosDetectorTest COMMAND test_chaos_detector)

# Test executable -- Step 13: Attribution Report
add_executable(test_attribution_report
    tests/test_attribution_report.cpp
)

target_link_libraries(test_attribution_report
    astartis_core
    OpenSSL::Crypto
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    "${NPCAP_SDK_DIR}/Lib/x64/Packet.lib"
    ws2_32
    iphlpapi
)

add_test(NAME AttributionReportTest COMMAND test_attribution_report)

# ===========================================================================
# astartis_bridge — Port target for Elixir orchestration (Step 15)
# ===========================================================================

add_executable(astartis_bridge
    bridge/astartis_bridge.cpp
    bridge/dashboard_writer.cpp
    bridge/dashboard_server.cpp
    # v3.0 agent swarm — 4-model tiers + ECC adapter
    agents/controller/granite_client.cpp
    agents/controller/persona_loader.cpp
    agents/controller/agent_controller.cpp
    agents/controller/policy_engine.cpp
    agents/controller/action_dispatcher.cpp
    agents/ecc/ecc_adapter.cpp
    # v2.1 network arch — Zero Trust simulation
    network_arch/zerotrust/nac_workflow.cpp
    network_arch/zerotrust/zerotrust_engine.cpp
    # v3.1 real-time protection monitors
    core/event_log_monitor/event_log_monitor.cpp
    core/fs_monitor/fs_monitor.cpp
    core/autonomy_loop/autonomy_loop.cpp
)

target_include_directories(astartis_bridge PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/core
    ${CMAKE_CURRENT_SOURCE_DIR}/bridge
    ${CMAKE_CURRENT_SOURCE_DIR}          # so #include "agents/..." and "network_arch/..." resolve
    ${OPENSSL_INCLUDE_DIR}
    ${NPCAP_SDK_DIR}/Include
)

target_compile_definitions(astartis_bridge PRIVATE
    HAVE_REMOTE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

target_link_libraries(astartis_bridge
    astartis_core
    OpenSSL::Crypto
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    "${NPCAP_SDK_DIR}/Lib/x64/Packet.lib"
    ws2_32
    iphlpapi
    wevtapi     # Windows Event Log API (EvtSubscribe)
    pdh         # PDH used by protection monitors + dashboard_writer
    shell32     # ShellExecuteA for --dashboard browser launch
)

# Test executable -- Step 16 ST-3: Quarantine module
add_executable(test_quarantine
    tests/test_quarantine.cpp
)

target_link_libraries(test_quarantine
    astartis_core
    OpenSSL::Crypto
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    "${NPCAP_SDK_DIR}/Lib/x64/Packet.lib"
    ws2_32
    iphlpapi
)

add_test(NAME QuarantineTest COMMAND test_quarantine)

# Test executable -- Step 16 ST-4: Firewall blocker
add_executable(test_firewall_blocker
    tests/test_firewall_blocker.cpp
)

target_link_libraries(test_firewall_blocker
    astartis_core
    OpenSSL::Crypto
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    "${NPCAP_SDK_DIR}/Lib/x64/Packet.lib"
    ws2_32
    iphlpapi
)

# Exit code 2 means "not elevated" — treat as SKIP not FAIL
add_test(NAME FirewallBlockerTest COMMAND test_firewall_blocker)
set_tests_properties(FirewallBlockerTest PROPERTIES SKIP_RETURN_CODE 2)

# Test executable -- Step 16 ST-7: Active defense integration
add_executable(test_active_defense
    tests/test_active_defense.cpp
)

target_link_libraries(test_active_defense
    astartis_core
    OpenSSL::Crypto
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    "${NPCAP_SDK_DIR}/Lib/x64/Packet.lib"
    ws2_32
    iphlpapi
)

# Exit code 2 means "not elevated" — treat as SKIP not FAIL
add_test(NAME ActiveDefenseTest COMMAND test_active_defense)
set_tests_properties(ActiveDefenseTest PROPERTIES SKIP_RETURN_CODE 2)

# Test executable -- Step 17: 12-Eye Unlock Protocol
add_executable(test_unlock_protocol
    tests/test_unlock_protocol.cpp
)

target_link_libraries(test_unlock_protocol
    astartis_core
    OpenSSL::Crypto
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    "${NPCAP_SDK_DIR}/Lib/x64/Packet.lib"
    ws2_32
    iphlpapi
)

add_test(NAME UnlockProtocolTest COMMAND test_unlock_protocol)

# Test executable -- Step 14: ClamAV / clamd scanner
add_executable(test_clamd_scanner
    tests/test_clamd_scanner.cpp
)

target_link_libraries(test_clamd_scanner
    astartis_core
    OpenSSL::Crypto
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    "${NPCAP_SDK_DIR}/Lib/x64/Packet.lib"
    ws2_32
    iphlpapi
)

# Exit code 2 means "clamd not running" — treat as SKIP not FAIL
add_test(NAME ClamdScannerTest COMMAND test_clamd_scanner)
set_tests_properties(ClamdScannerTest PROPERTIES SKIP_RETURN_CODE 2)

# Test executable -- Step 18: AI Triage (local Granite via Ollama)
add_executable(test_ai_triage
    tests/test_ai_triage.cpp
)

target_link_libraries(test_ai_triage
    astartis_core
    OpenSSL::Crypto
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    "${NPCAP_SDK_DIR}/Lib/x64/Packet.lib"
    ws2_32
    iphlpapi
)

# Exit code 2 means "Ollama not running" — treat as SKIP not FAIL
# Timeout=120: Tests 4+5 each wait ~5s connect-timeout (TEST-NET + dead port) → ~30s total.
# 120s provides headroom for heavy-tier Granite inference on slower hardware.
add_test(NAME AiTriageTest COMMAND test_ai_triage)
set_tests_properties(AiTriageTest PROPERTIES
    SKIP_RETURN_CODE 2
    TIMEOUT          120
)

# Test executable -- Step 19: Veeam / IBM Storage interface (stub)
add_executable(test_veeam_interface
    tests/test_veeam_interface.cpp
)

target_link_libraries(test_veeam_interface
    astartis_core
    OpenSSL::Crypto
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    "${NPCAP_SDK_DIR}/Lib/x64/Packet.lib"
    ws2_32
    iphlpapi
)

# No SKIP_RETURN_CODE — stub has zero external dependencies, always runs.
add_test(NAME VeeamInterfaceTest COMMAND test_veeam_interface)

# ===========================================================================
# v2.1 Network Architecture Tests — Zero Trust simulation
# Header-only segmentation + self-contained ZT engine (no external deps)
# ===========================================================================

# Test: SSID config + VLAN isolation (header-only, no .cpp required)
add_executable(test_segmentation
    network_arch/tests/test_segmentation.cpp
)
target_include_directories(test_segmentation PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}   # resolves "network_arch/segmentation/ssid_config.h"
)
add_test(NAME SegmentationTest COMMAND test_segmentation)

# Test: 8-step NAC workflow
add_executable(test_nac_workflow
    network_arch/tests/test_nac_workflow.cpp
    network_arch/zerotrust/nac_workflow.cpp
)
target_include_directories(test_nac_workflow PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}   # resolves "network_arch/zerotrust/nac_workflow.h"
)
add_test(NAME NACWorkflowTest COMMAND test_nac_workflow)

# Test: Zero Trust decision engine
add_executable(test_zerotrust_decisions
    network_arch/tests/test_zerotrust_decisions.cpp
    network_arch/zerotrust/zerotrust_engine.cpp
)
target_include_directories(test_zerotrust_decisions PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}   # resolves "network_arch/zerotrust/zerotrust_engine.h"
)
add_test(NAME ZeroTrustDecisionsTest COMMAND test_zerotrust_decisions)

# ===========================================================================
# v3.0 Agent Swarm Tests — GraniteClient + AgentController
# Tests for all 4 model tiers: FAST / HEAVY / ACCURACY / ORCHESTRATOR
# ===========================================================================

# Test: GraniteClient — 4-model tier validation + ORCHESTRATOR prefix injection
add_executable(test_granite_client
    tests/test_granite_client.cpp
    agents/controller/granite_client.cpp
)
target_include_directories(test_granite_client PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/core
    ${CMAKE_CURRENT_SOURCE_DIR}/bridge   # nlohmann/json.hpp lives here
    ${OPENSSL_INCLUDE_DIR}
    ${NPCAP_SDK_DIR}/Include
)
target_compile_definitions(test_granite_client PRIVATE
    HAVE_REMOTE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
target_link_libraries(test_granite_client
    OpenSSL::Crypto
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    "${NPCAP_SDK_DIR}/Lib/x64/Packet.lib"
    ws2_32
    iphlpapi
)
# Exit code 2 = Ollama not running (SKIP, not FAIL)
# Timeout 900s: ACCURACY + ORCHESTRATOR each take up to 360s on CPU.
# 2 calls × 360s = 720s + overhead → 900s total.
add_test(NAME GraniteClientTest COMMAND test_granite_client)
set_tests_properties(GraniteClientTest PROPERTIES
    SKIP_RETURN_CODE 2
    TIMEOUT          900
)

# Test: AgentController — PersonaLoader, tier distribution, lifecycle, ECC loading
# Needs action_dispatcher.cpp linked (agent_controller calls dispatch() when wired up).
# action_dispatcher.cpp depends on protection modules → link astartis_core + zerotrust.
add_executable(test_agent_controller
    tests/test_agent_controller.cpp
    agents/controller/granite_client.cpp
    agents/controller/persona_loader.cpp
    agents/controller/agent_controller.cpp
    agents/controller/policy_engine.cpp
    agents/controller/action_dispatcher.cpp
    agents/ecc/ecc_adapter.cpp
    network_arch/zerotrust/nac_workflow.cpp
    network_arch/zerotrust/zerotrust_engine.cpp
)
target_include_directories(test_agent_controller PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/core
    ${CMAKE_CURRENT_SOURCE_DIR}/bridge   # nlohmann/json.hpp lives here
    ${OPENSSL_INCLUDE_DIR}
    ${NPCAP_SDK_DIR}/Include
)
target_compile_definitions(test_agent_controller PRIVATE
    HAVE_REMOTE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
target_link_libraries(test_agent_controller
    astartis_core
    OpenSSL::Crypto
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    "${NPCAP_SDK_DIR}/Lib/x64/Packet.lib"
    ws2_32
    iphlpapi
)
# Exit code 2 = Ollama not running (SKIP, not FAIL)
# Timeout 900s: cycles through all 4 tiers. ACCURACY/ORCHESTRATOR = 360s each.
add_test(NAME AgentControllerTest COMMAND test_agent_controller)
set_tests_properties(AgentControllerTest PROPERTIES
    SKIP_RETURN_CODE 2
    TIMEOUT          900
)

# ===========================================================================
# v3.0 Phase 2A — Hardening tests + benchmark
# ===========================================================================

# Shared source list for agent-swarm-only tests (no protection modules needed).
# Note: agent_controller.cpp calls ActionDispatcher::dispatch() when wired up,
# but the 2A tests never call set_action_dispatcher(), so the symbol must still
# be present.  We include action_dispatcher.cpp + zerotrust here and link
# astartis_core for all AGENT_SWARM targets.
set(AGENT_SWARM_SOURCES
    agents/controller/granite_client.cpp
    agents/controller/persona_loader.cpp
    agents/controller/agent_controller.cpp
    agents/controller/policy_engine.cpp
    agents/controller/action_dispatcher.cpp
    agents/ecc/ecc_adapter.cpp
    network_arch/zerotrust/nac_workflow.cpp
    network_arch/zerotrust/zerotrust_engine.cpp
)

# Shared include dirs for agent swarm tests
set(AGENT_SWARM_INCLUDES
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/core
    ${CMAKE_CURRENT_SOURCE_DIR}/bridge
    ${OPENSSL_INCLUDE_DIR}
    ${NPCAP_SDK_DIR}/Include
)

# Shared compile defs
set(AGENT_SWARM_DEFS HAVE_REMOTE WIN32_LEAN_AND_MEAN NOMINMAX)

# Shared link libs — include astartis_core for protection modules used by ActionDispatcher
set(AGENT_SWARM_LIBS
    astartis_core
    OpenSSL::Crypto
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    "${NPCAP_SDK_DIR}/Lib/x64/Packet.lib"
    ws2_32
    iphlpapi
)

# --- test_integration_orchestrator ---
# FAIL (not skip) if model unavailable — Timeout 120s
add_executable(test_integration_orchestrator
    tests/test_integration_orchestrator.cpp
    ${AGENT_SWARM_SOURCES}
)
target_include_directories(test_integration_orchestrator PRIVATE ${AGENT_SWARM_INCLUDES})
target_compile_definitions(test_integration_orchestrator PRIVATE ${AGENT_SWARM_DEFS})
target_link_libraries(test_integration_orchestrator ${AGENT_SWARM_LIBS})
add_test(NAME IntegrationOrchestratorTest COMMAND test_integration_orchestrator)
# 360s model timeout + test overhead. CPU inference on 8B Q5 = ~133s for 256 tokens.
set_tests_properties(IntegrationOrchestratorTest PROPERTIES
    TIMEOUT          420
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

# --- test_stress_queue ---
# 20 tasks (5 per tier), FAST+HEAVY mandatory, ACCURACY+ORCHESTRATOR optional.
# Measured CPU inference: FAST~3s, HEAVY~15s, ACCURACY/ORCHESTRATOR~100s each.
# 5×3 + 5×15 + 5×100 + 5×100 = 1090s worst-case. Use 1800s (CTest max).
add_executable(test_stress_queue
    tests/test_stress_queue.cpp
    ${AGENT_SWARM_SOURCES}
)
target_include_directories(test_stress_queue PRIVATE ${AGENT_SWARM_INCLUDES})
target_compile_definitions(test_stress_queue PRIVATE ${AGENT_SWARM_DEFS})
target_link_libraries(test_stress_queue ${AGENT_SWARM_LIBS})
add_test(NAME StressQueueTest COMMAND test_stress_queue)
set_tests_properties(StressQueueTest PROPERTIES
    SKIP_RETURN_CODE 2
    TIMEOUT          900
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

# --- test_ollama_recovery ---
add_executable(test_ollama_recovery
    tests/test_ollama_recovery.cpp
    agents/controller/granite_client.cpp
)
target_include_directories(test_ollama_recovery PRIVATE ${AGENT_SWARM_INCLUDES})
target_compile_definitions(test_ollama_recovery PRIVATE ${AGENT_SWARM_DEFS})
target_link_libraries(test_ollama_recovery ${AGENT_SWARM_LIBS})
add_test(NAME OllamaRecoveryTest COMMAND test_ollama_recovery)
set_tests_properties(OllamaRecoveryTest PROPERTIES
    SKIP_RETURN_CODE 2
    TIMEOUT          120
)

# --- benchmark_tiers (standalone, not a CTest) ---
add_executable(benchmark_tiers
    scripts/benchmark_tiers.cpp
    agents/controller/granite_client.cpp
)
target_include_directories(benchmark_tiers PRIVATE ${AGENT_SWARM_INCLUDES})
target_compile_definitions(benchmark_tiers PRIVATE ${AGENT_SWARM_DEFS})
target_link_libraries(benchmark_tiers ${AGENT_SWARM_LIBS})
# Not added to CTest — run manually: .\build\Release\benchmark_tiers.exe

# ===========================================================================
# v3.0 Phase 2B — Action Dispatcher + Policy Engine
# These need both agent swarm + protection modules (astartis_core)
# ===========================================================================

# Source list for full integration tests (swarm + protection + zerotrust)
set(FULL_INTEGRATION_SOURCES
    agents/controller/granite_client.cpp
    agents/controller/persona_loader.cpp
    agents/controller/agent_controller.cpp
    agents/controller/policy_engine.cpp
    agents/controller/action_dispatcher.cpp
    agents/ecc/ecc_adapter.cpp
    network_arch/zerotrust/nac_workflow.cpp
    network_arch/zerotrust/zerotrust_engine.cpp
)

set(FULL_INTEGRATION_INCLUDES
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/core
    ${CMAKE_CURRENT_SOURCE_DIR}/bridge
    ${OPENSSL_INCLUDE_DIR}
    ${NPCAP_SDK_DIR}/Include
)

# ===========================================================================
# v3.0 Phase 2C — End-to-End Integration Tests
# ===========================================================================

# --- test_e2e_firewall_block ---
# Requires elevation (netsh). Exit code 2 = not elevated (SKIP).
add_executable(test_e2e_firewall_block
    tests/test_e2e_firewall_block.cpp
    ${FULL_INTEGRATION_SOURCES}
)
target_include_directories(test_e2e_firewall_block PRIVATE ${FULL_INTEGRATION_INCLUDES})
target_compile_definitions(test_e2e_firewall_block PRIVATE ${AGENT_SWARM_DEFS})
target_link_libraries(test_e2e_firewall_block
    astartis_core
    OpenSSL::Crypto
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    "${NPCAP_SDK_DIR}/Lib/x64/Packet.lib"
    ws2_32
    iphlpapi
)
add_test(NAME E2EFirewallBlockTest COMMAND test_e2e_firewall_block)
# ORCHESTRATOR tier (granite4.1): 360s socket timeout + test overhead.
set_tests_properties(E2EFirewallBlockTest PROPERTIES
    SKIP_RETURN_CODE 2
    TIMEOUT          480
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

# --- test_e2e_quarantine ---
add_executable(test_e2e_quarantine
    tests/test_e2e_quarantine.cpp
    ${FULL_INTEGRATION_SOURCES}
)
target_include_directories(test_e2e_quarantine PRIVATE ${FULL_INTEGRATION_INCLUDES})
target_compile_definitions(test_e2e_quarantine PRIVATE ${AGENT_SWARM_DEFS})
target_link_libraries(test_e2e_quarantine
    astartis_core
    OpenSSL::Crypto
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    "${NPCAP_SDK_DIR}/Lib/x64/Packet.lib"
    ws2_32
    iphlpapi
)
add_test(NAME E2EQuarantineTest COMMAND test_e2e_quarantine)
# ACCURACY tier (granite4.1): 360s socket timeout + test overhead.
set_tests_properties(E2EQuarantineTest PROPERTIES
    TIMEOUT          480
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

# --- test_e2e_deception ---
add_executable(test_e2e_deception
    tests/test_e2e_deception.cpp
    ${FULL_INTEGRATION_SOURCES}
)
target_include_directories(test_e2e_deception PRIVATE ${FULL_INTEGRATION_INCLUDES})
target_compile_definitions(test_e2e_deception PRIVATE ${AGENT_SWARM_DEFS})
target_link_libraries(test_e2e_deception
    astartis_core
    OpenSSL::Crypto
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    "${NPCAP_SDK_DIR}/Lib/x64/Packet.lib"
    ws2_32
    iphlpapi
)
add_test(NAME E2EDeceptionTest COMMAND test_e2e_deception)
# HEAVY tier — 60s timeout but large context. 180s headroom.
set_tests_properties(E2EDeceptionTest PROPERTIES
    SKIP_RETURN_CODE 2
    TIMEOUT          180
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

# --- test_e2e_zerotrust ---
add_executable(test_e2e_zerotrust
    tests/test_e2e_zerotrust.cpp
    ${FULL_INTEGRATION_SOURCES}
)
target_include_directories(test_e2e_zerotrust PRIVATE ${FULL_INTEGRATION_INCLUDES})
target_compile_definitions(test_e2e_zerotrust PRIVATE ${AGENT_SWARM_DEFS})
target_link_libraries(test_e2e_zerotrust
    astartis_core
    OpenSSL::Crypto
    "${NPCAP_SDK_DIR}/Lib/x64/wpcap.lib"
    "${NPCAP_SDK_DIR}/Lib/x64/Packet.lib"
    ws2_32
    iphlpapi
)
add_test(NAME E2EZeroTrustTest COMMAND test_e2e_zerotrust)
# ACCURACY tier (granite4.1): 360s socket timeout + test overhead.
set_tests_properties(E2EZeroTrustTest PROPERTIES
    SKIP_RETURN_CODE 2
    TIMEOUT          480
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

# ===========================================================================
# Phase 3 — Thread Pool, Async Inference, Warm-Model Keep-Alive Tests
# ===========================================================================

# --- test_thread_pool ---
add_executable(test_thread_pool
    tests/test_thread_pool.cpp
    ${AGENT_SWARM_SOURCES}
)
target_include_directories(test_thread_pool PRIVATE ${AGENT_SWARM_INCLUDES})
target_compile_definitions(test_thread_pool PRIVATE ${AGENT_SWARM_DEFS})
target_link_libraries(test_thread_pool ${AGENT_SWARM_LIBS})
add_test(NAME ThreadPoolTest COMMAND test_thread_pool)
set_tests_properties(ThreadPoolTest PROPERTIES
    SKIP_RETURN_CODE 2
    TIMEOUT          60
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

# --- test_async_inference ---
add_executable(test_async_inference
    tests/test_async_inference.cpp
    agents/controller/granite_client.cpp
)
target_include_directories(test_async_inference PRIVATE ${AGENT_SWARM_INCLUDES})
target_compile_definitions(test_async_inference PRIVATE ${AGENT_SWARM_DEFS})
target_link_libraries(test_async_inference ${AGENT_SWARM_LIBS})
add_test(NAME AsyncInferenceTest COMMAND test_async_inference)
set_tests_properties(AsyncInferenceTest PROPERTIES
    SKIP_RETURN_CODE 2
    TIMEOUT          60
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

# --- test_warm_model ---
add_executable(test_warm_model
    tests/test_warm_model.cpp
    agents/controller/granite_client.cpp
)
target_include_directories(test_warm_model PRIVATE ${AGENT_SWARM_INCLUDES})
target_compile_definitions(test_warm_model PRIVATE ${AGENT_SWARM_DEFS})
target_link_libraries(test_warm_model ${AGENT_SWARM_LIBS})
add_test(NAME WarmModelTest COMMAND test_warm_model)
set_tests_properties(WarmModelTest PROPERTIES
    SKIP_RETURN_CODE 2
    TIMEOUT          180
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)

# (dashboard_server, dashboard_writer, demo_dashboard_data, test_dashboard_exec_security,
#  test_dashboard_config_endpoint — removed; C++ HTTP dashboard retired, use astartis_web/)
