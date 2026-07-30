// test_integration_orchestrator.cpp -- Live ORCHESTRATOR inference test (Astartis v3.0)
//
// Verifies end-to-end: incident_responder persona (ORCHESTRATOR tier) submits
// a real task to Ollama granite4.1-8b-q5_K_M and gets a structured response.
//
// Unlike other tests, this does NOT exit with code 2 if the model is missing.
// The spec says: "If model unavailable: FAIL. Do not skip. Model IS pulled."
//
// Exit code 0 = ALL PASS
// Exit code 1 = FAIL
// Prerequisites: Ollama running, granite4.1-8b-q5_K_M pulled.

#pragma warning(push)
#pragma warning(disable: 4706 4127 4244)
#include "nlohmann/json.hpp"
#pragma warning(pop)

#include "agents/controller/agent_controller.h"
#include "agents/controller/persona_loader.h"
#include "agents/controller/granite_client.h"
#include "agents/controller/orchestrator_context.h"

#include <iostream>
#include <filesystem>
#include <string>
#include <chrono>
#include <thread>
#include <atomic>

namespace fs = std::filesystem;
using json = nlohmann::json;

static int g_failures = 0;
static bool g_orchestrator_prefix_seen = false;

#define EXPECT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "FAIL: " << (msg) << " [" << __FILE__ << ":" << __LINE__ << "]\n"; \
            ++g_failures; \
        } else { \
            std::cerr << "PASS: " << (msg) << "\n"; \
        } \
    } while(0)

static std::string test_audit(const std::string& evt, const std::string& payload)
{
    static int seq = 0;
    std::string id = "integ_" + std::to_string(++seq);
    std::cerr << "[AUDIT] " << evt << " | " << payload << "\n";
    // Track if ORCHESTRATOR prefix injection audit fires
    if (evt == "orchestrator_prefix_injected") {
        g_orchestrator_prefix_seen = true;
    }
    return id;
}

int main()
{
    std::cerr << "=== ORCHESTRATOR Live Integration Test ===\n\n";

    // --- Pre-flight: Ollama must be running ---
    std::cerr << "--- Pre-flight: Ollama ping ---\n";
    astartis::agents::GraniteClient ping_client(test_audit);
    if (!ping_client.ping()) {
        std::cerr << "FAIL: Ollama is not running. This test requires Ollama + granite4.1.\n";
        return 1;
    }
    std::cerr << "PASS: Ollama is reachable\n\n";

    // --- Step 1: Load incident_responder persona ---
    std::cerr << "--- Step 1: Load incident_responder (ORCHESTRATOR tier) ---\n";
    fs::path persona_path = "agents/definitions/incident_responder.json";
    if (!fs::exists(persona_path)) {
        std::cerr << "FAIL: " << persona_path << " not found\n";
        return 1;
    }
    auto persona = astartis::agents::PersonaLoader::load_from_json(persona_path);
    EXPECT(persona.name == "incident_responder", "Persona name should be incident_responder");
    EXPECT(persona.preferred_model == astartis::agents::GraniteModel::ORCHESTRATOR,
           "incident_responder should use ORCHESTRATOR tier");
    EXPECT(astartis::agents::PersonaLoader::validate_persona(persona),
           "incident_responder persona should be valid");
    std::cerr << "Persona loaded: " << persona.name
              << " tier=" << (int)persona.preferred_model
              << " max_tokens=" << persona.max_tokens << "\n\n";

    // --- Step 2: Build system prompt + submit directly via GraniteClient ---
    std::cerr << "--- Step 2: Submit task via GraniteClient (ORCHESTRATOR) ---\n";
    astartis::agents::GraniteClient client(test_audit);

    const std::string alert_input =
        "ALERT BUNDLE: Ransomware indicators detected on endpoint WIN-01 (192.168.1.50). "
        "C2 beacon observed to 185.220.101.42:443. "
        "File encryption activity detected: 847 files renamed in 30 seconds. "
        "Shadow copies deleted via vssadmin. "
        "Lateral movement via admin share to 192.168.1.75 and 192.168.1.80. "
        "Analyze and provide containment plan.";

    std::cerr << "Sending task to ORCHESTRATOR tier (granite4.1-8b-q5_K_M)...\n";
    std::cerr << "Timeout: " << astartis::agents::GraniteClient::ORCHESTRATOR_TIMEOUT_MS / 1000
              << "s (CPU inference — may take up to 4 minutes)\n";

    auto t_start = std::chrono::steady_clock::now();
    auto resp = client.generate(
        astartis::agents::GraniteModel::ORCHESTRATOR,
        persona.system_prompt,
        alert_input,
        persona.max_tokens,
        persona.temperature
    );
    auto t_end = std::chrono::steady_clock::now();
    int64_t latency_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        t_end - t_start).count();

    std::cerr << "Response received in " << latency_ms << "ms\n\n";

    // --- Step 3: Verify ORCHESTRATOR prefix was injected ---
    std::cerr << "--- Step 3: Verify ORCHESTRATOR_PROMPT_PREFIX injected ---\n";
    EXPECT(g_orchestrator_prefix_seen,
           "orchestrator_prefix_injected audit event should have fired");

    // --- Step 4: Verify model tag ---
    std::cerr << "\n--- Step 4: Verify model_used tag ---\n";
    EXPECT(resp.model_used == astartis::agents::GraniteClient::ORCHESTRATOR_MODEL_TAG,
           "model_used should be granite4.1-8b-q5_K_M");
    std::cerr << "model_used: " << resp.model_used << "\n";

    // --- Step 5: Verify response is non-empty ---
    std::cerr << "\n--- Step 5: Verify response quality ---\n";
    EXPECT(resp.ok, "ORCHESTRATOR generate() should return ok=true");
    EXPECT(!resp.text.empty(), "ORCHESTRATOR response should not be empty");
    std::cerr << "Response length: " << resp.text.size() << " chars\n";
    std::cerr << "Tokens used: " << resp.tokens_used << "\n";

    // --- Step 6: Verify structured content ---
    std::cerr << "\n--- Step 6: Verify structured output contains expected sections ---\n";
    const std::string& text = resp.text;
    bool has_executive    = text.find("EXECUTIVE_SUMMARY") != std::string::npos
                         || text.find("executive_summary") != std::string::npos
                         || text.find("Executive") != std::string::npos;
    bool has_assignments  = text.find("AGENT_ASSIGNMENTS") != std::string::npos
                         || text.find("agent_assignments") != std::string::npos
                         || text.find("containment") != std::string::npos
                         || text.find("containment_actions") != std::string::npos;
    bool has_json         = text.find('{') != std::string::npos;

    EXPECT(has_executive || has_assignments || has_json,
           "Response should contain structured content (EXECUTIVE_SUMMARY, AGENT_ASSIGNMENTS, or JSON)");

    // Print first 400 chars of response for verification
    std::cerr << "\n--- Response Preview (first 400 chars) ---\n";
    std::cerr << text.substr(0, std::min<size_t>(400, text.size())) << "\n";
    if (text.size() > 400) std::cerr << "... [" << text.size() - 400 << " more chars]\n";

    // --- Step 7: Verify latency is within ORCHESTRATOR_TIMEOUT_MS ---
    std::cerr << "\n--- Step 7: Verify latency within timeout ---\n";
    EXPECT(latency_ms < astartis::agents::GraniteClient::ORCHESTRATOR_TIMEOUT_MS,
           "Latency should be within ORCHESTRATOR timeout (360s on CPU)");
    std::cerr << "Latency: " << latency_ms << "ms / "
              << astartis::agents::GraniteClient::ORCHESTRATOR_TIMEOUT_MS << "ms limit\n";

    std::cerr << "\n=== Results ===\n";
    if (g_failures == 0) {
        std::cerr << "ALL TESTS PASSED\n";
        return 0;
    }
    std::cerr << g_failures << " TEST(S) FAILED\n";
    return 1;
}

// Made with Bob
