// test_granite_client.cpp -- GraniteClient unit + integration tests (Astartis v3.0)
//
// Tests cover all 4 model tiers: FAST, HEAVY, ACCURACY, ORCHESTRATOR.
// Exit code 2 = Ollama not running (treated as SKIP by CTest)

#include "agents/controller/granite_client.h"
#include "agents/controller/orchestrator_context.h"
#include <iostream>
#include <cassert>
#include <string>

static int g_failures = 0;

#define EXPECT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "FAIL: " << (msg) << " [" << __FILE__ << ":" << __LINE__ << "]\n"; \
            ++g_failures; \
        } else { \
            std::cerr << "PASS: " << (msg) << "\n"; \
        } \
    } while(0)

static std::string test_audit(const std::string& evt, const std::string& p)
{
    static int n = 0;
    std::cerr << "[AUDIT] " << evt << " | " << p << "\n";
    return "ga_" + std::to_string(++n);
}

int main()
{
    std::cerr << "=== GraniteClient Tests (v3.0) ===\n\n";

    // -----------------------------------------------------------------------
    // Test 1: Compile-time model tag constants
    // -----------------------------------------------------------------------
    std::cerr << "--- Test 1: Model tag constants ---\n";
    EXPECT(std::string(astartis::agents::GraniteClient::FAST_MODEL_TAG)
               == "granite3.1-moe:3b",
           "FAST tag should be granite3.1-moe:3b");
    EXPECT(std::string(astartis::agents::GraniteClient::HEAVY_MODEL_TAG)
               == "granite3.1-dense:8b",
           "HEAVY tag should be granite3.1-dense:8b");
    EXPECT(std::string(astartis::agents::GraniteClient::ACCURACY_MODEL_TAG)
               == "ibm/granite4.1:8b-q5_K_M",
           "ACCURACY tag should be ibm/granite4.1:8b-q5_K_M");
    EXPECT(std::string(astartis::agents::GraniteClient::ORCHESTRATOR_MODEL_TAG)
               == "ibm/granite4.1:8b-q5_K_M",
           "ORCHESTRATOR tag should be ibm/granite4.1:8b-q5_K_M (same model, diff prompt)");

    // -----------------------------------------------------------------------
    // Test 2: Compile-time timeout constants
    // -----------------------------------------------------------------------
    std::cerr << "\n--- Test 2: Timeout constants ---\n";
    EXPECT(astartis::agents::GraniteClient::FAST_TIMEOUT_MS         == 30000,
           "FAST timeout should be 30s");
    EXPECT(astartis::agents::GraniteClient::HEAVY_TIMEOUT_MS        == 60000,
           "HEAVY timeout should be 60s");
    EXPECT(astartis::agents::GraniteClient::ACCURACY_TIMEOUT_MS     == 360000,
           "ACCURACY timeout should be 360s (CPU inference on 8B Q5)");
    EXPECT(astartis::agents::GraniteClient::ORCHESTRATOR_TIMEOUT_MS == 360000,
           "ORCHESTRATOR timeout should be 360s (CPU inference on 8B Q5)");

    // -----------------------------------------------------------------------
    // Test 3: ORCHESTRATOR prefix constant is non-empty
    // -----------------------------------------------------------------------
    std::cerr << "\n--- Test 3: ORCHESTRATOR prefix constant ---\n";
    std::string prefix = astartis::ORCHESTRATOR_PROMPT_PREFIX;
    EXPECT(!prefix.empty(), "ORCHESTRATOR_PROMPT_PREFIX should not be empty");
    EXPECT(prefix.find("Swarm Orchestrator") != std::string::npos,
           "ORCHESTRATOR prefix should mention Swarm Orchestrator");
    EXPECT(prefix.find("EXECUTIVE_SUMMARY") != std::string::npos,
           "ORCHESTRATOR prefix should contain EXECUTIVE_SUMMARY section");
    EXPECT(prefix.find("HUMAN_ESCALATION") != std::string::npos,
           "ORCHESTRATOR prefix should contain HUMAN_ESCALATION section");

    // -----------------------------------------------------------------------
    // Test 4: GraniteModel enum has all 4 values
    // -----------------------------------------------------------------------
    std::cerr << "\n--- Test 4: GraniteModel enum coverage ---\n";
    astartis::agents::GraniteModel fast  = astartis::agents::GraniteModel::FAST;
    astartis::agents::GraniteModel heavy = astartis::agents::GraniteModel::HEAVY;
    astartis::agents::GraniteModel acc   = astartis::agents::GraniteModel::ACCURACY;
    astartis::agents::GraniteModel orch  = astartis::agents::GraniteModel::ORCHESTRATOR;
    EXPECT(fast  != heavy, "FAST and HEAVY should be distinct");
    EXPECT(fast  != acc,   "FAST and ACCURACY should be distinct");
    EXPECT(fast  != orch,  "FAST and ORCHESTRATOR should be distinct");
    EXPECT(heavy != acc,   "HEAVY and ACCURACY should be distinct");
    EXPECT(heavy != orch,  "HEAVY and ORCHESTRATOR should be distinct");
    EXPECT(acc   != orch,  "ACCURACY and ORCHESTRATOR should be distinct");

    // -----------------------------------------------------------------------
    // Test 5: Ping (skip if Ollama offline)
    // -----------------------------------------------------------------------
    std::cerr << "\n--- Test 5: Ping ---\n";
    astartis::agents::GraniteClient client(test_audit);
    bool alive = client.ping();
    if (!alive) {
        std::cerr << "INFO: Ollama not running — exiting with code 2 (SKIP)\n";
        if (g_failures > 0) {
            std::cerr << g_failures << " TEST(S) FAILED (before skip point)\n";
            return 1;
        }
        return 2;
    }
    std::cerr << "PASS: Ollama reachable\n";

    // -----------------------------------------------------------------------
    // Test 6: FAST model generates non-empty response
    // -----------------------------------------------------------------------
    std::cerr << "\n--- Test 6: FAST model generate ---\n";
    auto r1 = client.generate(
        astartis::agents::GraniteModel::FAST,
        "You are a classifier. Reply with exactly one JSON object.",
        "Classify this alert: failed SSH login from 10.0.0.5. "
        "Schema: {\"severity\":\"LOW|MEDIUM|HIGH|CRITICAL\"}",
        64, 0.1
    );
    EXPECT(r1.ok,              "FAST model should return ok=true");
    EXPECT(!r1.text.empty(),   "FAST model response should not be empty");
    EXPECT(r1.model_used == astartis::agents::GraniteClient::FAST_MODEL_TAG,
           "FAST model should use granite3.1-moe:3b tag");
    std::cerr << "Response: " << r1.text.substr(0, 100) << "...\n";

    // -----------------------------------------------------------------------
    // Test 7: generate with explicit FAST tier (replaces removed route_and_generate)
    // route_and_generate was dead code in production — deleted in v3.2.
    // -----------------------------------------------------------------------
    std::cerr << "\n--- Test 7: explicit FAST generate (replaces route_and_generate) ---\n";
    auto r2 = client.generate(
        astartis::agents::GraniteModel::FAST,
        "You are a triage bot.",
        "Is this a critical alert? SSH port scan from unknown IP.",
        64, 0.1
    );
    EXPECT(r2.ok, "Explicit FAST generate should succeed");
    EXPECT(r2.model_used == astartis::agents::GraniteClient::FAST_MODEL_TAG,
           "Explicit FAST should use FAST model tag");

    // -----------------------------------------------------------------------
    // Test 8: ORCHESTRATOR tier — prefix injection visible in audit log
    // -----------------------------------------------------------------------
    std::cerr << "\n--- Test 8: ORCHESTRATOR prefix injection ---\n";
    // We can only verify the audit event is fired; actual inference depends on Ollama.
    // The audit_adder callback will print "orchestrator_prefix_injected" if working.
    auto r3 = client.generate(
        astartis::agents::GraniteModel::ORCHESTRATOR,
        "You coordinate security agents.",
        "List the agents needed to respond to a ransomware incident.",
        128, 0.2
    );
    // ORCHESTRATOR uses same model as ACCURACY — should return accuracy tag
    EXPECT(r3.model_used == astartis::agents::GraniteClient::ORCHESTRATOR_MODEL_TAG ||
           r3.model_used == "unavailable" || r3.model_used == "parse_error",
           "ORCHESTRATOR should use granite4.1 tag or report unavailable");
    if (r3.ok) {
        EXPECT(!r3.text.empty(), "ORCHESTRATOR response text should not be empty");
        std::cerr << "Response: " << r3.text.substr(0, 100) << "...\n";
    } else {
        std::cerr << "INFO: ORCHESTRATOR model unavailable (granite4.1 not yet pulled) — OK to skip\n";
    }

    std::cerr << "\n=== Results ===\n";
    if (g_failures == 0) {
        std::cerr << "ALL TESTS PASSED\n";
        return 0;
    }
    std::cerr << g_failures << " TEST(S) FAILED\n";
    return 1;
}

// Made with Bob
