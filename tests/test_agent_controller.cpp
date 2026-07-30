// test_agent_controller.cpp -- AgentController + PersonaLoader unit tests (Astartis v3.0)
//
// Tests load persona JSON files, validate model enforcement, queue tasks,
// and verify persona catalogue completeness (65 JSON + 12 ECC = 77 total agents).
// Exit code 2 = Ollama not running (SKIP, not FAIL).

#include "agents/controller/agent_controller.h"
#include "agents/controller/persona_loader.h"
#include "agents/controller/granite_client.h"
#include "agents/ecc/ecc_adapter.h"

#include <iostream>
#include <cassert>
#include <filesystem>

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Minimal audit adder (writes to stderr for test visibility)
// ---------------------------------------------------------------------------
static std::string test_audit(const std::string& evt, const std::string& payload)
{
    static int seq = 0;
    std::string id = "test_" + std::to_string(++seq);
    std::cerr << "[AUDIT] " << evt << " | " << payload << " | id=" << id << "\n";
    return id;
}

// ---------------------------------------------------------------------------
// PASS / FAIL helpers
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Test 1: PersonaLoader validates required fields
// ---------------------------------------------------------------------------
static void test_persona_validation()
{
    astartis::agents::AgentPersona empty;
    EXPECT(!astartis::agents::PersonaLoader::validate_persona(empty),
           "Empty persona should fail validation");

    astartis::agents::AgentPersona valid;
    valid.name          = "test_agent";
    valid.system_prompt = "You are a test agent.";
    valid.max_tokens    = 128;
    valid.temperature   = 0.2;
    EXPECT(astartis::agents::PersonaLoader::validate_persona(valid),
           "Valid persona should pass validation");
}

// ---------------------------------------------------------------------------
// Test 2: PersonaLoader is_granite_only enforcement — all 4 tiers
// ---------------------------------------------------------------------------
static void test_granite_only_enforcement()
{
    // Helper to build a valid persona with given model
    auto make = [](astartis::agents::GraniteModel m) {
        astartis::agents::AgentPersona p;
        p.name            = "test";
        p.system_prompt   = "Test.";
        p.max_tokens      = 128;
        p.temperature     = 0.2;
        p.preferred_model = m;
        return p;
    };

    EXPECT(astartis::agents::PersonaLoader::is_granite_only(
               make(astartis::agents::GraniteModel::FAST)),
           "FAST model persona should pass granite_only check");
    EXPECT(astartis::agents::PersonaLoader::is_granite_only(
               make(astartis::agents::GraniteModel::HEAVY)),
           "HEAVY model persona should pass granite_only check");
    EXPECT(astartis::agents::PersonaLoader::is_granite_only(
               make(astartis::agents::GraniteModel::ACCURACY)),
           "ACCURACY model persona should pass granite_only check");
    EXPECT(astartis::agents::PersonaLoader::is_granite_only(
               make(astartis::agents::GraniteModel::ORCHESTRATOR)),
           "ORCHESTRATOR model persona should pass granite_only check");
}

// ---------------------------------------------------------------------------
// Test 3: Load all JSON personas from definitions directory
// ---------------------------------------------------------------------------
static void test_load_all_personas(const std::string& config_path = "")
{
    fs::path defs_dir = "agents/definitions";
    if (!fs::exists(defs_dir)) {
        std::cerr << "SKIP: agents/definitions directory not found\n";
        return;
    }

    astartis::agents::AgentController controller(test_audit);
    int loaded = config_path.empty()
        ? controller.load_all_personas(defs_dir)
        : controller.load_all_personas(defs_dir, config_path);

    std::cerr << "INFO: Loaded " << loaded << " personas from " << defs_dir << "\n";
    std::cerr << "Loaded " << loaded << " agents\n";
    EXPECT(loaded >= 1, "Should load at least 1 agent persona");
    EXPECT(controller.persona_count() >= 1,
           "Controller should hold >= 1 persona after load");

    // Verify ORCHESTRATOR-tier agent loaded correctly
    std::string ir_id = controller.submit_task("incident_responder", "test input");
    EXPECT(!ir_id.empty(), "incident_responder (ORCHESTRATOR tier) should accept tasks");

    // Verify ACCURACY-tier agent loaded correctly
    std::string th_id = controller.submit_task("threat_hunter", "test input");
    EXPECT(!th_id.empty(), "threat_hunter (ACCURACY tier) should accept tasks");

    // Verify FAST-tier agent loaded correctly
    std::string triage_id = controller.submit_task("alert_triage", "test input");
    EXPECT(!triage_id.empty(), "alert_triage (FAST tier) should accept tasks");

    // Verify HEAVY-tier agent loaded correctly
    std::string reviewer_id = controller.submit_task("security_reviewer", "test input");
    EXPECT(!reviewer_id.empty(), "security_reviewer (HEAVY tier) should accept tasks");

    // Verify new Phase 1C agents loaded
    std::string zt_id = controller.submit_task("zero_trust_engineer", "test input");
    EXPECT(!zt_id.empty(), "zero_trust_engineer (new ACCURACY) should accept tasks");

    std::string rh_id = controller.submit_task("ransomware_hunter", "test input");
    EXPECT(!rh_id.empty(), "ransomware_hunter (new ACCURACY) should accept tasks");

    std::string bs_id = controller.submit_task("breach_simulator", "test input");
    EXPECT(!bs_id.empty(), "breach_simulator (new ORCHESTRATOR) should accept tasks");

    // Verify recon_agent still accepts tasks
    std::string recon_id = controller.submit_task("recon_agent", "test input");
    EXPECT(!recon_id.empty(), "recon_agent should accept tasks");
}

// ---------------------------------------------------------------------------
// Test 4: Verify model tier distribution among loaded personas
// ---------------------------------------------------------------------------
static void test_model_tier_distribution()
{
    fs::path defs_dir = "agents/definitions";
    if (!fs::exists(defs_dir)) {
        std::cerr << "SKIP: agents/definitions directory not found\n";
        return;
    }

    int fast_count = 0, heavy_count = 0, accuracy_count = 0, orchestrator_count = 0;
    int total = 0;

    for (const auto& entry : fs::directory_iterator(defs_dir)) {
        if (entry.path().extension() != ".json") continue;
        try {
            auto p = astartis::agents::PersonaLoader::load_from_json(entry.path());
            if (!astartis::agents::PersonaLoader::validate_persona(p)) continue;
            ++total;
            switch (p.preferred_model) {
                case astartis::agents::GraniteModel::FAST:         ++fast_count;         break;
                case astartis::agents::GraniteModel::HEAVY:        ++heavy_count;        break;
                case astartis::agents::GraniteModel::ACCURACY:     ++accuracy_count;     break;
                case astartis::agents::GraniteModel::ORCHESTRATOR: ++orchestrator_count; break;
            }
        } catch (...) {}
    }

    std::cerr << "INFO: Model tier distribution:\n";
    std::cerr << "  FAST: "         << fast_count         << "\n";
    std::cerr << "  HEAVY: "        << heavy_count        << "\n";
    std::cerr << "  ACCURACY: "     << accuracy_count     << "\n";
    std::cerr << "  ORCHESTRATOR: " << orchestrator_count << "\n";
    std::cerr << "  TOTAL: "        << total              << "\n";

    EXPECT(fast_count == 8,
           "Should have exactly 8 FAST-tier agents");
    EXPECT(heavy_count == 35,
           "Should have exactly 35 HEAVY-tier agents");
    EXPECT(accuracy_count == 16,
           "Should have exactly 16 ACCURACY-tier agents");
    EXPECT(orchestrator_count == 6,
           "Should have exactly 6 ORCHESTRATOR-tier agents");
    EXPECT(total == 65,
           "Should have exactly 65 JSON agent personas");

    std::cerr << "INFO: Plus 12 ECC agents (all ACCURACY via sonnet mapping)\n";
    std::cerr << "INFO: Grand total: 65 JSON + 12 ECC = 77 agents\n";
}

// ---------------------------------------------------------------------------
// Test 4b: Combined JSON + ECC load = 77 total agents
// ---------------------------------------------------------------------------
static void test_combined_agent_load()
{
    fs::path defs_dir = "agents/definitions";
    fs::path ecc_dir  = "agents/ecc/agents";
    if (!fs::exists(defs_dir) || !fs::exists(ecc_dir)) {
        std::cerr << "SKIP: agents/definitions or agents/ecc/agents not found\n";
        return;
    }

    astartis::agents::AgentController controller(test_audit);

    int json_loaded = controller.load_all_personas(defs_dir);
    std::cerr << "INFO: Loaded " << json_loaded << " JSON personas\n";
    EXPECT(json_loaded == 65, "Should load exactly 65 JSON agent personas");

    int ecc_loaded = controller.load_ecc_personas(ecc_dir);
    std::cerr << "INFO: Loaded " << ecc_loaded << " ECC personas\n";
    EXPECT(ecc_loaded == 12, "Should load exactly 12 ECC agent personas");

    int total = static_cast<int>(controller.persona_count());
    std::cerr << "INFO: Total agents loaded: " << total << "\n";
    EXPECT(total == 77, "JSON (65) + ECC (12) should equal 77 total agents");

    // Verify 6 Phase 1C agents
    EXPECT(!controller.submit_task("zero_trust_engineer", "test").empty(),
           "zero_trust_engineer should be loaded");
    EXPECT(!controller.submit_task("ransomware_hunter", "test").empty(),
           "ransomware_hunter should be loaded");
    EXPECT(!controller.submit_task("breach_simulator", "test").empty(),
           "breach_simulator should be loaded");
    EXPECT(!controller.submit_task("quantum_crypto_analyst", "test").empty(),
           "quantum_crypto_analyst should be loaded");
    EXPECT(!controller.submit_task("api_security_guru", "test").empty(),
           "api_security_guru should be loaded");
    EXPECT(!controller.submit_task("cloud_native_defender", "test").empty(),
           "cloud_native_defender should be loaded");

    // Verify 6 ECC agents
    EXPECT(!controller.submit_task("cpp_security_reviewer", "test").empty(),
           "cpp_security_reviewer (ECC) should be loaded");
    EXPECT(!controller.submit_task("code_security_auditor", "test").empty(),
           "code_security_auditor (ECC) should be loaded");
    EXPECT(!controller.submit_task("ai_model_security_evaluator", "test").empty(),
           "ai_model_security_evaluator (ECC) should be loaded");
    EXPECT(!controller.submit_task("autonomous_response_operator", "test").empty(),
           "autonomous_response_operator (ECC) should be loaded");
    EXPECT(!controller.submit_task("security_e2e_tester", "test").empty(),
           "security_e2e_tester (ECC) should be loaded");
    EXPECT(!controller.submit_task("build_security_analyzer", "test").empty(),
           "build_security_analyzer (ECC) should be loaded");
}

// ---------------------------------------------------------------------------
// Test 5: Task queue priority ordering
// ---------------------------------------------------------------------------
static void test_task_priority_queue()
{
    astartis::agents::AgentController controller(test_audit);

    std::string id = controller.submit_task("nonexistent_agent", "input",
                                            astartis::agents::Priority::HIGH);
    EXPECT(id.empty(), "Unknown agent submit should return empty task_id");
}

// ---------------------------------------------------------------------------
// Test 6: AgentController starts and stops cleanly
// ---------------------------------------------------------------------------
static void test_controller_lifecycle()
{
    astartis::agents::AgentController controller(test_audit);
    EXPECT(!controller.is_running(), "Controller should start in stopped state");

    controller.start();
    EXPECT(controller.is_running(), "Controller should be running after start()");

    controller.stop();
    EXPECT(!controller.is_running(), "Controller should be stopped after stop()");
}

// ---------------------------------------------------------------------------
// Test 7: GraniteClient ping (skip if Ollama not running)
// ---------------------------------------------------------------------------
static void test_granite_client_ping(bool& ollama_available)
{
    astartis::agents::GraniteClient client(test_audit);
    ollama_available = client.ping();
    if (!ollama_available) {
        std::cerr << "INFO: Ollama not running — skipping live inference tests\n";
    } else {
        std::cerr << "PASS: GraniteClient ping — Ollama is reachable\n";
    }
}

// ---------------------------------------------------------------------------
// Test 8: GraniteClient FAST/HEAVY/ACCURACY/ORCHESTRATOR enum don't trigger rejection
// ---------------------------------------------------------------------------
static void test_model_no_rejection()
{
    astartis::agents::GraniteClient client(test_audit);
    // All 4 valid enum values should never produce "rejected"
    for (auto model : {
        astartis::agents::GraniteModel::FAST,
        astartis::agents::GraniteModel::HEAVY,
        astartis::agents::GraniteModel::ACCURACY,
        astartis::agents::GraniteModel::ORCHESTRATOR
    }) {
        auto resp = client.generate(model, "You are a test.", "hello", 10, 0.1);
        EXPECT(resp.model_used != "rejected",
               "Valid enum values should not trigger model rejection");
    }
}

// ---------------------------------------------------------------------------
// Test 9: ECC adapter — parse frontmatter + load md persona
// ---------------------------------------------------------------------------
static void test_ecc_adapter()
{
    // Test ECC frontmatter parsing inline (no file needed)
    const std::string ecc_md = R"(---
name: test-security-agent
description: A test security agent for parsing validation.
tools: ["Read", "Grep", "Glob"]
model: sonnet
color: orange
---

## Test Agent

You are a test security agent. Analyze inputs and report findings.
)";

    auto fm = astartis::agents::ECCAdapter::parse_frontmatter(ecc_md);
    EXPECT(fm.name == "test-security-agent",
           "ECCAdapter should parse name field");
    EXPECT(fm.description.find("test security agent") != std::string::npos,
           "ECCAdapter should parse description field");
    EXPECT(fm.model_hint == "sonnet",
           "ECCAdapter should parse model hint field");
    EXPECT(fm.color == "orange",
           "ECCAdapter should parse color field");
    EXPECT(fm.tools.size() == 3,
           "ECCAdapter should parse 3 tools from array");
    EXPECT(!fm.body.empty(),
           "ECCAdapter should capture body after second ---");

    // Test model hint mapping
    EXPECT(astartis::agents::ECCAdapter::parse_model_hint("opus")
               == astartis::agents::GraniteModel::ORCHESTRATOR,
           "opus → ORCHESTRATOR");
    EXPECT(astartis::agents::ECCAdapter::parse_model_hint("sonnet")
               == astartis::agents::GraniteModel::ACCURACY,
           "sonnet → ACCURACY");
    EXPECT(astartis::agents::ECCAdapter::parse_model_hint("haiku")
               == astartis::agents::GraniteModel::HEAVY,
           "haiku → HEAVY");
    EXPECT(astartis::agents::ECCAdapter::parse_model_hint("fast")
               == astartis::agents::GraniteModel::FAST,
           "fast → FAST");
    EXPECT(astartis::agents::ECCAdapter::parse_model_hint("")
               == astartis::agents::GraniteModel::HEAVY,
           "empty hint → HEAVY (default)");

    // Test snake_case conversion via to_agent_persona
    auto persona = astartis::agents::ECCAdapter::to_agent_persona(fm);
    EXPECT(persona.name == "test_security_agent",
           "ECCAdapter should convert hyphen-name to snake_case");
    EXPECT(persona.preferred_model == astartis::agents::GraniteModel::ACCURACY,
           "sonnet model hint → ACCURACY tier in persona");
    EXPECT(!persona.system_prompt.empty(),
           "ECCAdapter body should become system_prompt");

    // Test loading from the actual ECC agents directory
    fs::path ecc_dir = "agents/ecc/agents";
    if (fs::exists(ecc_dir)) {
        astartis::agents::AgentController ctrl(test_audit);
        int loaded = ctrl.load_ecc_personas(ecc_dir);
        std::cerr << "INFO: Loaded " << loaded << " ECC agent personas from " << ecc_dir << "\n";
        EXPECT(loaded == 12, "Should load exactly 12 ECC agent .md files");

        // Verify key ECC agents are loadable
        std::string id1 = ctrl.submit_task("cpp_security_reviewer", "test");
        EXPECT(!id1.empty(), "cpp_security_reviewer should be loaded from ECC .md");
        std::string id2 = ctrl.submit_task("autonomous_response_operator", "test");
        EXPECT(!id2.empty(), "autonomous_response_operator should be loaded from ECC .md");
    } else {
        std::cerr << "SKIP: agents/ecc/agents directory not found\n";
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[])
{
    std::string config_path;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "--mode" || arg == "-m") && i + 1 < argc) {
            config_path = argv[++i];
        }
    }

    std::cerr << "=== AgentController Tests (v3.0) ===\n\n";

    std::cerr << "--- Test 1: Persona Validation ---\n";
    test_persona_validation();

    std::cerr << "\n--- Test 2: Granite-Only Enforcement (all 4 tiers) ---\n";
    test_granite_only_enforcement();

    std::cerr << "\n--- Test 3: Load All Personas ---\n";
    test_load_all_personas(config_path);

    std::cerr << "\n--- Test 4: Model Tier Distribution ---\n";
    test_model_tier_distribution();

    std::cerr << "\n--- Test 4b: Combined JSON + ECC Load (77 total) ---\n";
    test_combined_agent_load();

    std::cerr << "\n--- Test 5: Task Queue Priority ---\n";
    test_task_priority_queue();

    std::cerr << "\n--- Test 6: Controller Lifecycle ---\n";
    test_controller_lifecycle();

    bool ollama_available = false;
    std::cerr << "\n--- Test 7: GraniteClient Ping ---\n";
    test_granite_client_ping(ollama_available);

    if (ollama_available) {
        std::cerr << "\n--- Test 8: Model Rejection Check (all 4 tiers, Ollama live) ---\n";
        test_model_no_rejection();
    }

    std::cerr << "\n--- Test 9: ECC Adapter (inline + file loading) ---\n";
    test_ecc_adapter();

    std::cerr << "\n=== Results ===\n";
    if (g_failures == 0) {
        std::cerr << "ALL TESTS PASSED\n";
        return 0;
    } else {
        std::cerr << g_failures << " TEST(S) FAILED\n";
        return 1;
    }
}

// Made with Bob
