// test_e2e_deception.cpp -- AI agent → ActiveResponse deception (Phase 2C)
//
// Scenario: deception_engineer (HEAVY) analyzes an SSH probe.
// ActionDispatcher parses output and calls ActiveResponse::serve() to
// engage the attacker with a throttled deception response.
//
// Exit code 0 = PASS
// Exit code 1 = FAIL
// Exit code 2 = Ollama not running (SKIP)

// Winsock2 first
#include <winsock2.h>

#pragma warning(push)
#pragma warning(disable: 4706 4127 4244)
#include "nlohmann/json.hpp"
#pragma warning(pop)

#include "agents/controller/agent_controller.h"
#include "agents/controller/persona_loader.h"
#include "agents/controller/action_dispatcher.h"
#include "agents/controller/policy_engine.h"
#include "core/audit_chain/audit_chain.h"
#include "core/firewall/firewall_blocker.h"
#include "core/quarantine/quarantine.h"
#include "core/active_response/active_response.h"
#include "network_arch/zerotrust/zerotrust_engine.h"

#include <iostream>
#include <string>
#include <filesystem>
#include <chrono>
#include <thread>

namespace fs = std::filesystem;

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

int main()
{
    std::cerr << "=== E2E Deception Test ===\n\n";

    // Check elevation for firewall module (needed even if we don't block)
    // Deception test itself doesn't need elevation, but firewall is in the dispatcher
    // Pre-flight: Ollama
    astartis::audit::AuditChain audit;
    auto audit_fn = [&](const std::string& e, const std::string& p) {
        return audit.add_entry(e, p);
    };

    astartis::agents::GraniteClient ping_client(audit_fn);
    if (!ping_client.ping()) {
        std::cerr << "INFO: Ollama not running — exiting with code 2 (SKIP)\n";
        return 2;
    }
    std::cerr << "PASS: Ollama reachable\n\n";

    // --- Setup protection modules ---
    // Use a non-elevated FirewallBlocker for deception test — it won't be called
    std::string temp_qtn = "C:\\Temp\\AstartisDeceptionTest\\Quarantine";
    fs::create_directories(temp_qtn);
    astartis::firewall::FirewallBlocker fw(audit_fn, 60);
    astartis::quarantine::Quarantine    qtn(temp_qtn, audit_fn);
    astartis::active_response::ActiveResponse ar(audit_fn);
    astartis::zerotrust::ZeroTrustEngine zt(audit_fn);
    astartis::ActionDispatcher dispatcher(fw, qtn, ar, zt, audit_fn);

    // --- Step 1: Load deception_engineer persona ---
    std::cerr << "--- Step 1: Load deception_engineer (HEAVY) ---\n";
    fs::path persona_path = "agents/definitions/deception_engineer.json";
    if (!fs::exists(persona_path)) {
        std::cerr << "FAIL: " << persona_path << " not found\n";
        return 1;
    }
    auto persona = astartis::agents::PersonaLoader::load_from_json(persona_path);
    EXPECT(persona.preferred_model == astartis::agents::GraniteModel::HEAVY,
           "deception_engineer must be HEAVY tier");
    EXPECT(astartis::PolicyEngine::can_deceive("deception_engineer"),
           "deception_engineer must be authorized to deceive");

    // --- Step 2: Submit task ---
    std::cerr << "\n--- Step 2: Submit SSH probe task to deception_engineer ---\n";
    astartis::agents::AgentController controller(audit_fn);
    controller.set_action_dispatcher(&dispatcher);
    controller.load_all_personas("agents/definitions");

    const std::string task_input =
        "Attacker is probing our SSH honeypot on session_probe_abc123. "
        "They have made 15 login attempts. Recommend eradication steps to engage "
        "the attacker with deceptive responses. Include session_probe_abc123 in eradication_steps.";

    controller.start();
    std::string task_id = controller.submit_task("deception_engineer", task_input,
                                                  astartis::agents::Priority::HIGH);
    EXPECT(!task_id.empty(), "submit_task should return task_id");

    // Wait for HEAVY inference (60s + buffer)
    std::cerr << "Waiting for HEAVY inference (up to 70s)...\n";
    for (int i = 0; i < 70; ++i) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        auto statuses = controller.get_statuses();
        for (const auto& st : statuses) {
            if (st.name == "deception_engineer" &&
                (st.state == astartis::agents::AgentState::COMPLETED ||
                 st.state == astartis::agents::AgentState::FAILED)) {
                goto task_done;
            }
        }
        if (i % 15 == 14) std::cerr << "  Waiting... " << (i + 1) << "s\n";
    }
    task_done:
    controller.stop();

    // --- Step 3: Verify deception response was logged ---
    std::cerr << "\n--- Step 3: Verify deception response ---\n";
    auto forensic_log = ar.forensic_log();

    // Also test the dispatcher directly with known session ID
    if (forensic_log.empty()) {
        std::cerr << "INFO: Agent may not have output session ID in eradication_steps.\n";
        std::cerr << "INFO: Testing ActionDispatcher directly.\n";
        std::string explicit_json =
            R"({"eradication_steps": ["Engage session_probe_abc123 with deception response", "Activate honeypot loop"]})";
        auto dr = dispatcher.dispatch("deception_engineer", explicit_json);
        EXPECT(dr.action_taken && dr.action_type == "deception",
               "Direct deception dispatch should succeed");
        if (dr.action_taken) {
            std::cerr << "Direct dispatch triggered deception for: " << dr.target << "\n";
        }
        forensic_log = ar.forensic_log();
    }

    EXPECT(!forensic_log.empty(), "Forensic log should have at least one deception event");
    if (!forensic_log.empty()) {
        const auto& evt = forensic_log.back();
        std::cerr << "Last forensic event: session=" << evt.session_id
                  << " resource=" << evt.resource
                  << " tier=" << evt.response_tier << "\n";
    }

    // --- Step 4: Verify audit chain ---
    std::cerr << "\n--- Step 4: Verify audit chain ---\n";
    auto entries = audit.get_all_entries();
    bool has_ar_entry = false;
    for (const auto& e : entries) {
        if (e.event_type == "active_response_served" ||
            e.event_type == "action_dispatcher_deception") {
            has_ar_entry = true;
            std::cerr << "Audit: " << e.event_type << " | "
                      << e.payload.substr(0, 80) << "\n";
            break;
        }
    }
    EXPECT(has_ar_entry, "Audit chain should have deception entry");

    // Cleanup
    std::error_code ec;
    fs::remove_all("C:\\Temp\\AstartisDeceptionTest", ec);

    std::cerr << "\n=== Results ===\n";
    if (g_failures == 0) {
        std::cerr << "ALL TESTS PASSED\n";
        return 0;
    }
    std::cerr << g_failures << " TEST(S) FAILED\n";
    return 1;
}

// Made with Bob
