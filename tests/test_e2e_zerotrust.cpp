// test_e2e_zerotrust.cpp -- AI agent → ZeroTrustEngine deny (Phase 2C)
//
// Scenario: zero_trust_engineer (ACCURACY) analyzes a non-compliant device.
// ActionDispatcher parses output and calls ZeroTrustEngine::evaluate()
// which returns DENY for the flagged access context.
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
    std::cerr << "=== E2E Zero Trust Deny Test ===\n\n";

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
    std::string temp_qtn = "C:\\Temp\\AstartisZTTest\\Quarantine";
    fs::create_directories(temp_qtn);
    astartis::firewall::FirewallBlocker fw(audit_fn, 60);
    astartis::quarantine::Quarantine    qtn(temp_qtn, audit_fn);
    astartis::active_response::ActiveResponse ar(audit_fn);
    astartis::zerotrust::ZeroTrustEngine zt(audit_fn);
    astartis::ActionDispatcher dispatcher(fw, qtn, ar, zt, audit_fn);

    // --- Step 1: Load zero_trust_engineer persona ---
    std::cerr << "--- Step 1: Load zero_trust_engineer (ACCURACY) ---\n";
    fs::path persona_path = "agents/definitions/zero_trust_engineer.json";
    if (!fs::exists(persona_path)) {
        std::cerr << "FAIL: " << persona_path << " not found\n";
        return 1;
    }
    auto persona = astartis::agents::PersonaLoader::load_from_json(persona_path);
    EXPECT(persona.preferred_model == astartis::agents::GraniteModel::ACCURACY,
           "zero_trust_engineer must be ACCURACY tier");
    EXPECT(astartis::PolicyEngine::can_zerotrust_deny("zero_trust_engineer"),
           "zero_trust_engineer must be authorized for ZT deny");

    // --- Step 2: Direct ZeroTrust deny test via ActionDispatcher ---
    // We test the ActionDispatcher→ZeroTrust path directly first (no model needed)
    std::cerr << "\n--- Step 2: Direct ActionDispatcher → ZeroTrust deny ---\n";
    const std::string test_mac = "aa:bb:cc:dd:ee:ff";
    std::string explicit_json =
        R"({"zt_score": 0, "principle_gaps": ["trust_implicit"], )"
        R"("recovery_checklist": ["Revoke access for device aa:bb:cc:dd:ee:ff on VLAN_200", )"
        R"("Review IAM policies"]})";

    auto dr = dispatcher.dispatch("zero_trust_engineer", explicit_json);
    std::cerr << "Dispatch result: action_taken=" << dr.action_taken
              << " type=" << dr.action_type
              << " target=" << dr.target << "\n";

    // --- Step 3: Verify ZeroTrust DENY via direct engine call ---
    std::cerr << "\n--- Step 3: ZeroTrustEngine direct deny for untrusted context ---\n";
    astartis::zerotrust::AccessContext ctx;
    ctx.user_id            = "unknown_user";
    ctx.device_id          = test_mac;
    ctx.source_ip          = "0.0.0.0";     // Unknown IP → low trust
    ctx.destination_ip     = "10.0.99.1";  // Management zone
    ctx.requested_resource = "/management/secrets";
    ctx.ssid_name          = "PUBLIC";      // Wrong SSID for management zone
    ctx.trust_score        = 0;             // Engine will compute

    auto decision = zt.evaluate(ctx);
    std::cerr << "ZeroTrust decision: " << astartis::zerotrust::ZeroTrustEngine::decision_str(decision) << "\n";
    EXPECT(decision == astartis::zerotrust::TrustDecision::DENY ||
           decision == astartis::zerotrust::TrustDecision::QUARANTINE ||
           decision == astartis::zerotrust::TrustDecision::MFA_REQUIRED,
           "Untrusted device accessing management zone should be DENY/QUARANTINE/MFA");

    // --- Step 4: Submit task to agent controller ---
    std::cerr << "\n--- Step 4: Submit task to zero_trust_engineer via AgentController ---\n";
    astartis::agents::AgentController controller(audit_fn);
    controller.set_action_dispatcher(&dispatcher);
    controller.load_all_personas("agents/definitions");

    const std::string task_input =
        "Non-compliant device with MAC aa:bb:cc:dd:ee:ff is attempting to access VLAN_200 "
        "(enterprise management network). Device has no AV, no disk encryption, "
        "connecting from PUBLIC SSID. Evaluate Zero Trust compliance and provide "
        "recovery_checklist with device MAC aa:bb:cc:dd:ee:ff and VLAN info.";

    controller.start();
    std::string task_id = controller.submit_task("zero_trust_engineer", task_input,
                                                  astartis::agents::Priority::HIGH);
    EXPECT(!task_id.empty(), "submit_task should return task_id");

    // Wait for ACCURACY inference
    std::cerr << "Waiting for ACCURACY inference (up to 130s)...\n";
    for (int i = 0; i < 130; ++i) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        auto statuses = controller.get_statuses();
        for (const auto& st : statuses) {
            if (st.name == "zero_trust_engineer" &&
                (st.state == astartis::agents::AgentState::COMPLETED ||
                 st.state == astartis::agents::AgentState::FAILED)) {
                goto task_done;
            }
        }
        if (i % 20 == 19) std::cerr << "  Waiting... " << (i + 1) << "s\n";
    }
    task_done:
    controller.stop();

    // --- Step 5: Verify audit chain ---
    std::cerr << "\n--- Step 5: Verify audit chain ---\n";
    auto entries = audit.get_all_entries();
    bool has_zt_entry = false;
    bool has_decision  = false;
    for (const auto& e : entries) {
        if (e.event_type == "action_dispatcher_zerotrust" ||
            e.event_type == "zerotrust_decision") {
            has_zt_entry = true;
            std::cerr << "Audit: " << e.event_type << " | "
                      << e.payload.substr(0, 80) << "\n";
        }
        if (e.event_type == "zerotrust_decision") has_decision = true;
    }
    EXPECT(has_zt_entry || has_decision, "Audit chain should have ZeroTrust entry");

    // Cleanup
    std::error_code ec;
    fs::remove_all("C:\\Temp\\AstartisZTTest", ec);

    std::cerr << "\n=== Results ===\n";
    if (g_failures == 0) {
        std::cerr << "ALL TESTS PASSED\n";
        return 0;
    }
    std::cerr << g_failures << " TEST(S) FAILED\n";
    return 1;
}

// Made with Bob
