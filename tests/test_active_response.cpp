#ifdef NDEBUG
#undef NDEBUG
#endif
#include <iostream>
#include <cassert>
#include <string>

#include "../core/audit_chain/audit_chain.h"
#include "../core/active_response/active_response.h"

using namespace astartis::audit;
using namespace astartis::active_response;

// ---------------------------------------------------------------------------
// Test 1: Progressive throttling ??? all four response tiers
// ---------------------------------------------------------------------------
void test_progressive_throttling() {
    std::cout << "\n=== Test 1: Progressive Throttling ??? All Four Response Tiers ===" << std::endl;

    AuditChain chain;
    ActiveResponse ar([&chain](const std::string& et, const std::string& p) {
        return chain.add_entry(et, p);
    });

    std::string session = "attacker-session-Z";
    std::string resource = "decoy/assets/financial-projections-2024.xlsx";

    // interactions 1, 2 ??? tier 0 (full response)
    auto ev1 = ar.serve(session, resource);
    assert(ev1.response_tier == 0);
    std::cout << "  interaction 1 ??? tier " << ev1.response_tier << " (full)" << std::endl;

    auto ev2 = ar.serve(session, resource);
    assert(ev2.response_tier == 0);
    std::cout << "  interaction 2 ??? tier " << ev2.response_tier << " (full)" << std::endl;

    // interactions 3???5 ??? tier 1 (slightly degraded)
    auto ev3 = ar.serve(session, resource);
    assert(ev3.response_tier == 1);
    std::cout << "  interaction 3 ??? tier " << ev3.response_tier << " (degraded)" << std::endl;

    ar.serve(session, resource); ar.serve(session, resource);  // 4, 5

    // interactions 6???9 ??? tier 2 (heavily degraded)
    auto ev6 = ar.serve(session, resource);
    assert(ev6.response_tier == 2);
    std::cout << "  interaction 6 ??? tier " << ev6.response_tier << " (heavily degraded)" << std::endl;

    ar.serve(session, resource); ar.serve(session, resource); ar.serve(session, resource); // 7,8,9

    // interaction 10+ ??? tier 3 (honeypot loop)
    auto ev10 = ar.serve(session, resource);
    assert(ev10.response_tier == 3);
    std::cout << "  interaction 10 ??? tier " << ev10.response_tier << " (honeypot loop)" << std::endl;

    assert(ar.session_interaction_count(session) == 10);

    // Every interaction wrote to the audit chain
    size_t served_entries = 0;
    for (const auto& e : chain.get_all_entries())
        if (e.event_type == "active_response_served") ++served_entries;
    assert(served_entries == 10);
    std::cout << "  Audit entries (active_response_served): " << served_entries << std::endl;
}

// ---------------------------------------------------------------------------
// Test 2: IOC correlation match logged in forensic log and audit chain
// ---------------------------------------------------------------------------
void test_ioc_correlation_match() {
    std::cout << "\n=== Test 2: IOC Correlation Match Logged ===" << std::endl;

    AuditChain chain;
    ActiveResponse ar([&chain](const std::string& et, const std::string& p) {
        return chain.add_entry(et, p);
    });

    // Known IOC ??? from the sample dataset
    std::string known_ip = "45.142.212.100";

    auto ev = ar.serve("attacker-session-X",
                       "decoy/server-02/opt/app/config.json",
                       known_ip);

    assert(ev.ioc_match);
    assert(ev.ioc_indicator == known_ip);
    std::cout << "  IOC match: " << ev.ioc_indicator << std::endl;

    // Audit chain must have an ioc_correlation_match entry
    bool found_ioc = false;
    for (const auto& e : chain.get_all_entries()) {
        if (e.event_type == "ioc_correlation_match") {
            found_ioc = true;
            std::cout << "  Audit entry: [" << e.event_type << "] "
                      << e.payload.substr(0, 60) << "..." << std::endl;
        }
    }
    assert(found_ioc);
}

// ---------------------------------------------------------------------------
// Test 3: Standalone check_ioc()
// ---------------------------------------------------------------------------
void test_standalone_ioc_check() {
    std::cout << "\n=== Test 3: Standalone check_ioc() ===" << std::endl;

    AuditChain chain;
    ActiveResponse ar([&chain](const std::string& et, const std::string& p) {
        return chain.add_entry(et, p);
    });

    // Hit
    auto m1 = ar.check_ioc("194.165.16.11");
    assert(m1.matched);
    assert(m1.entry.type == IocType::IOC_IP);
    std::cout << "  194.165.16.11 matched: " << m1.entry.description << std::endl;

    // Known internal pivot IP
    auto m2 = ar.check_ioc("10.0.0.55");
    assert(m2.matched);
    std::cout << "  10.0.0.55 matched: " << m2.entry.description << std::endl;

    // Miss
    auto m3 = ar.check_ioc("8.8.8.8");
    assert(!m3.matched);
    std::cout << "  8.8.8.8: no match (correct)" << std::endl;

    // Both hits wrote ioc_correlation_match audit entries
    size_t ioc_entries = 0;
    for (const auto& e : chain.get_all_entries())
        if (e.event_type == "ioc_correlation_match") ++ioc_entries;
    assert(ioc_entries == 2);
    std::cout << "  ioc_correlation_match audit entries: " << ioc_entries << std::endl;
}

// ---------------------------------------------------------------------------
// Test 4: Simulated intruder session ??? full progression + forensic log
// ---------------------------------------------------------------------------
void test_simulated_intruder_session() {
    std::cout << "\n=== Test 4: Simulated Intruder Session ??? Full Forensic Log ===" << std::endl;

    AuditChain chain;
    ActiveResponse ar([&chain](const std::string& et, const std::string& p) {
        return chain.add_entry(et, p);
    });

    std::string sid = "intruder-001";

    // Simulate 6-step intruder session hitting different resources
    std::vector<std::pair<std::string, std::string>> steps = {
        {"decoy/credentials/.aws/credentials",             "185.220.101.45"},  // known IOC
        {"decoy/assets/customer-pii-export.csv",           ""},
        {"decoy/server-02/etc/hostname",                   ""},
        {"decoy/server-02/var/log/auth.log",               "45.142.212.100"},  // known IOC
        {"decoy/assets/ip-source-code-archive.tar.gz",     ""},
        {"decoy/server-02/opt/app/config.json",            ""},
    };

    for (const auto& step : steps) {
        auto ev = ar.serve(sid, step.first, step.second);
        std::cout << "  step " << ar.session_interaction_count(sid)
                  << " [tier " << ev.response_tier << "]"
                  << " resource=" << step.first.substr(0, 35)
                  << (ev.ioc_match ? " [IOC HIT]" : "") << std::endl;
    }

    auto log = ar.forensic_log();
    assert(log.size() == 6);

    // Tier progression must be correct
    assert(log[0].response_tier == 0);  // interaction 1
    assert(log[1].response_tier == 0);  // interaction 2
    assert(log[2].response_tier == 1);  // interaction 3
    assert(log[5].response_tier == 2);  // interaction 6

    // Two IOC hits (step 1 and step 4)
    size_t ioc_hits = 0;
    for (const auto& ev : log) if (ev.ioc_match) ++ioc_hits;
    assert(ioc_hits == 2);
    std::cout << "  Total IOC hits in session: " << ioc_hits << std::endl;
    std::cout << "  Forensic log entries: " << log.size() << std::endl;

    auto v = chain.verify_chain();
    assert(v.is_valid);
    std::cout << "  Audit chain integrity: valid" << std::endl;
}

// ---------------------------------------------------------------------------
// Test 5: Multiple concurrent sessions ??? counters are independent
// ---------------------------------------------------------------------------
void test_multiple_sessions_independent() {
    std::cout << "\n=== Test 5: Multiple Sessions Are Independent ===" << std::endl;

    AuditChain chain;
    ActiveResponse ar([&chain](const std::string& et, const std::string& p) {
        return chain.add_entry(et, p);
    });

    std::string r = "decoy/assets/financial-projections-2024.xlsx";

    // Session A gets 10 interactions ??? tier 3
    for (int i = 0; i < 10; i++) ar.serve("session-A", r);
    assert(ar.session_interaction_count("session-A") == 10);

    // Session B fresh ??? tier 0
    auto evB = ar.serve("session-B", r);
    assert(evB.response_tier == 0);
    assert(ar.session_interaction_count("session-B") == 1);

    std::cout << "  session-A interaction count: " << ar.session_interaction_count("session-A")
              << " (tier 3)" << std::endl;
    std::cout << "  session-B interaction count: " << ar.session_interaction_count("session-B")
              << " (tier 0)" << std::endl;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "ASTARTIS ACTIVE RESPONSE TEST           " << std::endl;
    std::cout << "Step 11: DIBANET Layer 3                " << std::endl;
    std::cout << "========================================" << std::endl;

    try {
        test_progressive_throttling();
        test_ioc_correlation_match();
        test_standalone_ioc_check();
        test_simulated_intruder_session();
        test_multiple_sessions_independent();

        std::cout << "\n========================================" << std::endl;
        std::cout << "ALL TESTS PASSED"                         << std::endl;
        std::cout << "Active response layer working!"           << std::endl;
        std::cout << "========================================\n" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\nTEST FAILED: " << e.what() << std::endl;
        return 1;
    }
}

// Made with Bob

