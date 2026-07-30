#ifdef NDEBUG
#undef NDEBUG   // force assert() active in Release builds for test executables
#endif
#include <iostream>
#include <cassert>
#include <string>

#include "../core/audit_chain/audit_chain.h"
#include "../core/worm_lock/worm_lock.h"
#include "../core/threat_level/threat_level.h"
#include "../core/rule_engine/rule_engine.h"
#include "../core/packet_sensor/packet_sensor.h"

using namespace astartis::audit;
using namespace astartis::worm;
using namespace astartis::threat;
using namespace astartis::rules;
using namespace astartis::sensor;

// ---------------------------------------------------------------------------
// Full-stack fixture
// ---------------------------------------------------------------------------
struct RuleFixture {
    AuditChain         chain;
    WormLock           worm;
    ThreatStateMachine tsm;
    RuleEngine         engine;

    RuleFixture()
        : worm([this](const std::string& et, const std::string& p) {
               return chain.add_entry(et, p);
           })
        , tsm(
            [this](const std::string& et, const std::string& p) {
                return chain.add_entry(et, p);
            },
            [this](const std::string& reason) {
                worm.trigger_lockdown(reason);
            })
        , engine(
            [this](const std::string& et, const std::string& p) {
                return chain.add_entry(et, p);
            },
            tsm,
            [this](const std::string& reason) {
                worm.trigger_lockdown(reason);
            },
            [this]() {
                return worm.is_locked();
            })
    {}
};

// ---------------------------------------------------------------------------
// Test 1: RULE-01 anomalous packet window independently triggers WORM
//         (no full breach required — this is the key standalone trigger)
// ---------------------------------------------------------------------------
void test_rule01_anomalous_packet_triggers_worm_standalone() {
    std::cout << "\n=== Test 1: RULE-01 Anomalous Packet -> WORM (Standalone) ===" << std::endl;

    RuleFixture f;

    // Confirm starting state
    assert(!f.worm.is_locked());
    assert(f.tsm.current_tier() == ThreatTier::LOW);

    // Build an anomalous window (above 7.2 bits mean entropy)
    EntropyWindow w;
    w.window_index      = 1;
    w.packet_count      = 50;
    w.mean_entropy_bits = 7.5;
    w.max_entropy_bits  = 7.9;
    w.min_entropy_bits  = 7.1;
    w.threat_score      = 93;   // (7.5/8)*100 ≈ 93
    w.anomalous         = true; // <-- this is the flag RULE-01 watches
    w.synthetic         = false;
    w.adapter_name      = "Ethernet0";

    RuleResult r = f.engine.evaluate_packet_window(w);

    std::cout << "  Rule fired:      " << (r.fired ? "YES" : "NO") << std::endl;
    std::cout << "  WORM triggered:  " << (r.worm_triggered ? "YES" : "NO") << std::endl;
    std::cout << "  Action taken:    " << r.action_taken << std::endl;
    std::cout << "  Tier after:      " << tier_name(f.tsm.current_tier()) << std::endl;
    std::cout << "  WormLock state:  " << (f.worm.is_locked() ? "LOCKED" : "NORMAL") << std::endl;

    assert(r.fired);
    assert(f.tsm.current_tier() == ThreatTier::CRITICAL);
    assert(f.worm.is_locked());   // WORM engaged purely by the anomalous packet — no breach
    assert(f.engine.total_fires() == 1);
}

// ---------------------------------------------------------------------------
// Test 2: RULE-01 non-anomalous window does NOT fire rule or trigger WORM
// ---------------------------------------------------------------------------
void test_rule01_normal_window_no_trigger() {
    std::cout << "\n=== Test 2: RULE-01 Normal Window — No Trigger ===" << std::endl;

    RuleFixture f;

    EntropyWindow w;
    w.window_index      = 1;
    w.packet_count      = 50;
    w.mean_entropy_bits = 4.2;
    w.max_entropy_bits  = 5.1;
    w.min_entropy_bits  = 3.0;
    w.threat_score      = 52;
    w.anomalous         = false;  // normal traffic
    w.synthetic         = false;
    w.adapter_name      = "Ethernet0";

    RuleResult r = f.engine.evaluate_packet_window(w);

    std::cout << "  Rule fired:    " << (r.fired ? "YES" : "NO") << std::endl;
    std::cout << "  WORM locked:   " << (f.worm.is_locked() ? "YES" : "NO") << std::endl;

    assert(!r.fired);
    assert(!r.worm_triggered);
    assert(!f.worm.is_locked());
    // Tier may have changed from score (52 -> HIGH) but WORM must not be locked
    assert(f.engine.total_fires() == 0);
}

// ---------------------------------------------------------------------------
// Test 3: RULE-02 drives tier transition via raw threat score
// ---------------------------------------------------------------------------
void test_rule02_score_drives_tier() {
    std::cout << "\n=== Test 3: RULE-02 Raw Threat Score Drives Tier Transition ===" << std::endl;

    RuleFixture f;

    assert(f.tsm.current_tier() == ThreatTier::LOW);

    RuleResult r = f.engine.evaluate_threat_score(35, "http_anomaly_detector");
    std::cout << "  score=35: tier=" << tier_name(f.tsm.current_tier())
              << "  fired=" << r.fired << std::endl;
    assert(r.fired);
    assert(f.tsm.current_tier() == ThreatTier::MEDIUM);

    r = f.engine.evaluate_threat_score(60, "entropy_detector");
    std::cout << "  score=60: tier=" << tier_name(f.tsm.current_tier())
              << "  fired=" << r.fired << std::endl;
    assert(r.fired);
    assert(f.tsm.current_tier() == ThreatTier::HIGH);
}

// ---------------------------------------------------------------------------
// Test 4: RULE-03 auth failure spike forces HIGH, then CRITICAL with WORM
// ---------------------------------------------------------------------------
void test_rule03_auth_failures() {
    std::cout << "\n=== Test 4: RULE-03 Auth Failure Spike ===" << std::endl;

    RuleFixture f;

    // Below both thresholds — no action
    RuleResult r0 = f.engine.evaluate_auth_failures(3, "login_service");
    assert(!r0.fired);
    std::cout << "  failures=3: no action (below threshold)" << std::endl;

    // Above RULE03_FAILURE_THRESHOLD (5) but below RULE03_CRITICAL_THRESHOLD (10)
    RuleResult r1 = f.engine.evaluate_auth_failures(7, "login_service");
    assert(r1.fired);
    assert(f.tsm.current_tier() == ThreatTier::HIGH);
    assert(!f.worm.is_locked());
    std::cout << "  failures=7: forced HIGH — " << r1.action_taken << std::endl;

    // Above RULE03_CRITICAL_THRESHOLD (10) — forces CRITICAL + WORM
    RuleFixture f2;
    RuleResult r2 = f2.engine.evaluate_auth_failures(12, "login_service");
    assert(r2.fired);
    assert(f2.tsm.current_tier() == ThreatTier::CRITICAL);
    assert(f2.worm.is_locked());
    std::cout << "  failures=12: forced CRITICAL + WORM — " << r2.action_taken << std::endl;
}

// ---------------------------------------------------------------------------
// Test 5: Rule engine correctly drives a tier transition (spec requirement)
// ---------------------------------------------------------------------------
void test_rule_engine_drives_tier_transition() {
    std::cout << "\n=== Test 5: Rule Engine Drives Tier Transition ===" << std::endl;

    RuleFixture f;

    assert(f.tsm.current_tier() == ThreatTier::LOW);

    // RULE-02 with score=55 -> HIGH
    f.engine.evaluate_threat_score(55, "combined_sensor");
    std::cout << "  evaluate_threat_score(55) -> tier="
              << tier_name(f.tsm.current_tier()) << std::endl;
    assert(f.tsm.current_tier() == ThreatTier::HIGH);
}

// ---------------------------------------------------------------------------
// Test 6: RULE-01 fires + audit chain records the rule event
// ---------------------------------------------------------------------------
void test_rule01_audit_entry_written() {
    std::cout << "\n=== Test 6: RULE-01 Writes Audit Entry ===" << std::endl;

    RuleFixture f;

    size_t before = f.chain.get_chain_length();

    EntropyWindow w;
    w.window_index      = 2;
    w.packet_count      = 50;
    w.mean_entropy_bits = 7.6;
    w.max_entropy_bits  = 7.9;
    w.min_entropy_bits  = 7.3;
    w.threat_score      = 95;
    w.anomalous         = true;
    w.synthetic         = false;
    w.adapter_name      = "Ethernet0";

    f.engine.evaluate_packet_window(w);

    size_t after = f.chain.get_chain_length();
    std::cout << "  Audit entries before: " << before << std::endl;
    std::cout << "  Audit entries after:  " << after  << std::endl;
    assert(after > before);  // at least one new entry was written

    auto v = f.chain.verify_chain();
    assert(v.is_valid);
    std::cout << "  Chain integrity: valid" << std::endl;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "ASTARTIS DETERMINISTIC RULE ENGINE TEST " << std::endl;
    std::cout << "Step 7: Rule Engine + Tier + WORM Wiring" << std::endl;
    std::cout << "========================================" << std::endl;

    try {
        test_rule01_anomalous_packet_triggers_worm_standalone();
        test_rule01_normal_window_no_trigger();
        test_rule02_score_drives_tier();
        test_rule03_auth_failures();
        test_rule_engine_drives_tier_transition();
        test_rule01_audit_entry_written();

        std::cout << "\n========================================" << std::endl;
        std::cout << "ALL TESTS PASSED"                         << std::endl;
        std::cout << "Rule engine working!"                     << std::endl;
        std::cout << "========================================\n" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\nTEST FAILED: " << e.what() << std::endl;
        return 1;
    }
}

// Made with Bob
