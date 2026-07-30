#ifdef NDEBUG
#undef NDEBUG   // force assert() active in Release builds for test executables
#endif
#include <iostream>
#include <cassert>
#include <string>

#include "../core/audit_chain/audit_chain.h"
#include "../core/worm_lock/worm_lock.h"
#include "../core/threat_level/threat_level.h"

using namespace astartis::audit;
using namespace astartis::worm;
using namespace astartis::threat;

// ---------------------------------------------------------------------------
// Fixture: AuditChain + WormLock + ThreatStateMachine all wired together
// ---------------------------------------------------------------------------
struct ThreatFixture {
    AuditChain         chain;
    WormLock           worm;
    ThreatStateMachine tsm;

    ThreatFixture()
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
    {}
};

// ---------------------------------------------------------------------------
// Test 1: Initial tier is LOW
// ---------------------------------------------------------------------------
void test_initial_tier_low() {
    std::cout << "\n=== Test 1: Initial Tier is LOW ===" << std::endl;

    ThreatFixture f;
    assert(f.tsm.current_tier() == ThreatTier::LOW);
    assert(f.tsm.transition_count() == 0);

    std::cout << "  current_tier()     = " << tier_name(f.tsm.current_tier()) << std::endl;
    std::cout << "  transition_count() = " << f.tsm.transition_count() << std::endl;
}

// ---------------------------------------------------------------------------
// Test 2: Score-driven escalation LOW → MEDIUM → HIGH → CRITICAL
// ---------------------------------------------------------------------------
void test_escalation_sequence() {
    std::cout << "\n=== Test 2: Escalation Sequence LOW -> MEDIUM -> HIGH -> CRITICAL ===" << std::endl;

    ThreatFixture f;

    // ---- LOW (score 10 — stays LOW) ----
    auto r0 = f.tsm.observe_signal(10, "test_sensor");
    assert(!r0.tier_changed);
    assert(f.tsm.current_tier() == ThreatTier::LOW);
    std::cout << "  score=10  -> tier=" << tier_name(f.tsm.current_tier())
              << " (no change)" << std::endl;

    // ---- MEDIUM (score 30) ----
    auto r1 = f.tsm.observe_signal(30, "test_sensor");
    assert(r1.tier_changed);
    assert(r1.previous_tier  == ThreatTier::LOW);
    assert(r1.current_tier   == ThreatTier::MEDIUM);
    assert(!r1.worm_triggered);
    std::cout << "  score=30  -> tier=" << tier_name(r1.current_tier)
              << "  response: " << r1.response_description << std::endl;

    // ---- HIGH (score 55) ----
    auto r2 = f.tsm.observe_signal(55, "test_sensor");
    assert(r2.tier_changed);
    assert(r2.previous_tier  == ThreatTier::MEDIUM);
    assert(r2.current_tier   == ThreatTier::HIGH);
    assert(!r2.worm_triggered);
    std::cout << "  score=55  -> tier=" << tier_name(r2.current_tier)
              << "  response: " << r2.response_description << std::endl;

    // ---- CRITICAL (score 80) ----
    auto r3 = f.tsm.observe_signal(80, "test_sensor");
    assert(r3.tier_changed);
    assert(r3.previous_tier  == ThreatTier::HIGH);
    assert(r3.current_tier   == ThreatTier::CRITICAL);
    assert(r3.worm_triggered);                      // WORM must have fired
    assert(f.worm.is_locked());                     // WormLock must be engaged
    std::cout << "  score=80  -> tier=" << tier_name(r3.current_tier)
              << "  response: " << r3.response_description << std::endl;
    std::cout << "  WORM lockdown triggered: " << (r3.worm_triggered ? "YES" : "NO") << std::endl;

    // 3 transitions so far (LOW->MED, MED->HIGH, HIGH->CRIT)
    assert(f.tsm.transition_count() == 3);
}

// ---------------------------------------------------------------------------
// Test 3: CRITICAL correctly triggers WORM
// ---------------------------------------------------------------------------
void test_critical_triggers_worm() {
    std::cout << "\n=== Test 3: CRITICAL Tier Triggers WORM Lockdown ===" << std::endl;

    ThreatFixture f;

    assert(!f.worm.is_locked());

    f.tsm.observe_signal(90, "entropy_detector");

    assert(f.tsm.current_tier() == ThreatTier::CRITICAL);
    assert(f.worm.is_locked());
    std::cout << "  Tier   = " << tier_name(f.tsm.current_tier()) << std::endl;
    std::cout << "  WORM locked: " << (f.worm.is_locked() ? "YES" : "NO") << std::endl;
    std::cout << "  Lock reason: " << f.worm.lock_reason() << std::endl;
}

// ---------------------------------------------------------------------------
// Test 4: force_tier works for all four tiers
// ---------------------------------------------------------------------------
void test_force_tier_all_tiers() {
    std::cout << "\n=== Test 4: force_tier() Exercises All Four Tiers ===" << std::endl;

    // Use a no-op WORM trigger so we can test HIGH without locking
    AuditChain chain;
    ThreatStateMachine tsm(
        [&chain](const std::string& et, const std::string& p) {
            return chain.add_entry(et, p);
        }
        // worm_trigger defaults to no-op
    );

    assert(tsm.current_tier() == ThreatTier::LOW);

    bool changed;

    changed = tsm.force_tier(ThreatTier::MEDIUM, "manual escalation");
    assert(changed && tsm.current_tier() == ThreatTier::MEDIUM);
    std::cout << "  forced -> MEDIUM" << std::endl;

    changed = tsm.force_tier(ThreatTier::HIGH, "manual escalation");
    assert(changed && tsm.current_tier() == ThreatTier::HIGH);
    std::cout << "  forced -> HIGH" << std::endl;

    changed = tsm.force_tier(ThreatTier::CRITICAL, "manual escalation");
    assert(changed && tsm.current_tier() == ThreatTier::CRITICAL);
    std::cout << "  forced -> CRITICAL" << std::endl;

    // force to same tier is a no-op
    changed = tsm.force_tier(ThreatTier::CRITICAL, "no-op repeat");
    assert(!changed);
    std::cout << "  force CRITICAL again -> no-op (correct)" << std::endl;

    assert(tsm.transition_count() == 3);
}

// ---------------------------------------------------------------------------
// Test 5: Every tier transition writes an audit entry
// ---------------------------------------------------------------------------
void test_every_transition_audited() {
    std::cout << "\n=== Test 5: Every Tier Transition Is Audited ===" << std::endl;

    AuditChain chain;
    ThreatStateMachine tsm(
        [&chain](const std::string& et, const std::string& p) {
            return chain.add_entry(et, p);
        }
    );

    tsm.observe_signal(30, "sensor");   // LOW  -> MEDIUM
    tsm.observe_signal(60, "sensor");   // MED  -> HIGH
    tsm.observe_signal(80, "sensor");   // HIGH -> CRITICAL  (WORM no-op here)

    // 3 transitions = 3 audit entries
    assert(chain.get_chain_length() == 3);

    auto entries = chain.get_all_entries();
    for (const auto& e : entries) {
        assert(e.event_type == "threat_tier_transition");
        std::cout << "  [" << e.event_type << "] " << e.payload << std::endl;
    }

    // Chain integrity must hold
    auto v = chain.verify_chain();
    assert(v.is_valid);
    std::cout << "  Chain integrity: valid" << std::endl;
}

// ---------------------------------------------------------------------------
// Test 6: De-escalation requires score to drop well below threshold
// ---------------------------------------------------------------------------
void test_conservative_deescalation() {
    std::cout << "\n=== Test 6: De-escalation Is Conservative (No Jitter) ===" << std::endl;

    AuditChain chain;
    ThreatStateMachine tsm(
        [&chain](const std::string& et, const std::string& p) {
            return chain.add_entry(et, p);
        }
    );

    // Escalate to MEDIUM (threshold = 25)
    tsm.observe_signal(30, "sensor");
    assert(tsm.current_tier() == ThreatTier::MEDIUM);
    std::cout << "  Escalated to MEDIUM (score=30)" << std::endl;

    // Score drops to 20 — still above (25 - 10 = 15) so stays MEDIUM
    auto r1 = tsm.observe_signal(20, "sensor");
    assert(!r1.tier_changed);
    assert(tsm.current_tier() == ThreatTier::MEDIUM);
    std::cout << "  score=20 -> stays MEDIUM (de-escalation blocked, score not low enough)" << std::endl;

    // Score drops to 5 — below 15 → de-escalates to LOW
    auto r2 = tsm.observe_signal(5, "sensor");
    assert(r2.tier_changed);
    assert(r2.current_tier == ThreatTier::LOW);
    std::cout << "  score=5  -> de-escalated to LOW" << std::endl;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "ASTARTIS THREAT LEVEL STATE MACHINE TEST" << std::endl;
    std::cout << "Step 6: Adaptive Four-Tier State Machine" << std::endl;
    std::cout << "========================================" << std::endl;

    try {
        test_initial_tier_low();
        test_escalation_sequence();
        test_critical_triggers_worm();
        test_force_tier_all_tiers();
        test_every_transition_audited();
        test_conservative_deescalation();

        std::cout << "\n========================================" << std::endl;
        std::cout << "ALL TESTS PASSED"                         << std::endl;
        std::cout << "Threat-level state machine working!"      << std::endl;
        std::cout << "========================================\n" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\nTEST FAILED: " << e.what() << std::endl;
        return 1;
    }
}

// Made with Bob
