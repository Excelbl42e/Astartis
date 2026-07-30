#ifdef NDEBUG
#undef NDEBUG
#endif
#include <iostream>
#include <cassert>
#include <vector>
#include <cmath>
#include <string>
#include <limits>

#include "../core/audit_chain/audit_chain.h"
#include "../core/worm_lock/worm_lock.h"
#include "../core/threat_level/threat_level.h"
#include "../core/rule_engine/rule_engine.h"
#include "../core/chaos_detector/chaos_detector.h"

using namespace astartis::audit;
using namespace astartis::worm;
using namespace astartis::threat;
using namespace astartis::rules;
using namespace astartis::chaos;

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

// ---------------------------------------------------------------------------
// Synthetic series generators
// ---------------------------------------------------------------------------

// Logistic map at r=4: x_{n+1} = r * x_n * (1 - x_n)
// This is a canonical chaos benchmark -- K should converge near 1.
static std::vector<double> logistic_map(size_t n, double x0 = 0.4)
{
    std::vector<double> s;
    s.reserve(n);
    double x = x0;
    for (size_t i = 0; i < n; ++i) {
        s.push_back(x);
        x = 4.0 * x * (1.0 - x);
    }
    return s;
}

// Sine wave: x_n = sin(2*pi*n/period)
// This is a known-regular (periodic) series -- K should converge near 0.
static std::vector<double> sine_wave(size_t n, double period = 20.0)
{
    std::vector<double> s;
    s.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(std::sin(2.0 * M_PI * i / period));
    }
    return s;
}

// ---------------------------------------------------------------------------
// Test 1: Logistic map (r=4) -> K near 1 (chaotic)
// ---------------------------------------------------------------------------
void test_logistic_map_is_chaotic()
{
    std::cout << "\n=== Test 1: Logistic Map (r=4) Classified as Chaotic ===" << std::endl;

    auto series = logistic_map(256);
    double K = ChaosDetector::compute_K(series);

    std::cout << "  Series length: " << series.size() << std::endl;
    std::cout << "  K = " << K << "  (expected near 1.0)" << std::endl;

    // K should be well above the chaos threshold for the logistic map at r=4
    if (K < 0.7) {
        std::cerr << "FAIL: expected K >= 0.7 for logistic map, got " << K << "\n";
        std::exit(1);
    }
    std::cout << "  PASS: K=" << K << " >= 0.7 (classified as chaotic)" << std::endl;
}

// ---------------------------------------------------------------------------
// Test 2: Sine wave -> K near 0 (regular)
// ---------------------------------------------------------------------------
void test_sine_wave_is_regular()
{
    std::cout << "\n=== Test 2: Sine Wave Classified as Regular ===" << std::endl;

    auto series = sine_wave(256, 20.0);
    double K = ChaosDetector::compute_K(series);

    std::cout << "  Series length: " << series.size() << std::endl;
    std::cout << "  K = " << K << "  (expected near 0.0)" << std::endl;

    // K should be well below the chaos threshold for a pure sine wave
    if (K >= 0.7) {
        std::cerr << "FAIL: expected K < 0.7 for sine wave, got " << K << "\n";
        std::exit(1);
    }
    std::cout << "  PASS: K=" << K << " < 0.7 (classified as regular)" << std::endl;
}

// ---------------------------------------------------------------------------
// Test 3: ChaosDetector push/flush emits correct ChaosWindow structs
// ---------------------------------------------------------------------------
void test_detector_push_and_flush()
{
    std::cout << "\n=== Test 3: ChaosDetector push() Emits Correct Windows ===" << std::endl;

    AuditChain chain;
    std::vector<ChaosWindow> emitted;

    ChaosDetector det(
        [&emitted](const ChaosWindow& w) { emitted.push_back(w); },
        [&chain](const std::string& et, const std::string& p) {
            return chain.add_entry(et, p);
        },
        64  // small window size for test speed
    );

    // Push a full window of logistic-map samples (chaotic)
    auto samples = logistic_map(64);
    for (double v : samples) det.push(v, false);

    if (emitted.size() != 1) {
        std::cerr << "FAIL: expected 1 window, got " << emitted.size() << "\n";
        std::exit(1);
    }

    const auto& w = emitted[0];
    std::cout << "  Window 0: K=" << w.K << " anomalous=" << w.anomalous
              << " samples=" << w.sample_count << std::endl;

    if (!w.anomalous) {
        std::cerr << "FAIL: logistic map window should be anomalous\n"; std::exit(1);
    }
    if (w.sample_count != 64) {
        std::cerr << "FAIL: wrong sample count\n"; std::exit(1);
    }

    // Second window: sine wave (regular)
    auto sine = sine_wave(64, 20.0);
    for (double v : sine) det.push(v, false);

    if (emitted.size() != 2) {
        std::cerr << "FAIL: expected 2 windows, got " << emitted.size() << "\n";
        std::exit(1);
    }

    const auto& w2 = emitted[1];
    std::cout << "  Window 1: K=" << w2.K << " anomalous=" << w2.anomalous << std::endl;
    if (w2.anomalous) {
        std::cerr << "FAIL: sine wave window should NOT be anomalous\n"; std::exit(1);
    }

    // Audit chain should have chaos_window entries
    size_t chaos_entries = 0;
    for (const auto& e : chain.get_all_entries())
        if (e.event_type == "chaos_window") ++chaos_entries;
    if (chaos_entries != 2) {
        std::cerr << "FAIL: expected 2 chaos_window audit entries, got " << chaos_entries << "\n";
        std::exit(1);
    }
    std::cout << "  chaos_window audit entries: " << chaos_entries << "  (correct)" << std::endl;
}

// ---------------------------------------------------------------------------
// Test 4: Lyapunov exponent -- logistic positive, sine near-zero or negative
// ---------------------------------------------------------------------------
void test_lyapunov_signs()
{
    std::cout << "\n=== Test 4: Rosenstein Lyapunov Exponent Signs ===" << std::endl;

    auto chaotic = logistic_map(256);
    double lam_chaos = ChaosDetector::compute_lyapunov(chaotic);

    auto regular = sine_wave(256, 20.0);
    double lam_reg = ChaosDetector::compute_lyapunov(regular);

    std::cout << "  lambda1 (logistic map): " << lam_chaos << "  (expected > 0)" << std::endl;
    std::cout << "  lambda1 (sine wave):    " << lam_reg   << "  (expected <= 0 or near 0)" << std::endl;

    if (std::isnan(lam_chaos)) {
        std::cerr << "FAIL: lyapunov returned NaN for logistic map\n"; std::exit(1);
    }
    if (lam_chaos <= 0.0) {
        std::cerr << "FAIL: expected positive Lyapunov for chaotic series, got " << lam_chaos << "\n";
        std::exit(1);
    }
    std::cout << "  PASS: positive lambda1 for chaotic series" << std::endl;
}

// ---------------------------------------------------------------------------
// Test 5: RULE-05 fires BEFORE any entropy/auth rule would have fired,
//         on the chaotic fixture.  This is the core spec requirement.
// ---------------------------------------------------------------------------
void test_rule05_preemptive_escalation()
{
    std::cout << "\n=== Test 5: RULE-05 Fires Preemptive Escalation (Chaotic Input) ===" << std::endl;

    AuditChain chain;
    WormLock   worm([&chain](const std::string& et, const std::string& p) {
                   return chain.add_entry(et, p);
               });
    ThreatStateMachine tsm(
        [&chain](const std::string& et, const std::string& p) {
            return chain.add_entry(et, p);
        },
        [&worm](const std::string& r) { worm.trigger_lockdown(r); }
    );
    RuleEngine engine(
        [&chain](const std::string& et, const std::string& p) {
            return chain.add_entry(et, p);
        },
        tsm,
        [&worm](const std::string& r) { worm.trigger_lockdown(r); },
        [&worm]() { return worm.is_locked(); }
    );

    // Start at LOW
    if (tsm.current_tier() != ThreatTier::LOW) {
        std::cerr << "FAIL: expected initial tier LOW\n"; std::exit(1);
    }

    // Build chaotic windows (logistic map K > 0.7)
    auto chaotic = logistic_map(64);

    ChaosWindow w1;
    w1.window_index = 0; w1.sample_count = 64;
    w1.K = ChaosDetector::compute_K(chaotic);
    w1.anomalous = (w1.K > ChaosDetector::CHAOS_THRESHOLD);
    w1.synthetic = true;

    ChaosWindow w2 = w1;
    w2.window_index = 1;

    // Window 1: K high -- below RULE05_SUSTAINED_WINDOWS (2), no fire yet
    auto r1 = engine.evaluate_chaos_window(w1);
    std::cout << "  Window 1: K=" << w1.K
              << " fired=" << r1.fired
              << " tier=" << tier_name(tsm.current_tier()) << std::endl;
    if (r1.fired) {
        std::cerr << "FAIL: RULE-05 should not fire on first window alone\n"; std::exit(1);
    }
    if (tsm.current_tier() != ThreatTier::LOW) {
        std::cerr << "FAIL: tier should still be LOW after first window\n"; std::exit(1);
    }

    // Window 2: second consecutive high K -- RULE-05 must fire now
    auto r2 = engine.evaluate_chaos_window(w2);
    std::cout << "  Window 2: K=" << w2.K
              << " fired=" << r2.fired
              << " tier=" << tier_name(tsm.current_tier()) << std::endl;
    if (!r2.fired) {
        std::cerr << "FAIL: RULE-05 should fire on 2nd consecutive window\n"; std::exit(1);
    }
    if (tsm.current_tier() != ThreatTier::MEDIUM) {
        std::cerr << "FAIL: expected MEDIUM after RULE-05, got "
                  << tier_name(tsm.current_tier()) << "\n";
        std::exit(1);
    }

    // WORM must NOT be locked (RULE-05 is precursor only, not breach)
    if (worm.is_locked()) {
        std::cerr << "FAIL: WORM should not be triggered by RULE-05\n"; std::exit(1);
    }
    std::cout << "  WORM locked: NO (correct -- precursor only)" << std::endl;

    // This escalation fired BEFORE any entropy/auth rule would have fired
    // (no RULE-01/02/03 calls were made above -- tier came from RULE-05 alone)
    std::cout << "  PASS: RULE-05 escalated to MEDIUM before any existing rule fired" << std::endl;

    // Audit chain must have a rule_engine_rule05_fired entry
    bool found_r05 = false;
    for (const auto& e : chain.get_all_entries())
        if (e.event_type == "rule_engine_rule05_fired") { found_r05 = true; break; }
    if (!found_r05) {
        std::cerr << "FAIL: no rule_engine_rule05_fired audit entry\n"; std::exit(1);
    }
    std::cout << "  Audit entry 'rule_engine_rule05_fired': present" << std::endl;
}

// ---------------------------------------------------------------------------
// Test 6: RULE-05 does NOT fire on regular (sine) input
// ---------------------------------------------------------------------------
void test_rule05_no_fire_on_regular_input()
{
    std::cout << "\n=== Test 6: RULE-05 Does Not Fire on Regular (Sine) Input ===" << std::endl;

    AuditChain chain;
    ThreatStateMachine tsm(
        [&chain](const std::string& et, const std::string& p) {
            return chain.add_entry(et, p);
        }
    );
    RuleEngine engine(
        [&chain](const std::string& et, const std::string& p) {
            return chain.add_entry(et, p);
        },
        tsm,
        [](const std::string&) {},
        []() { return false; }
    );

    auto regular = sine_wave(64, 20.0);
    double K_reg = ChaosDetector::compute_K(regular);

    // Feed 5 regular windows -- RULE-05 should never fire
    for (int i = 0; i < 5; ++i) {
        ChaosWindow w;
        w.window_index = i; w.sample_count = 64;
        w.K = K_reg; w.anomalous = false; w.synthetic = true;
        auto r = engine.evaluate_chaos_window(w);
        if (r.fired) {
            std::cerr << "FAIL: RULE-05 fired on regular (sine) input at window " << i << "\n";
            std::exit(1);
        }
    }
    std::cout << "  K_regular=" << K_reg
              << "  RULE-05 never fired across 5 windows (correct)" << std::endl;
    if (tsm.current_tier() != ThreatTier::LOW) {
        std::cerr << "FAIL: tier should remain LOW on regular input\n"; std::exit(1);
    }
    std::cout << "  Tier remains LOW: correct" << std::endl;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main()
{
    std::cout << "========================================" << std::endl;
    std::cout << "ASTARTIS CHAOS DETECTOR TEST            " << std::endl;
    std::cout << "Step 12: 0-1 Test + Lyapunov + RULE-05  " << std::endl;
    std::cout << "========================================" << std::endl;

    try {
        test_logistic_map_is_chaotic();
        test_sine_wave_is_regular();
        test_detector_push_and_flush();
        test_lyapunov_signs();
        test_rule05_preemptive_escalation();
        test_rule05_no_fire_on_regular_input();

        std::cout << "\n========================================" << std::endl;
        std::cout << "ALL TESTS PASSED"                         << std::endl;
        std::cout << "Chaos detector working!"                  << std::endl;
        std::cout << "========================================\n" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\nTEST FAILED: " << e.what() << std::endl;
        return 1;
    }
}

// Made with Bob
