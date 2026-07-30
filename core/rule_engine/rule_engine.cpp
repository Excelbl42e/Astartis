#include "rule_engine.h"
#include <sstream>

namespace astartis {
namespace rules {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

RuleEngine::RuleEngine(
    std::function<std::string(const std::string&, const std::string&)> audit_adder,
    threat::ThreatStateMachine& tsm,
    std::function<void(const std::string&)> worm_trigger,
    std::function<bool()>                   worm_is_locked)
    : audit_adder_(std::move(audit_adder))
    , tsm_(tsm)
    , worm_trigger_(std::move(worm_trigger))
    , worm_is_locked_(std::move(worm_is_locked))
{}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

threat::ThreatTier RuleEngine::current_tier() const
{
    return tsm_.current_tier();
}

uint64_t RuleEngine::total_fires() const
{
    std::lock_guard<std::mutex> lk(mutex_);
    return total_fires_;
}

uint64_t RuleEngine::worm_trigger_count() const
{
    std::lock_guard<std::mutex> lk(mutex_);
    return worm_trigger_count_;
}

// ---------------------------------------------------------------------------
// RULE-04 belt-and-suspenders helper
// ---------------------------------------------------------------------------

bool RuleEngine::apply_rule04_belt(const std::string& triggering_rule)
{
    if (tsm_.current_tier() == threat::ThreatTier::CRITICAL && !worm_is_locked_()) {
        worm_trigger_("RULE-04 belt: " + triggering_rule + " confirmed CRITICAL, WORM not yet locked");
        {
            std::lock_guard<std::mutex> lk(mutex_);
            ++worm_trigger_count_;
        }
        std::ostringstream p;
        p << "rule=RULE-04 triggered_by=" << triggering_rule;
        audit_adder_("rule_engine_rule04_belt", p.str());
        return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// RULE-01: anomalous packet window
// ---------------------------------------------------------------------------

RuleResult RuleEngine::evaluate_packet_window(const sensor::EntropyWindow& window)
{
    // Always feed the threat score from the window into the state machine first.
    // This may or may not change the tier; RULE-01 then checks anomaly flag on top.
    tsm_.observe_signal(window.threat_score, "packet_sensor_window");

    bool fired = false;
    bool worm_hit = false;

    if (window.anomalous) {
        // RULE-01 fires independently — force CRITICAL directly.
        // This is the standalone anomalous-packet → WORM path
        // that does NOT require a full OMIDAX+DIBANET breach.
        fired = true;

        bool changed = tsm_.force_tier(
            threat::ThreatTier::CRITICAL,
            "RULE-01 anomalous_packet entropy=" + std::to_string(window.mean_entropy_bits));

        // RULE-04 belt: ensure WORM is locked
        worm_hit = apply_rule04_belt("RULE-01");

        // Audit this rule firing
        std::ostringstream p;
        p << "rule=RULE-01"
          << " window_index=" << window.window_index
          << " mean_entropy=" << window.mean_entropy_bits
          << " threat_score=" << window.threat_score
          << " anomalous=true"
          << " tier_changed=" << (changed ? "true" : "false")
          << " worm_triggered=" << (worm_hit ? "true" : "false");
        audit_adder_("rule_engine_rule01_fired", p.str());

        {
            std::lock_guard<std::mutex> lk(mutex_);
            ++total_fires_;
        }
    }

    return RuleResult{
        "RULE-01",
        fired,
        worm_hit,
        fired
            ? "anomalous packet window detected: forced CRITICAL tier + WORM lockdown check"
            : "packet window processed, no anomaly flag"
    };
}

// ---------------------------------------------------------------------------
// RULE-02: raw threat score
// ---------------------------------------------------------------------------

RuleResult RuleEngine::evaluate_threat_score(int score, const std::string& source)
{
    auto result = tsm_.observe_signal(score, source);

    bool worm_hit = apply_rule04_belt("RULE-02");

    bool fired = result.tier_changed || worm_hit;

    if (fired) {
        std::lock_guard<std::mutex> lk(mutex_);
        ++total_fires_;
    }

    std::ostringstream action;
    action << "score=" << score << " source=" << source;
    if (result.tier_changed) {
        action << " tier_transition="
               << threat::tier_name(result.previous_tier) << "->"
               << threat::tier_name(result.current_tier);
    }
    if (worm_hit) {
        action << " worm_triggered=true";
    }

    return RuleResult{
        "RULE-02",
        fired,
        worm_hit,
        action.str()
    };
}

// ---------------------------------------------------------------------------
// RULE-03: authentication failure spike
// ---------------------------------------------------------------------------

RuleResult RuleEngine::evaluate_auth_failures(int failures_in_window,
                                               const std::string& source)
{
    bool fired      = false;
    bool worm_hit   = false;
    std::string action;

    if (failures_in_window >= RULE03_CRITICAL_THRESHOLD) {
        fired = true;
        tsm_.force_tier(threat::ThreatTier::CRITICAL,
                        "RULE-03 auth_failures=" + std::to_string(failures_in_window)
                        + " source=" + source);
        worm_hit = apply_rule04_belt("RULE-03");

        std::ostringstream p;
        p << "rule=RULE-03 failures=" << failures_in_window
          << " source=" << source
          << " action=forced_CRITICAL";
        audit_adder_("rule_engine_rule03_fired", p.str());

        action = "auth failure spike (>= " + std::to_string(RULE03_CRITICAL_THRESHOLD)
               + "): forced CRITICAL + WORM check";

    } else if (failures_in_window >= RULE03_FAILURE_THRESHOLD) {
        fired = true;
        tsm_.force_tier(threat::ThreatTier::HIGH,
                        "RULE-03 auth_failures=" + std::to_string(failures_in_window)
                        + " source=" + source);

        std::ostringstream p;
        p << "rule=RULE-03 failures=" << failures_in_window
          << " source=" << source
          << " action=forced_HIGH";
        audit_adder_("rule_engine_rule03_fired", p.str());

        action = "auth failure spike (>= " + std::to_string(RULE03_FAILURE_THRESHOLD)
               + "): forced HIGH";
    } else {
        action = "auth failures=" + std::to_string(failures_in_window)
               + " (below threshold, no action)";
    }

    if (fired) {
        std::lock_guard<std::mutex> lk(mutex_);
        ++total_fires_;
    }

    return RuleResult{"RULE-03", fired, worm_hit, action};
}

// ---------------------------------------------------------------------------
// RULE-05: chaos precursor escalation
// ---------------------------------------------------------------------------

RuleResult RuleEngine::evaluate_chaos_window(const chaos::ChaosWindow& window)
{
    bool fired    = false;
    std::string action;

    // Track consecutive windows above the chaos threshold
    if (window.K > RULE05_K_THRESHOLD) {
        std::lock_guard<std::mutex> lk(mutex_);
        ++chaos_high_count_;

        if (chaos_high_count_ >= RULE05_SUSTAINED_WINDOWS) {
            // Fire preemptive escalation to MEDIUM only -- this is a precursor
            // signal, not a confirmed breach.  Does not touch WORM.
            fired = true;
            ++total_fires_;

            tsm_.force_tier(threat::ThreatTier::MEDIUM,
                            "RULE-05 chaos_precursor K=" +
                            std::to_string(window.K) +
                            " sustained_windows=" +
                            std::to_string(chaos_high_count_));

            std::ostringstream p;
            p << "rule=RULE-05"
              << " window_index=" << window.window_index
              << " K=" << window.K
              << " sustained_windows=" << chaos_high_count_
              << " action=preemptive_escalation_to_MEDIUM";
            audit_adder_("rule_engine_rule05_fired", p.str());

            action = "chaos precursor: K=" + std::to_string(window.K) +
                     " sustained over " + std::to_string(chaos_high_count_) +
                     " windows -- preemptive escalation to MEDIUM";
        } else {
            action = "chaos signal accumulating: K=" + std::to_string(window.K) +
                     " count=" + std::to_string(chaos_high_count_) +
                     " (need " + std::to_string(RULE05_SUSTAINED_WINDOWS) + ")";
        }
    } else {
        // Below threshold -- reset the consecutive counter
        std::lock_guard<std::mutex> lk(mutex_);
        chaos_high_count_ = 0;
        action = "chaos K=" + std::to_string(window.K) + " (below threshold, no action)";
    }

    return RuleResult{"RULE-05", fired, false, action};
}

} // namespace rules
} // namespace astartis

// Made with Bob
