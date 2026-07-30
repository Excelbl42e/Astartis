#ifndef ASTARTIS_RULE_ENGINE_H
#define ASTARTIS_RULE_ENGINE_H

// Step 7 -- Deterministic Rule Engine + Step 12 RULE-05 extension.
// RULE-01: high-entropy anomalous packet window -> WORM
// RULE-02: raw threat score crossing
// RULE-03: auth failure spike
// RULE-04: CRITICAL belt-and-suspenders WORM check
// RULE-05: chaos precursor (K sustained > threshold -> preemptive MEDIUM)

#include <string>
#include <functional>
#include <cstdint>
#include <mutex>

#include "../threat_level/threat_level.h"
#include "../packet_sensor/packet_sensor.h"
#include "../chaos_detector/chaos_detector.h"

namespace astartis {
namespace rules {

/**
 * @brief Result of a single rule evaluation.
 */
struct RuleResult {
    std::string rule_id;          ///< e.g. "RULE-01"
    bool        fired;            ///< true if the rule's condition was met
    bool        worm_triggered;   ///< true if this evaluation triggered WORM
    std::string action_taken;     ///< human-readable description of what happened
};

/**
 * @brief Deterministic rule engine for Astartis.
 *
 * Thread-safe. All evaluation methods can be called concurrently.
 */
class RuleEngine {
public:
    // Thresholds (compile-time constants -- no tunable black-box parameters)
    static constexpr int      RULE01_ANOMALY_WORM_THRESHOLD  = 1;
    static constexpr int      RULE03_FAILURE_THRESHOLD       = 5;
    static constexpr int      RULE03_CRITICAL_THRESHOLD      = 10;
    static constexpr double   RULE05_K_THRESHOLD             = 0.7;
    static constexpr int      RULE05_SUSTAINED_WINDOWS       = 2;

    /**
     * @param audit_adder    Callable (event_type, payload) -> entry_id.
     * @param tsm            Reference to the live ThreatStateMachine.
     * @param worm_trigger   Callable (reason) -> void; triggers WormLock::trigger_lockdown.
     * @param worm_is_locked Callable () -> bool; queries WormLock::is_locked.
     */
    RuleEngine(
        std::function<std::string(const std::string&, const std::string&)> audit_adder,
        threat::ThreatStateMachine& tsm,
        std::function<void(const std::string&)> worm_trigger,
        std::function<bool()>                   worm_is_locked
    );

    ~RuleEngine() = default;

    // Non-copyable.
    RuleEngine(const RuleEngine&)            = delete;
    RuleEngine& operator=(const RuleEngine&) = delete;

    // -----------------------------------------------------------------------
    // Rule evaluation entry-points
    // -----------------------------------------------------------------------

    /**
     * @brief RULE-01: evaluate a completed entropy window.
     *
     * If window.anomalous is true:
     *   - Forces the threat state machine to CRITICAL (which in turn fires WORM via
     *     the wired worm_trigger inside ThreatStateMachine), AND
     *   - Directly calls worm_trigger as a safety belt (RULE-04 logic folded in).
     * Regardless of anomaly flag, feeds window.threat_score into the state machine.
     *
     * @return RuleResult for RULE-01.
     */
    RuleResult evaluate_packet_window(const sensor::EntropyWindow& window);

    /**
     * @brief RULE-02: evaluate a raw threat score from any source.
     *
     * Passes the score to ThreatStateMachine::observe_signal() and then
     * applies RULE-04 (CRITICAL → WORM belt-and-suspenders check).
     *
     * @param score  0–100.
     * @param source Label for the originating sensor / component.
     * @return RuleResult for RULE-02.
     */
    RuleResult evaluate_threat_score(int score, const std::string& source);

    /**
     * @brief RULE-03: evaluate authentication failure count in current window.
     *
     * @param failures_in_window Number of consecutive/recent auth failures.
     * @param source             Which subsystem reported them.
     * @return RuleResult for RULE-03.
     */
    RuleResult evaluate_auth_failures(int failures_in_window, const std::string& source);

    // RULE-05: evaluate a completed chaos window.
    // Fires preemptive MEDIUM escalation when K > RULE05_K_THRESHOLD
    // on RULE05_SUSTAINED_WINDOWS consecutive windows.
    // Does NOT trigger WORM or HIGH/CRITICAL on its own.
    RuleResult evaluate_chaos_window(const chaos::ChaosWindow& window);

    // -----------------------------------------------------------------------
    // Diagnostics
    // -----------------------------------------------------------------------

    /** Current threat tier of the underlying state machine. */
    threat::ThreatTier current_tier() const;

    /** Total number of times any rule has fired since construction. */
    uint64_t total_fires() const;

    /** Total number of WORM triggers issued by this engine since construction. */
    uint64_t worm_trigger_count() const;

private:
    // Apply RULE-04: if tier is CRITICAL and WORM is not yet locked, trigger it.
    // Returns true if it had to act.  Caller must NOT hold mutex_.
    bool apply_rule04_belt(const std::string& triggering_rule);

    std::function<std::string(const std::string&, const std::string&)> audit_adder_;
    threat::ThreatStateMachine& tsm_;
    std::function<void(const std::string&)> worm_trigger_;
    std::function<bool()>                   worm_is_locked_;

    uint64_t total_fires_        = 0;
    uint64_t worm_trigger_count_ = 0;
    int      chaos_high_count_   = 0;  // consecutive windows above K threshold

    mutable std::mutex mutex_;
};

} // namespace rules
} // namespace astartis

#endif // ASTARTIS_RULE_ENGINE_H

// Made with Bob
