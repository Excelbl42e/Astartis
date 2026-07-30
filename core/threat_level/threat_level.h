#ifndef ASTARTIS_THREAT_LEVEL_H
#define ASTARTIS_THREAT_LEVEL_H

#include <string>
#include <functional>
#include <mutex>
#include <cstdint>
#include <vector>

namespace astartis {
namespace threat {

/**
 * @brief Four-tier threat level as defined in the architecture (§ Step 6).
 *
 * Tiers are ordered by severity.  Casting to int gives the ordinal (0–3).
 */
enum class ThreatTier : int {
    LOW      = 0,
    MEDIUM   = 1,
    HIGH     = 2,
    CRITICAL = 3,
};

/** Human-readable name for a tier. */
const char* tier_name(ThreatTier t);

/**
 * @brief Automated response descriptor — what fires when a tier is entered.
 */
struct TierResponse {
    ThreatTier tier;
    std::string description;   // short description logged to audit chain
};

/**
 * @brief Result of an observe_signal() call.
 */
struct SignalResult {
    bool        tier_changed;        // true if the tier was elevated or lowered
    ThreatTier  previous_tier;
    ThreatTier  current_tier;
    std::string response_description; // text of the automated response that fired
    bool        worm_triggered;       // true if CRITICAL triggered WORM lockdown
};

/**
 * @brief Adaptive four-tier threat-level state machine.
 *
 * Tiers (architecture §Step 6):
 *   LOW      — silent logging, behavioral note, mild rate limiting
 *   MEDIUM   — aggressive rate limiting, CAPTCHA-equivalent challenge,
 *               enhanced forensic logging
 *   HIGH     — immediate session termination, account lockdown,
 *               forensic investigation flag
 *   CRITICAL — full lockdown trigger (feeds into WORM), all non-essential
 *               access suspended
 *
 * Every tier transition is written to the AuditChain.
 * CRITICAL transitions call the worm_trigger callback, which is wired to
 * WormLock::trigger_lockdown() by the caller.
 *
 * Signal scoring:
 *   observe_signal(score) accepts a 0–100 threat score.
 *   Thresholds:
 *     score < 25  → LOW
 *     score < 50  → MEDIUM
 *     score < 75  → HIGH
 *     score >= 75 → CRITICAL
 *   The machine only escalates eagerly (on any call above the current threshold)
 *   but de-escalates conservatively (only when the score drops well below the
 *   current tier threshold).  De-escalation requires score to be at least one
 *   full tier-band below the current tier lower bound — this prevents jitter.
 *
 * Thread-safe.
 */
class ThreatStateMachine {
public:
    /**
     * @param audit_adder  Callable (event_type, payload) -> entry_id.
     *                     Wired to AuditChain::add_entry.
     * @param worm_trigger Callable (reason) called when CRITICAL is entered.
     *                     Wire to WormLock::trigger_lockdown.
     *                     Defaults to no-op (for isolated unit tests).
     */
    explicit ThreatStateMachine(
        std::function<std::string(const std::string&, const std::string&)> audit_adder,
        std::function<void(const std::string&)> worm_trigger = [](const std::string&) {}
    );

    ~ThreatStateMachine() = default;

    // Non-copyable, movable.
    ThreatStateMachine(const ThreatStateMachine&)            = delete;
    ThreatStateMachine& operator=(const ThreatStateMachine&) = delete;

    // -----------------------------------------------------------------------
    // Core interface
    // -----------------------------------------------------------------------

    /**
     * @brief Ingest a threat signal and advance (or hold) the tier.
     *
     * @param score     0–100 threat score from any sensor or rule.
     * @param source    Human-readable label for what produced the score (logged).
     * @return SignalResult describing what happened.
     */
    SignalResult observe_signal(int score, const std::string& source);

    /**
     * @brief Manually force a specific tier (used by the rule engine, Step 7).
     *
     * Unconditionally transitions to the target tier regardless of score.
     * Fires the tier's automated response and writes to the audit chain.
     * No-op (returns false) if already at that tier.
     *
     * @param tier    Target tier.
     * @param reason  Why this was forced (logged).
     * @return true if tier changed.
     */
    bool force_tier(ThreatTier tier, const std::string& reason);

    // -----------------------------------------------------------------------
    // State query
    // -----------------------------------------------------------------------

    /** Current threat tier. */
    ThreatTier current_tier() const;

    /** Number of tier transitions since construction. */
    uint64_t transition_count() const;

    /** Score threshold above which a tier is entered (for introspection/tests). */
    static int tier_lower_threshold(ThreatTier t);

private:
    // Internal: transition to a new tier, fire response, write audit entry.
    // Caller must hold mutex_.
    SignalResult do_transition(ThreatTier new_tier,
                               const std::string& reason);

    // The automated response text for each tier.
    static TierResponse make_response(ThreatTier t);

    std::function<std::string(const std::string&, const std::string&)> audit_adder_;
    std::function<void(const std::string&)>                             worm_trigger_;

    ThreatTier current_tier_ = ThreatTier::LOW;
    uint64_t   transition_count_ = 0;

    mutable std::mutex mutex_;
};

} // namespace threat
} // namespace astartis

#endif // ASTARTIS_THREAT_LEVEL_H

// Made with Bob
