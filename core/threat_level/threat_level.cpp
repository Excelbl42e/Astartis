#include "threat_level.h"
#include <sstream>
#include <stdexcept>

namespace astartis {
namespace threat {

// ---------------------------------------------------------------------------
// Tier helpers
// ---------------------------------------------------------------------------

const char* tier_name(ThreatTier t)
{
    switch (t) {
        case ThreatTier::LOW:      return "LOW";
        case ThreatTier::MEDIUM:   return "MEDIUM";
        case ThreatTier::HIGH:     return "HIGH";
        case ThreatTier::CRITICAL: return "CRITICAL";
    }
    return "UNKNOWN";
}

/* static */ int ThreatStateMachine::tier_lower_threshold(ThreatTier t)
{
    // score range that maps to each tier:
    //   LOW      [0 , 25)
    //   MEDIUM   [25, 50)
    //   HIGH     [50, 75)
    //   CRITICAL [75,100]
    switch (t) {
        case ThreatTier::LOW:      return 0;
        case ThreatTier::MEDIUM:   return 25;
        case ThreatTier::HIGH:     return 50;
        case ThreatTier::CRITICAL: return 75;
    }
    return 0;
}

/* static */ TierResponse ThreatStateMachine::make_response(ThreatTier t)
{
    switch (t) {
        case ThreatTier::LOW:
            return {t, "silent logging, behavioral note added, mild rate limiting"};
        case ThreatTier::MEDIUM:
            return {t, "aggressive rate limiting, CAPTCHA-equivalent challenge, enhanced forensic logging"};
        case ThreatTier::HIGH:
            return {t, "immediate session termination, account lockdown, forensic investigation flag"};
        case ThreatTier::CRITICAL:
            return {t, "full WORM lockdown triggered, all non-essential access suspended"};
    }
    return {t, "unknown"};
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

ThreatStateMachine::ThreatStateMachine(
    std::function<std::string(const std::string&, const std::string&)> audit_adder,
    std::function<void(const std::string&)> worm_trigger)
    : audit_adder_(std::move(audit_adder))
    , worm_trigger_(std::move(worm_trigger))
{}

// ---------------------------------------------------------------------------
// State query
// ---------------------------------------------------------------------------

ThreatTier ThreatStateMachine::current_tier() const
{
    std::lock_guard<std::mutex> lk(mutex_);
    return current_tier_;
}

uint64_t ThreatStateMachine::transition_count() const
{
    std::lock_guard<std::mutex> lk(mutex_);
    return transition_count_;
}

// ---------------------------------------------------------------------------
// Internal transition (mutex must be held by caller)
// ---------------------------------------------------------------------------

SignalResult ThreatStateMachine::do_transition(ThreatTier new_tier,
                                                const std::string& reason)
{
    ThreatTier prev = current_tier_;
    current_tier_   = new_tier;
    ++transition_count_;

    TierResponse resp = make_response(new_tier);

    // Audit chain entry for every tier transition
    std::ostringstream payload;
    payload << "from=" << tier_name(prev)
            << " to="  << tier_name(new_tier)
            << " reason=\"" << reason << "\""
            << " response=\"" << resp.description << "\"";
    audit_adder_("threat_tier_transition", payload.str());

    // CRITICAL: fire WORM lockdown
    bool worm_triggered = false;
    if (new_tier == ThreatTier::CRITICAL) {
        worm_trigger_("threat tier reached CRITICAL — " + reason);
        worm_triggered = true;
    }

    return SignalResult{
        true,              // tier_changed
        prev,
        new_tier,
        resp.description,
        worm_triggered
    };
}

// ---------------------------------------------------------------------------
// observe_signal
// ---------------------------------------------------------------------------

SignalResult ThreatStateMachine::observe_signal(int score, const std::string& source)
{
    // Clamp score to [0, 100]
    if (score < 0)   score = 0;
    if (score > 100) score = 100;

    std::lock_guard<std::mutex> lk(mutex_);

    // Determine target tier from score
    ThreatTier target;
    if      (score >= 75) target = ThreatTier::CRITICAL;
    else if (score >= 50) target = ThreatTier::HIGH;
    else if (score >= 25) target = ThreatTier::MEDIUM;
    else                  target = ThreatTier::LOW;

    // Escalate eagerly: jump to target if it is higher than current
    if (static_cast<int>(target) > static_cast<int>(current_tier_)) {
        std::string reason = "score=" + std::to_string(score) + " source=\"" + source + "\"";
        return do_transition(target, reason);
    }

    // De-escalate conservatively: only lower if score is a full band below current tier
    // (prevents jitter on borderline scores)
    int current_lower = tier_lower_threshold(current_tier_);
    if (static_cast<int>(target) < static_cast<int>(current_tier_) &&
        score < current_lower - 10)
    {
        std::string reason = "de-escalation: score=" + std::to_string(score) + " source=\"" + source + "\"";
        return do_transition(target, reason);
    }

    // No tier change
    return SignalResult{false, current_tier_, current_tier_, "", false};
}

// ---------------------------------------------------------------------------
// force_tier
// ---------------------------------------------------------------------------

bool ThreatStateMachine::force_tier(ThreatTier tier, const std::string& reason)
{
    std::lock_guard<std::mutex> lk(mutex_);
    if (tier == current_tier_) {
        return false;
    }
    do_transition(tier, "forced: " + reason);
    return true;
}

} // namespace threat
} // namespace astartis

// Made with Bob
