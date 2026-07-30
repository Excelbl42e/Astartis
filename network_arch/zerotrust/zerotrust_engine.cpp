// zerotrust_engine.cpp -- Zero Trust decision engine (Astartis v2.1)

#include "network_arch/zerotrust/zerotrust_engine.h"
#include <algorithm>
#include <sstream>
#include <set>

namespace astartis::zerotrust {

// Simulated anomalous user patterns (production: UEBA / ML model)
static const std::set<std::string> ANOMALOUS_ACTIONS = {
    "login_off_hours",
    "mass_download",
    "admin_from_public_ssid",
    "privilege_escalation_attempt",
};

ZeroTrustEngine::ZeroTrustEngine(
    std::function<std::string(const std::string&, const std::string&)> audit_adder)
    : audit_adder_(std::move(audit_adder))
{
    // Zone definitions (subnet → zone)
    zone_map_ = {
        {"192.168.100.", "public"},
        {"10.0.200.",    "enterprise"},
        {"10.0.99.",     "management"},
        {"10.0.300.",    "quarantine"},
    };

    // Zone policies (zone → allowed roles to enter)
    zone_policies_ = {
        {"public",      {"guest", "contractor"}},
        {"enterprise",  {"it_admin", "staff", "contractor"}},
        {"management",  {"it_admin"}},
        {"quarantine",  {}},
    };
}

std::string zone_of(const std::string& ip,
                    const std::map<std::string, std::string>& zone_map)
{
    for (const auto& [prefix, zone] : zone_map) {
        if (ip.rfind(prefix, 0) == 0) return zone;
    }
    return "unknown";
}

int ZeroTrustEngine::calculate_trust_score(const AccessContext& ctx)
{
    int score = 0;

    // User is in directory → +40 (identity is the primary trust anchor)
    const std::set<std::string> known_users = {
        "kgosi.blanda","admin","user1","user2","contractor1"};
    const bool user_known = known_users.count(ctx.user_id) > 0;
    if (user_known) score += 40;

    // Known SSID + known user → +20 (SSID alone is not sufficient trust)
    if (user_known && (ctx.ssid_name == "eGov" || ctx.ssid_name == "Astartis-Admin"))
        score += 20;

    // Source IP in enterprise subnet (only meaningful when user is known) → +20
    if (user_known && ctx.source_ip.rfind("10.0.200.", 0) == 0) score += 20;

    // Not anomalous → +20
    if (!is_anomalous_behavior(ctx.user_id, ctx.requested_resource)) score += 20;

    return std::min(score, 100);
}

bool ZeroTrustEngine::is_cross_zone_allowed(const std::string& from_zone,
                                             const std::string& to_zone,
                                             const std::string& role)
{
    // Public → Enterprise: NEVER allowed (hard rule)
    if (from_zone == "public" && to_zone == "enterprise") return false;
    if (from_zone == "public" && to_zone == "management")  return false;
    if (from_zone == "quarantine")                          return false;

    // Check zone policy
    auto it = zone_policies_.find(to_zone);
    if (it == zone_policies_.end()) return false;
    const auto& allowed_roles = it->second;
    return std::find(allowed_roles.begin(), allowed_roles.end(), role)
           != allowed_roles.end();
}

bool ZeroTrustEngine::is_anomalous_behavior(const std::string& /*user_id*/,
                                             const std::string& action)
{
    return ANOMALOUS_ACTIONS.count(action) > 0;
}

TrustDecision ZeroTrustEngine::evaluate(const AccessContext& ctx)
{
    int score = calculate_trust_score(ctx);
    std::string from_zone = zone_of(ctx.source_ip, zone_map_);
    std::string to_zone   = zone_of(ctx.destination_ip, zone_map_);

    TrustDecision decision;
    std::string reason;

    if (is_anomalous_behavior(ctx.user_id, ctx.requested_resource)) {
        decision = TrustDecision::MFA_REQUIRED;
        reason   = "Anomalous behavior detected — MFA required";
    } else if (!is_cross_zone_allowed(from_zone, to_zone, "staff")) {
        decision = TrustDecision::DENY;
        reason   = "Cross-zone routing denied: " + from_zone + " → " + to_zone;
    } else if (score >= 70) {
        decision = TrustDecision::ALLOW;
        reason   = "Trust score " + std::to_string(score) + " >= 70 — full access";
    } else if (score >= 40) {
        decision = TrustDecision::LIMITED;
        reason   = "Trust score " + std::to_string(score) + " — limited access";
    } else {
        decision = TrustDecision::QUARANTINE;
        reason   = "Trust score " + std::to_string(score) + " < 40 — quarantine";
    }

    log_decision(ctx, decision, reason);
    return decision;
}

void ZeroTrustEngine::log_decision(const AccessContext& ctx,
                                    TrustDecision decision,
                                    const std::string& reason)
{
    std::ostringstream payload;
    payload << "user=" << ctx.user_id
            << " device=" << ctx.device_id
            << " src=" << ctx.source_ip
            << " dst=" << ctx.destination_ip
            << " resource=" << ctx.requested_resource
            << " ssid=" << ctx.ssid_name
            << " score=" << ctx.trust_score
            << " decision=" << decision_str(decision)
            << " reason=" << reason;
    audit_adder_("zerotrust_decision", payload.str());
}

const char* ZeroTrustEngine::decision_str(TrustDecision d) noexcept
{
    switch (d) {
        case TrustDecision::ALLOW:        return "ALLOW";
        case TrustDecision::DENY:         return "DENY";
        case TrustDecision::QUARANTINE:   return "QUARANTINE";
        case TrustDecision::MFA_REQUIRED: return "MFA_REQUIRED";
        case TrustDecision::LIMITED:      return "LIMITED";
        default:                          return "UNKNOWN";
    }
}

} // namespace astartis::zerotrust

// Made with Bob
