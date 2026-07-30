// zerotrust_engine.h -- Zero Trust decision engine (Astartis v2.1)
// Implements: Never trust, always verify. Assume breach. Least privilege.

#pragma once
#include <string>
#include <map>
#include <functional>

namespace astartis::zerotrust {

enum class TrustDecision { ALLOW, DENY, QUARANTINE, MFA_REQUIRED, LIMITED };

struct AccessContext {
    std::string user_id;
    std::string device_id;
    std::string source_ip;
    std::string destination_ip;
    std::string requested_resource;
    std::string ssid_name;
    int         trust_score = 0;   ///< 0–100, calculated by engine
};

class ZeroTrustEngine {
public:
    explicit ZeroTrustEngine(
        std::function<std::string(const std::string&, const std::string&)> audit_adder
    );

    /// Evaluate access, audit the decision, return verdict.
    TrustDecision evaluate(const AccessContext& ctx);

    /// Calculate trust score (0=untrusted, 100=fully trusted).
    int calculate_trust_score(const AccessContext& ctx);

    /// Check whether cross-zone routing is allowed for a given role.
    bool is_cross_zone_allowed(const std::string& from_zone,
                               const std::string& to_zone,
                               const std::string& role);

    /// Simulated behavioral anomaly detection.
    bool is_anomalous_behavior(const std::string& user_id,
                               const std::string& action);

    void log_decision(const AccessContext& ctx,
                      TrustDecision decision,
                      const std::string& reason);

    static const char* decision_str(TrustDecision d) noexcept;

private:
    std::function<std::string(const std::string&, const std::string&)> audit_adder_;
    // subnet → zone name
    std::map<std::string, std::string> zone_map_;
    // zone → allowed roles
    std::map<std::string, std::vector<std::string>> zone_policies_;
};

} // namespace astartis::zerotrust

// Made with Bob
