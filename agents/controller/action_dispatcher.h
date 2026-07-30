// action_dispatcher.h -- AI agent output → real action dispatch (Astartis v3.0)
//
// Parses structured JSON output from agents and dispatches real protective
// actions: firewall blocks, file quarantine, deception responses, ZT denials.
//
// Every dispatch attempt (success or failure) writes an audit entry.
// Policy checks are applied before every action — unauthorized agents
// receive advisory-only handling.

#pragma once
#include <string>
#include <functional>

#include "core/firewall/firewall_blocker.h"
#include "core/quarantine/quarantine.h"
#include "core/active_response/active_response.h"
#include "network_arch/zerotrust/zerotrust_engine.h"

namespace astartis {

class ActionDispatcher {
public:
    struct DispatchResult {
        bool        action_taken;
        std::string action_type;     ///< "firewall_block"|"quarantine"|"deception"|"zerotrust_deny"|"advisory"
        std::string target;          ///< IP, file path, session ID, or MAC
        std::string audit_entry_id;
        std::string error_message;   ///< empty if success
    };

    explicit ActionDispatcher(
        firewall::FirewallBlocker&               fw,
        quarantine::Quarantine&                  qtn,
        active_response::ActiveResponse&         ar,
        zerotrust::ZeroTrustEngine&              zt,
        std::function<std::string(const std::string&, const std::string&)> audit_adder
    );

    /// Main entry point: parse agent JSON output, check policy, dispatch action.
    /// Returns immediately if agent is not authorized for any action.
    DispatchResult dispatch(const std::string& agent_name,
                            const std::string& agent_output_json);

    /// Return true if ip is a private/loopback/reserved address (never blocked).
    static bool is_safe_ip(const std::string& ip);

    /// Extract the first IPv4 address from a string. Returns "" if none found.
    static std::string extract_ipv4(const std::string& text);

    /// Extract the first Windows file path from a string. Returns "" if none.
    static std::string extract_filepath(const std::string& text);

private:
    /// Try to extract and block an IP from containment_actions or iocs_found.
    bool try_firewall_block(const std::string& output_json,
                            const std::string& agent_name,
                            DispatchResult& out);

    /// Try to quarantine a file path from recommended_detections or eradication_steps.
    bool try_quarantine(const std::string& output_json,
                        const std::string& agent_name,
                        DispatchResult& out);

    /// Try to trigger deception response from eradication_steps.
    bool try_deception(const std::string& output_json,
                       const std::string& agent_name,
                       DispatchResult& out);

    /// Try to trigger a ZeroTrust deny from recovery_checklist.
    bool try_zerotrust_deny(const std::string& output_json,
                             const std::string& agent_name,
                             DispatchResult& out);

    firewall::FirewallBlocker&               fw_;
    quarantine::Quarantine&                  qtn_;
    active_response::ActiveResponse&         ar_;
    zerotrust::ZeroTrustEngine&              zt_;
    std::function<std::string(const std::string&, const std::string&)> audit_adder_;
};

} // namespace astartis

// Made with Bob
