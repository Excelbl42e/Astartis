// policy_engine.h -- Agent action authorization policy (Astartis v3.0)
//
// Defines which agents may trigger which real-world actions.
// All other agents are advisory-only — they produce recommendations
// that a human or authorized agent must approve before execution.

#pragma once
#include <string>

namespace astartis {

class PolicyEngine {
public:
    // ---------------------------------------------------------------------------
    // Per-action authorization checks
    // ---------------------------------------------------------------------------

    /// Can this agent trigger a Windows Firewall block rule?
    /// Authorized: incident_responder, breach_simulator, red_team_coord, ransomware_hunter
    static bool can_block_firewall(const std::string& agent_name);

    /// Can this agent move a file to quarantine?
    /// Authorized: malware_analyst, forensics_agent, forensics_investigator, threat_hunter
    static bool can_quarantine(const std::string& agent_name);

    /// Can this agent trigger a deception/active-response serve?
    /// Authorized: deception_engineer, purple_team
    static bool can_deceive(const std::string& agent_name);

    /// Can this agent trigger a Zero Trust DENY decision?
    /// Authorized: zero_trust_engineer, iam_privilege_auditor
    static bool can_zerotrust_deny(const std::string& agent_name);

    // ---------------------------------------------------------------------------
    // Global safety limits
    // ---------------------------------------------------------------------------

    /// Maximum simultaneous active firewall blocks before human approval required
    static int max_concurrent_blocks()   { return 100; }

    /// Maximum file quarantines per hour before human approval required
    static int max_quarantine_per_hour() { return 50;  }

    /// Returns true if this action type requires human approval
    /// before being dispatched (currently: none — all are auto-dispatched
    /// within policy, but this hook is available for future escalation gates)
    static bool require_human_approval(const std::string& action_type);
};

} // namespace astartis

// Made with Bob
