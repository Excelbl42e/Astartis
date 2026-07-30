// policy_engine.cpp -- Agent action authorization policy (Astartis v3.0)

#include "agents/controller/policy_engine.h"
#include <algorithm>

namespace astartis {

// Authorized agents for each action type — add agent names here as needed.
// Names must match the "name" field in the agent's JSON definition exactly.

static const char* FIREWALL_BLOCK_AGENTS[] = {
    "incident_responder",
    "breach_simulator",
    "red_team_coord",
    "ransomware_hunter",
    nullptr
};

static const char* QUARANTINE_AGENTS[] = {
    "malware_analyst",
    "forensics_agent",
    "forensics_investigator",
    "threat_hunter",
    nullptr
};

static const char* DECEPTION_AGENTS[] = {
    "deception_engineer",
    "purple_team",
    nullptr
};

static const char* ZEROTRUST_DENY_AGENTS[] = {
    "zero_trust_engineer",
    "iam_privilege_auditor",
    nullptr
};

static bool name_in(const char* const* list, const std::string& name)
{
    for (int i = 0; list[i] != nullptr; ++i) {
        if (name == list[i]) return true;
    }
    return false;
}

bool PolicyEngine::can_block_firewall(const std::string& agent_name)
{
    return name_in(FIREWALL_BLOCK_AGENTS, agent_name);
}

bool PolicyEngine::can_quarantine(const std::string& agent_name)
{
    return name_in(QUARANTINE_AGENTS, agent_name);
}

bool PolicyEngine::can_deceive(const std::string& agent_name)
{
    return name_in(DECEPTION_AGENTS, agent_name);
}

bool PolicyEngine::can_zerotrust_deny(const std::string& agent_name)
{
    return name_in(ZEROTRUST_DENY_AGENTS, agent_name);
}

bool PolicyEngine::require_human_approval(const std::string& /*action_type*/)
{
    // Future escalation gate — for now all authorized actions auto-dispatch
    return false;
}

} // namespace astartis

// Made with Bob
