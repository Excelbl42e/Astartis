// nac_workflow.cpp -- 8-step NAC simulation (Astartis v2.1)

#include "network_arch/zerotrust/nac_workflow.h"
#include <algorithm>
#include <chrono>
#include <map>
#include <set>

using namespace std::chrono_literals;

namespace astartis::zerotrust {

// ---------------------------------------------------------------------------
// Simulated known-device registry (production: CMDB or endpoint manager)
// ---------------------------------------------------------------------------
static const std::set<std::string> KNOWN_DEVICES = {
    "aa:bb:cc:dd:ee:ff",   // Desktop-001
    "11:22:33:44:55:66",   // Laptop-IT-001
    "de:ad:be:ef:00:01",   // Laptop-IT-002
};

// Simulated AD/LDAP user → role mapping (production: LDAP group lookup)
static const std::map<std::string, std::string> USER_ROLES = {
    {"kgosi.blanda",    "it_admin"},
    {"admin",           "it_admin"},
    {"user1",           "staff"},
    {"user2",           "staff"},
    {"contractor1",     "contractor"},
    {"guest",           "guest"},
};

// Role → accessible resources
static const std::map<std::string, std::vector<std::string>> ROLE_RESOURCES = {
    {"it_admin",   {"file-server", "admin-portal", "print-server", "dc01", "backup-repo"}},
    {"staff",      {"file-server", "print-server", "intranet"}},
    {"contractor", {"intranet"}},
    {"guest",      {}},
};

// ---------------------------------------------------------------------------

bool NACWorkflow::is_known_device(const std::string& mac)
{
    std::string lower_mac = mac;
    std::transform(lower_mac.begin(), lower_mac.end(), lower_mac.begin(),
                   [](unsigned char c){ return std::tolower(c); });
    return KNOWN_DEVICES.count(lower_mac) > 0;
}

bool NACWorkflow::authenticate_8021x(const std::string& ssid_name,
                                      const IdentityCredentials& creds)
{
    // Public SSID doesn't require 802.1X
    if (ssid_name == "SmartBots") return true;
    // Check username is non-empty (production: RADIUS EAP-TLS)
    return !creds.username.empty() && !creds.domain.empty();
}

bool NACWorkflow::verify_identity(const IdentityCredentials& creds)
{
    // Simulated AD/LDAP check: user must exist in directory
    return USER_ROLES.count(creds.username) > 0;
}

std::string NACWorkflow::determine_role(const std::string& username,
                                         const std::string& /*domain*/)
{
    auto it = USER_ROLES.find(username);
    return (it != USER_ROLES.end()) ? it->second : "guest";
}

std::vector<std::string> NACWorkflow::resources_for_role(const std::string& role)
{
    auto it = ROLE_RESOURCES.find(role);
    return (it != ROLE_RESOURCES.end()) ? it->second : std::vector<std::string>{};
}

NACDecision NACWorkflow::build_decision(bool identity_ok, bool posture_ok,
                                         const std::string& role,
                                         const std::string& ssid_name)
{
    NACDecision d;

    if (ssid_name == "SmartBots") {
        // Public SSID: always filtered internet, no internal resources
        d.result               = NACDecision::Result::ALLOW_LIMITED;
        d.assigned_vlan        = "VLAN_100";
        d.assigned_role        = "guest";
        d.accessible_resources = {};
        d.remediation_reason   = "";
        d.reauth_interval      = 3600s;
        return d;
    }

    if (!identity_ok) {
        d.result             = NACDecision::Result::DENY;
        d.assigned_vlan      = "";
        d.assigned_role      = "none";
        d.remediation_reason = "Identity verification failed — unknown user or bad credentials";
        return d;
    }

    if (!posture_ok) {
        d.result             = NACDecision::Result::QUARANTINE;
        d.assigned_vlan      = "VLAN_300";   // Remediation VLAN
        d.assigned_role      = "quarantine";
        d.remediation_reason = "Device posture non-compliant — run OS updates and enable encryption";
        d.reauth_interval    = 300s;          // Re-check every 5 minutes
        return d;
    }

    // Full access
    d.result               = NACDecision::Result::ALLOW_FULL;
    d.assigned_vlan        = "VLAN_200";
    d.assigned_role        = role;
    d.accessible_resources = resources_for_role(role);
    d.remediation_reason   = "";
    d.reauth_interval      = 3600s;
    return d;
}

// ---------------------------------------------------------------------------
// Core 8-step workflow
// ---------------------------------------------------------------------------
NACDecision NACWorkflow::process(const AccessRequest& req)
{
    bool identity_ok = authenticate_8021x(req.ssid_name, req.identity)
                    && verify_identity(req.identity);
    bool posture_ok  = is_compliant(req.posture);
    std::string role = identity_ok ? determine_role(req.identity.username,
                                                     req.identity.domain) : "guest";
    return build_decision(identity_ok, posture_ok, role, req.ssid_name);
}

std::vector<NACWorkflow::StepResult> NACWorkflow::process_verbose(const AccessRequest& req)
{
    std::vector<StepResult> steps;
    steps.reserve(8);

    auto make_step = [](Step s, bool ok, const std::string& detail) {
        return StepResult{s, ok, detail, std::chrono::milliseconds(1)};
    };

    // Step 1: CONNECT
    steps.push_back(make_step(Step::CONNECT, true,
        "Device " + req.device_name + " (" + req.device_mac + ") connected to " + req.ssid_name));

    // Step 2: AUTH_8021X
    bool auth_ok = authenticate_8021x(req.ssid_name, req.identity);
    steps.push_back(make_step(Step::AUTH_8021X, auth_ok,
        auth_ok ? "802.1X EAP accepted for " + req.identity.username + "@" + req.identity.domain
                : "802.1X EAP rejected — missing credentials"));

    // Step 3: VERIFY_IDENTITY
    bool id_ok = auth_ok && verify_identity(req.identity);
    steps.push_back(make_step(Step::VERIFY_IDENTITY, id_ok,
        id_ok ? "AD/LDAP: user '" + req.identity.username + "' found in directory"
              : "AD/LDAP: user '" + req.identity.username + "' not found"));

    // Step 4: POSTURE_CHECK
    bool posture_ok = is_compliant(req.posture);
    std::string posture_detail;
    if (posture_ok) {
        posture_detail = "Device posture compliant (OS updated, AV running, disk encrypted, firewall on)";
    } else {
        posture_detail = "Posture NON-COMPLIANT:";
        if (!req.posture.os_updated)          posture_detail += " [OS not updated]";
        if (!req.posture.antivirus_running)    posture_detail += " [AV not running]";
        if (!req.posture.disk_encrypted)       posture_detail += " [disk not encrypted]";
        if (!req.posture.firewall_enabled)     posture_detail += " [firewall disabled]";
    }
    steps.push_back(make_step(Step::POSTURE_CHECK, posture_ok, posture_detail));

    // Step 5: APPLY_POLICY
    std::string role = id_ok ? determine_role(req.identity.username, req.identity.domain) : "guest";
    auto decision = build_decision(id_ok, posture_ok, role, req.ssid_name);
    bool policy_ok = (decision.result == NACDecision::Result::ALLOW_FULL
                   || decision.result == NACDecision::Result::ALLOW_LIMITED);
    steps.push_back(make_step(Step::APPLY_POLICY, policy_ok,
        "Policy: VLAN=" + decision.assigned_vlan + " role=" + decision.assigned_role));

    // Step 6: RBAC_ASSIGN
    steps.push_back(make_step(Step::RBAC_ASSIGN, policy_ok && id_ok,
        "RBAC: role=" + role + " resources=" + std::to_string(decision.accessible_resources.size())));

    // Step 7: CONTINUOUS_MONITOR
    steps.push_back(make_step(Step::CONTINUOUS_MONITOR, true,
        "Continuous monitoring enabled — reauth in " +
        std::to_string(decision.reauth_interval.count()) + "s"));

    // Step 8: REMEDIATE (only relevant when quarantined)
    bool needs_remediation = (decision.result == NACDecision::Result::QUARANTINE
                           || decision.result == NACDecision::Result::DENY);
    steps.push_back(make_step(Step::REMEDIATE, !needs_remediation,
        needs_remediation
            ? "Remediation required: " + decision.remediation_reason
            : "No remediation needed"));

    return steps;
}

} // namespace astartis::zerotrust

// Made with Bob
