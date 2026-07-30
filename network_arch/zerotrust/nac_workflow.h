// nac_workflow.h -- 8-step NAC simulation (Astartis v2.1)
// Models 802.1X → AD/LDAP → posture check → RBAC → continuous monitoring.

#pragma once
#include <string>
#include <vector>
#include <chrono>
#include <functional>

namespace astartis::zerotrust {

// ---------------------------------------------------------------------------
// Device posture
// ---------------------------------------------------------------------------
struct DevicePosture {
    bool os_updated             = false;
    bool antivirus_running      = false;
    bool disk_encrypted         = false;
    bool firewall_enabled       = false;
    bool screen_lock_enabled    = false;
    std::string os_version;
    std::string last_update_date;
    int critical_patches_missing = 0;
};

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------
struct IdentityCredentials {
    std::string username;
    std::string domain;           ///< e.g. "egov.gov.bw"
    bool certificate_based = false;
    std::string cert_thumbprint;
};

// ---------------------------------------------------------------------------
// Inbound access request
// ---------------------------------------------------------------------------
struct AccessRequest {
    std::string         device_mac;
    std::string         device_name;
    std::string         ssid_name;
    IdentityCredentials identity;
    DevicePosture       posture;
};

// ---------------------------------------------------------------------------
// NAC decision
// ---------------------------------------------------------------------------
struct NACDecision {
    enum class Result {
        ALLOW_FULL,     ///< Full enterprise access — compliant + authenticated
        ALLOW_LIMITED,  ///< Quarantine VLAN — limited resources, must remediate
        MFA_REQUIRED,   ///< Additional authentication factor needed
        QUARANTINE,     ///< Remediation VLAN — no internal access
        DENY            ///< Block completely — unknown device or malicious
    };

    Result      result;
    std::string assigned_vlan;
    std::string assigned_role;
    std::vector<std::string> accessible_resources;
    std::string remediation_reason;
    std::chrono::seconds reauth_interval{3600};
};

// ---------------------------------------------------------------------------
// NACWorkflow — 8-step execution
// ---------------------------------------------------------------------------
class NACWorkflow {
public:
    enum class Step {
        CONNECT            = 1, ///< Device connects to SSID
        AUTH_8021X         = 2, ///< 802.1X authentication initiated
        VERIFY_IDENTITY    = 3, ///< Check AD/LDAP
        POSTURE_CHECK      = 4, ///< Device health / compliance
        APPLY_POLICY       = 5, ///< Quarantine vs full access decision
        RBAC_ASSIGN        = 6, ///< Role-based resource access
        CONTINUOUS_MONITOR = 7, ///< Periodic re-check
        REMEDIATE          = 8  ///< Non-compliant → remediation VLAN
    };

    struct StepResult {
        Step        step;
        bool        passed;
        std::string detail;
        std::chrono::milliseconds duration_ms{0};
    };

    /**
     * @brief Process the full 8-step NAC workflow.
     * @return Final NACDecision with assigned VLAN and role.
     */
    NACDecision process(const AccessRequest& req);

    /**
     * @brief Process with per-step detail (for dashboard visualization).
     */
    std::vector<StepResult> process_verbose(const AccessRequest& req);

    // --- Subcomponent functions (public for testability) ---

    /// Simulated 802.1X auth (production: RADIUS server call)
    bool authenticate_8021x(const std::string& ssid_name,
                             const IdentityCredentials& creds);

    /// Simulated AD/LDAP identity check
    bool verify_identity(const IdentityCredentials& creds);

    /// Determine assigned role from identity
    std::string determine_role(const std::string& username,
                               const std::string& domain);

    /// Get allowed resources for a role
    std::vector<std::string> resources_for_role(const std::string& role);

    /// True if ALL required posture flags are set
    static bool is_compliant(const DevicePosture& posture) noexcept {
        return posture.os_updated
            && posture.antivirus_running
            && posture.disk_encrypted
            && posture.firewall_enabled;
    }

    /// True if device MAC is in simulated known-device registry
    static bool is_known_device(const std::string& mac);

private:
    NACDecision build_decision(bool identity_ok, bool posture_ok,
                                const std::string& role,
                                const std::string& ssid_name);
};

} // namespace astartis::zerotrust

// Made with Bob
