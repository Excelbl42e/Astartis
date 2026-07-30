// ssid_config.h -- Multi-SSID network segmentation (Astartis v2.1)
// Models the PUBLIC "SmartBots" (guest/BYOD) and ENTERPRISE "eGov" SSIDs.
// This is a simulation module — all values are real-world correct configs.

#pragma once
#include <string>
#include <optional>

namespace astartis::network {

enum class SecurityPosture {
    FILTERED_INTERNET,  ///< PUBLIC: Guest/BYOD — internet only, no internal access
    ZERO_TRUST,         ///< ENTERPRISE: Full NAC + 802.1X + micro-segmentation
    MANAGEMENT          ///< Admin backplane — restricted to infrastructure roles
};

struct SSIDConfig {
    std::string ssid_name;
    std::string vlan_id;
    std::string ip_subnet;
    std::string gateway;
    SecurityPosture posture;
    bool client_isolation;      ///< Prevent direct client-to-client traffic
    bool requires_8021x;        ///< Enforce 802.1X authentication
    std::string captive_portal_url; ///< Empty = no captive portal
    int bandwidth_limit_mbps;   ///< 0 = unlimited
    int session_timeout_minutes;///< 0 = no timeout (re-auth via 802.1X)
};

// ---------------------------------------------------------------------------
// PUBLIC SSID: SmartBots — Guest / BYOD
// Internet-only. Client-isolated. Captive portal for registration.
// MUST NEVER reach ENTERPRISE VLAN resources.
// ---------------------------------------------------------------------------
inline SSIDConfig make_public_ssid()
{
    SSIDConfig s;
    s.ssid_name              = "SmartBots";
    s.vlan_id                = "VLAN_100";
    s.ip_subnet              = "192.168.100.0/24";
    s.gateway                = "192.168.100.1";
    s.posture                = SecurityPosture::FILTERED_INTERNET;
    s.client_isolation       = true;
    s.requires_8021x         = false;
    s.captive_portal_url     = "http://captive.astartis.local";
    s.bandwidth_limit_mbps   = 10;
    s.session_timeout_minutes= 60;
    return s;
}

// ---------------------------------------------------------------------------
// ENTERPRISE SSID: eGov — Secure internal
// Zero Trust enforced. 802.1X required. Posture check before access.
// ---------------------------------------------------------------------------
inline SSIDConfig make_enterprise_ssid()
{
    SSIDConfig s;
    s.ssid_name              = "eGov";
    s.vlan_id                = "VLAN_200";
    s.ip_subnet              = "10.0.200.0/24";
    s.gateway                = "10.0.200.1";
    s.posture                = SecurityPosture::ZERO_TRUST;
    s.client_isolation       = false;
    s.requires_8021x         = true;
    s.captive_portal_url     = "";
    s.bandwidth_limit_mbps   = 0;       // Unlimited for enterprise
    s.session_timeout_minutes= 0;       // No timeout — continuous re-auth
    return s;
}

// ---------------------------------------------------------------------------
// MANAGEMENT SSID: Astartis-Admin — Infrastructure backplane
// ---------------------------------------------------------------------------
inline SSIDConfig make_management_ssid()
{
    SSIDConfig s;
    s.ssid_name              = "Astartis-Admin";
    s.vlan_id                = "VLAN_999";
    s.ip_subnet              = "10.0.99.0/24";
    s.gateway                = "10.0.99.1";
    s.posture                = SecurityPosture::MANAGEMENT;
    s.client_isolation       = true;
    s.requires_8021x         = true;
    s.captive_portal_url     = "";
    s.bandwidth_limit_mbps   = 100;
    s.session_timeout_minutes= 30;
    return s;
}

// ---------------------------------------------------------------------------
// VLAN isolation check — PUBLIC must NEVER reach ENTERPRISE
// ---------------------------------------------------------------------------
inline bool vlan_routing_allowed(const std::string& from_vlan,
                                  const std::string& to_vlan)
{
    // Hard rule: VLAN_100 (public) cannot route to VLAN_200 (enterprise)
    if (from_vlan == "VLAN_100" && to_vlan == "VLAN_200") return false;
    if (from_vlan == "VLAN_100" && to_vlan == "VLAN_999") return false;
    if (from_vlan == "VLAN_200" && to_vlan == "VLAN_999") return false;
    return true;
}

} // namespace astartis::network

// Made with Bob
