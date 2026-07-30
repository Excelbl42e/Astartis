// test_segmentation.cpp — SSID config and VLAN isolation tests (Astartis v2.1)

#include "network_arch/segmentation/ssid_config.h"
#include <iostream>

static int g_failures = 0;
#define EXPECT(cond, msg) \
    do { if (!(cond)) { std::cerr << "FAIL [" << __LINE__ << "]: " << (msg) << "\n"; ++g_failures; } \
         else { std::cerr << "PASS: " << (msg) << "\n"; } } while(0)

using namespace astartis::network;

int main()
{
    std::cerr << "=== Segmentation Tests ===\n\n";

    auto pub  = make_public_ssid();
    auto ent  = make_enterprise_ssid();
    auto mgmt = make_management_ssid();

    // --- Test 1: SSID names are correct ---
    std::cerr << "--- Test 1: SSID names ---\n";
    EXPECT(pub.ssid_name == "SmartBots",      "Public SSID name is SmartBots");
    EXPECT(ent.ssid_name == "eGov",            "Enterprise SSID name is eGov");
    EXPECT(mgmt.ssid_name == "Astartis-Admin", "Management SSID name is Astartis-Admin");

    // --- Test 2: VLAN IDs are correct ---
    std::cerr << "\n--- Test 2: VLAN IDs ---\n";
    EXPECT(pub.vlan_id  == "VLAN_100", "Public VLAN is 100");
    EXPECT(ent.vlan_id  == "VLAN_200", "Enterprise VLAN is 200");
    EXPECT(mgmt.vlan_id == "VLAN_999", "Management VLAN is 999");

    // --- Test 3: Security posture correct ---
    std::cerr << "\n--- Test 3: Security postures ---\n";
    EXPECT(pub.posture  == SecurityPosture::FILTERED_INTERNET, "Public = FILTERED_INTERNET");
    EXPECT(ent.posture  == SecurityPosture::ZERO_TRUST,        "Enterprise = ZERO_TRUST");
    EXPECT(mgmt.posture == SecurityPosture::MANAGEMENT,        "Management = MANAGEMENT");

    // --- Test 4: Client isolation ---
    std::cerr << "\n--- Test 4: Client isolation ---\n";
    EXPECT(pub.client_isolation,   "Public SSID must isolate clients");
    EXPECT(!ent.client_isolation,  "Enterprise SSID does NOT isolate clients");
    EXPECT(mgmt.client_isolation,  "Management SSID must isolate clients");

    // --- Test 5: 802.1X requirements ---
    std::cerr << "\n--- Test 5: 802.1X requirements ---\n";
    EXPECT(!pub.requires_8021x,  "Public SSID does NOT require 802.1X");
    EXPECT(ent.requires_8021x,   "Enterprise SSID REQUIRES 802.1X");
    EXPECT(mgmt.requires_8021x,  "Management SSID REQUIRES 802.1X");

    // --- Test 6: Captive portal only on public ---
    std::cerr << "\n--- Test 6: Captive portal ---\n";
    EXPECT(!pub.captive_portal_url.empty(),  "Public SSID must have captive portal");
    EXPECT(ent.captive_portal_url.empty(),   "Enterprise SSID has no captive portal");

    // --- Test 7: VLAN isolation rules ---
    std::cerr << "\n--- Test 7: VLAN isolation (public must not reach enterprise) ---\n";
    EXPECT(!vlan_routing_allowed("VLAN_100", "VLAN_200"),
           "VLAN_100 (public) must NOT reach VLAN_200 (enterprise)");
    EXPECT(!vlan_routing_allowed("VLAN_100", "VLAN_999"),
           "VLAN_100 (public) must NOT reach VLAN_999 (management)");
    EXPECT(!vlan_routing_allowed("VLAN_200", "VLAN_999"),
           "VLAN_200 (enterprise) must NOT reach VLAN_999 (management)");
    EXPECT(vlan_routing_allowed("VLAN_200", "VLAN_200"),
           "VLAN_200 can route within itself");

    // --- Test 8: Bandwidth and timeout values ---
    std::cerr << "\n--- Test 8: Bandwidth and session timeouts ---\n";
    EXPECT(pub.bandwidth_limit_mbps == 10,
           "Public SSID bandwidth limited to 10Mbps");
    EXPECT(ent.bandwidth_limit_mbps == 0,
           "Enterprise SSID has no bandwidth limit (0 = unlimited)");
    EXPECT(pub.session_timeout_minutes == 60,
           "Public SSID session timeout is 60 minutes");
    EXPECT(ent.session_timeout_minutes == 0,
           "Enterprise SSID has no session timeout (continuous re-auth)");

    std::cerr << "\n=== Results ===\n";
    if (g_failures == 0) { std::cerr << "ALL TESTS PASSED\n"; return 0; }
    std::cerr << g_failures << " TEST(S) FAILED\n"; return 1;
}

// Made with Bob
