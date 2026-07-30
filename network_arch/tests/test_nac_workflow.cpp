// test_nac_workflow.cpp — NAC 8-step workflow tests (Astartis v2.1)
// Tests: compliant device, non-compliant, unknown user, public SSID, step count

#include "network_arch/zerotrust/nac_workflow.h"
#include <iostream>
#include <cassert>

static int g_failures = 0;
#define EXPECT(cond, msg) \
    do { if (!(cond)) { std::cerr << "FAIL [" << __LINE__ << "]: " << (msg) << "\n"; ++g_failures; } \
         else { std::cerr << "PASS: " << (msg) << "\n"; } } while(0)

using namespace astartis::zerotrust;

static AccessRequest make_compliant_request(const std::string& ssid = "eGov")
{
    AccessRequest r;
    r.device_mac  = "11:22:33:44:55:66";
    r.device_name = "IT-Laptop-001";
    r.ssid_name   = ssid;
    r.identity.username = "kgosi.blanda";
    r.identity.domain   = "egov.gov.bw";
    r.posture.os_updated        = true;
    r.posture.antivirus_running = true;
    r.posture.disk_encrypted    = true;
    r.posture.firewall_enabled  = true;
    r.posture.screen_lock_enabled = true;
    return r;
}

int main()
{
    std::cerr << "=== NAC Workflow Tests ===\n\n";
    NACWorkflow nac;

    // --- Test 1: Compliant device on eGov → ALLOW_FULL ---
    std::cerr << "--- Test 1: Compliant device on eGov ---\n";
    {
        auto r = make_compliant_request("eGov");
        auto d = nac.process(r);
        EXPECT(d.result == NACDecision::Result::ALLOW_FULL,
               "Compliant device on eGov should get ALLOW_FULL");
        EXPECT(d.assigned_vlan == "VLAN_200",
               "eGov full access should be VLAN_200");
        EXPECT(!d.accessible_resources.empty(),
               "it_admin should have accessible resources");
    }

    // --- Test 2: Non-compliant device (no disk encryption) → QUARANTINE ---
    std::cerr << "\n--- Test 2: Non-compliant device → QUARANTINE ---\n";
    {
        auto r = make_compliant_request("eGov");
        r.posture.disk_encrypted = false;
        auto d = nac.process(r);
        EXPECT(d.result == NACDecision::Result::QUARANTINE,
               "Non-compliant device should be QUARANTINE");
        EXPECT(d.assigned_vlan == "VLAN_300",
               "Quarantined device should get remediation VLAN");
        EXPECT(!d.remediation_reason.empty(),
               "Quarantine must include a remediation reason");
    }

    // --- Test 3: Public SSID (SmartBots) → ALLOW_LIMITED, no internal access ---
    std::cerr << "\n--- Test 3: Public SSID SmartBots → ALLOW_LIMITED ---\n";
    {
        auto r = make_compliant_request("SmartBots");
        auto d = nac.process(r);
        EXPECT(d.result == NACDecision::Result::ALLOW_LIMITED,
               "SmartBots SSID should get ALLOW_LIMITED");
        EXPECT(d.assigned_vlan == "VLAN_100",
               "SmartBots should get VLAN_100");
        EXPECT(d.accessible_resources.empty(),
               "Public SSID should have no internal resources");
    }

    // --- Test 4: Unknown user on eGov → DENY ---
    std::cerr << "\n--- Test 4: Unknown user → DENY ---\n";
    {
        auto r = make_compliant_request("eGov");
        r.identity.username = "unknown.intruder";
        auto d = nac.process(r);
        EXPECT(d.result == NACDecision::Result::DENY,
               "Unknown user on eGov should be DENY");
    }

    // --- Test 5: Verbose output has exactly 8 steps ---
    std::cerr << "\n--- Test 5: Verbose process returns exactly 8 steps ---\n";
    {
        auto r = make_compliant_request("eGov");
        auto steps = nac.process_verbose(r);
        EXPECT(steps.size() == 8u,
               "NAC workflow must execute exactly 8 steps");
        // Step 7 (CONTINUOUS_MONITOR) should always pass
        EXPECT(steps[6].passed,
               "CONTINUOUS_MONITOR step should always pass");
        // Step 8 (REMEDIATE) — compliant device: no remediation needed
        EXPECT(steps[7].passed,
               "REMEDIATE step passed means no remediation needed (compliant)");
    }

    // --- Test 6: is_compliant helper logic ---
    std::cerr << "\n--- Test 6: is_compliant covers all four required flags ---\n";
    {
        DevicePosture p;
        EXPECT(!NACWorkflow::is_compliant(p), "All-false posture is non-compliant");
        p.os_updated = true; p.antivirus_running = true;
        p.disk_encrypted = true; p.firewall_enabled = true;
        EXPECT(NACWorkflow::is_compliant(p), "All-true posture is compliant");
        p.antivirus_running = false;
        EXPECT(!NACWorkflow::is_compliant(p), "Missing AV is non-compliant");
    }

    // --- Test 7: 802.1X not required on SmartBots ---
    std::cerr << "\n--- Test 7: 802.1X not required on SmartBots ---\n";
    {
        IdentityCredentials empty_creds;
        EXPECT(nac.authenticate_8021x("SmartBots", empty_creds),
               "SmartBots should not require 802.1X");
        EXPECT(!nac.authenticate_8021x("eGov", empty_creds),
               "eGov with empty creds should fail 802.1X");
    }

    std::cerr << "\n=== Results ===\n";
    if (g_failures == 0) { std::cerr << "ALL TESTS PASSED\n"; return 0; }
    std::cerr << g_failures << " TEST(S) FAILED\n"; return 1;
}

// Made with Bob
