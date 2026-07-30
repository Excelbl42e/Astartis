// test_zerotrust_decisions.cpp — Zero Trust engine decision matrix tests (Astartis v2.1)

#include "network_arch/zerotrust/zerotrust_engine.h"
#include <iostream>
#include <cassert>

static int g_failures = 0;
#define EXPECT(cond, msg) \
    do { if (!(cond)) { std::cerr << "FAIL [" << __LINE__ << "]: " << (msg) << "\n"; ++g_failures; } \
         else { std::cerr << "PASS: " << (msg) << "\n"; } } while(0)

using namespace astartis::zerotrust;

static std::string test_audit(const std::string&, const std::string&) {
    static int n = 0; return "zt_" + std::to_string(++n);
}

int main()
{
    std::cerr << "=== Zero Trust Decision Tests ===\n\n";

    ZeroTrustEngine engine(test_audit);

    // --- Test 1: Public → Enterprise cross-zone routing → DENY ---
    std::cerr << "--- Test 1: VLAN_100 → VLAN_200 cross-zone → DENY ---\n";
    {
        AccessContext ctx;
        ctx.user_id            = "kgosi.blanda";
        ctx.device_id          = "Laptop-001";
        ctx.source_ip          = "192.168.100.50";   // Public VLAN
        ctx.destination_ip     = "10.0.200.10";      // Enterprise VLAN
        ctx.requested_resource = "file-server";
        ctx.ssid_name          = "SmartBots";

        auto d = engine.evaluate(ctx);
        EXPECT(d == TrustDecision::DENY,
               "Public→Enterprise cross-zone must be DENY");
    }

    // --- Test 2: Same-zone enterprise access with high trust → ALLOW ---
    std::cerr << "\n--- Test 2: Enterprise → Enterprise high-trust → ALLOW ---\n";
    {
        AccessContext ctx;
        ctx.user_id            = "kgosi.blanda";
        ctx.device_id          = "IT-Laptop-001";
        ctx.source_ip          = "10.0.200.50";
        ctx.destination_ip     = "10.0.200.10";
        ctx.requested_resource = "file-server";
        ctx.ssid_name          = "eGov";

        auto d = engine.evaluate(ctx);
        EXPECT(d == TrustDecision::ALLOW,
               "Enterprise same-zone high-trust should ALLOW");

        int score = engine.calculate_trust_score(ctx);
        EXPECT(score >= 70, "High-trust context should score >= 70");
    }

    // --- Test 3: Anomalous behavior → MFA_REQUIRED ---
    std::cerr << "\n--- Test 3: Anomalous action → MFA_REQUIRED ---\n";
    {
        AccessContext ctx;
        ctx.user_id            = "kgosi.blanda";
        ctx.device_id          = "Laptop-001";
        ctx.source_ip          = "10.0.200.50";
        ctx.destination_ip     = "10.0.200.10";
        ctx.requested_resource = "mass_download";   // triggers anomaly flag
        ctx.ssid_name          = "eGov";

        auto d = engine.evaluate(ctx);
        EXPECT(d == TrustDecision::MFA_REQUIRED,
               "Anomalous action should require MFA");
    }

    // --- Test 4: Unknown user with low-trust score → QUARANTINE ---
    std::cerr << "\n--- Test 4: Unknown user → QUARANTINE (score < 40) ---\n";
    {
        AccessContext ctx;
        ctx.user_id            = "completely.unknown";
        ctx.device_id          = "Rogue-Device";
        ctx.source_ip          = "10.0.200.99";
        ctx.destination_ip     = "10.0.200.10";
        ctx.requested_resource = "admin-portal";
        ctx.ssid_name          = "eGov";

        int score = engine.calculate_trust_score(ctx);
        EXPECT(score < 40, "Unknown user should have trust score < 40");
        auto d = engine.evaluate(ctx);
        EXPECT(d == TrustDecision::QUARANTINE || d == TrustDecision::DENY,
               "Unknown user with low score should QUARANTINE or DENY");
    }

    // --- Test 5: Cross-zone policy check helpers ---
    std::cerr << "\n--- Test 5: Cross-zone allowed() helpers ---\n";
    {
        EXPECT(!engine.is_cross_zone_allowed("public", "enterprise", "guest"),
               "public→enterprise must not be allowed for any role");
        EXPECT(!engine.is_cross_zone_allowed("public", "management", "it_admin"),
               "public→management must not be allowed");
        EXPECT(!engine.is_cross_zone_allowed("quarantine", "enterprise", "it_admin"),
               "quarantine zone cannot reach anywhere");
        EXPECT(engine.is_cross_zone_allowed("enterprise", "enterprise", "it_admin"),
               "enterprise→enterprise allowed for it_admin");
    }

    // --- Test 6: decision_str() covers all enum values ---
    std::cerr << "\n--- Test 6: decision_str() round-trips ---\n";
    {
        EXPECT(std::string(ZeroTrustEngine::decision_str(TrustDecision::ALLOW)) == "ALLOW",
               "ALLOW str");
        EXPECT(std::string(ZeroTrustEngine::decision_str(TrustDecision::DENY)) == "DENY",
               "DENY str");
        EXPECT(std::string(ZeroTrustEngine::decision_str(TrustDecision::MFA_REQUIRED)) == "MFA_REQUIRED",
               "MFA_REQUIRED str");
        EXPECT(std::string(ZeroTrustEngine::decision_str(TrustDecision::QUARANTINE)) == "QUARANTINE",
               "QUARANTINE str");
        EXPECT(std::string(ZeroTrustEngine::decision_str(TrustDecision::LIMITED)) == "LIMITED",
               "LIMITED str");
    }

    std::cerr << "\n=== Results ===\n";
    if (g_failures == 0) { std::cerr << "ALL TESTS PASSED\n"; return 0; }
    std::cerr << g_failures << " TEST(S) FAILED\n"; return 1;
}

// Made with Bob
