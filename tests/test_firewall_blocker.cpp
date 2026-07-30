// Step 16 ST-4 -- FirewallBlocker test
//
// Tests:
//  A. Allowlist check: 127.0.0.1 is never blocked (no netsh call needed)
//  B. Real block on 240.0.0.1 (IANA reserved / TEST-NET-4, unroutable):
//       - block() returns blocked=true
//       - netsh show rule confirms the rule exists
//       - is_blocked() returns true during TTL
//       - wait for TTL expiry (10 s) — rule auto-removed
//       - is_blocked() returns false after expiry
//       - audit chain has both firewall_block and firewall_unblock entries
//  C. is_blocked() reflects state correctly during and after the TTL
//
// Exit code 2 = not elevated (skip, not fail — same pattern as ClamdScannerTest).

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <cassert>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>

// Windows elevation check
#include <winsock2.h>
#include <windows.h>

#include "audit_chain/audit_chain.h"
#include "firewall/firewall_blocker.h"

using namespace astartis::audit;
using namespace astartis::firewall;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Check if a netsh rule with the given name exists.
// Runs: netsh advfirewall firewall show rule name="<name>" > NUL 2>&1
// Returns true if the command exits with code 0 (rule found).
static bool rule_exists_in_netsh(const std::string& name)
{
    std::string cmd =
        "netsh advfirewall firewall show rule name=\"" + name + "\" >NUL 2>&1";
    return std::system(cmd.c_str()) == 0;
}

static bool is_elevated_process()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    TOKEN_ELEVATION elev{};
    DWORD sz = sizeof(elev);
    BOOL ok = GetTokenInformation(token, TokenElevation, &elev, sz, &sz);
    CloseHandle(token);
    return ok && elev.TokenIsElevated != 0;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    std::cout << "========================================\n"
              << "ASTARTIS FIREWALL BLOCKER TEST          \n"
              << "Step 16 ST-4                            \n"
              << "========================================\n";

    // Skip gracefully if not elevated
    if (!is_elevated_process()) {
        std::cout << "[SKIP] Process is not elevated — "
                     "run from an Administrator terminal to exercise netsh.\n";
        return 2;
    }
    std::cout << "[INFO] Process is elevated — proceeding with netsh tests.\n";

    AuditChain chain;
    auto audit_adder = [&](const std::string& et, const std::string& pl) {
        return chain.add_entry(et, pl);
    };

    // Use a 10-second TTL so the auto-expiry test completes quickly
    constexpr int TEST_TTL_S = 10;
    // Test IP: 240.0.0.1 — IANA Class E reserved / TEST-NET-4 (0xF0000001)
    // Unroutable on any real network; safe to block temporarily.
    const std::string TEST_IP = "240.0.0.1";

    FirewallBlocker fw(audit_adder, TEST_TTL_S);

    // -----------------------------------------------------------------------
    // Test A: allowlist rejects 127.0.0.1 before any netsh call
    // -----------------------------------------------------------------------
    {
        BlockResult r = fw.block("127.0.0.1", TEST_TTL_S);
        assert(!r.blocked && "127.0.0.1 must never be blocked");
        assert(r.reason.find("allowlist") != std::string::npos
               && "reason must mention allowlist");
        assert(!fw.is_blocked("127.0.0.1"));
        std::cout << "[PASS] Test A: 127.0.0.1 rejected by allowlist\n";
        std::cout << "       reason: " << r.reason << "\n";
    }

    // -----------------------------------------------------------------------
    // Test B: real block on 240.0.0.1
    // -----------------------------------------------------------------------
    {
        BlockResult r = fw.block(TEST_IP, TEST_TTL_S);
        assert(r.blocked && "block() must succeed for 240.0.0.1");
        assert(!r.rule_name_in.empty() && !r.rule_name_out.empty());
        std::cout << "[PASS] Test B-1: block() returned blocked=true\n";
        std::cout << "       rule_in:  " << r.rule_name_in  << "\n";
        std::cout << "       rule_out: " << r.rule_name_out << "\n";

        // Confirm rules actually exist in Windows Firewall
        assert(rule_exists_in_netsh(r.rule_name_in)
               && "inbound rule must exist in netsh");
        assert(rule_exists_in_netsh(r.rule_name_out)
               && "outbound rule must exist in netsh");
        std::cout << "[PASS] Test B-2: netsh confirms both rules exist\n";

        // -----------------------------------------------------------------------
        // Test C: is_blocked() is true during TTL
        // -----------------------------------------------------------------------
        assert(fw.is_blocked(TEST_IP) && "is_blocked must be true during TTL");
        std::cout << "[PASS] Test C: is_blocked() = true during TTL\n";

        // -----------------------------------------------------------------------
        // Test B-3: wait for TTL expiry
        // The expiry thread wakes every 30 s normally, but we shorten the wait
        // by calling unblock() directly after TTL has elapsed. We set TTL=10s
        // and sleep 12s, then check — the expiry thread fires within that window
        // because it wakes every 1 s (implemented with 30×1s increments).
        // -----------------------------------------------------------------------
        std::cout << "[INFO] Waiting " << (TEST_TTL_S + 2)
                  << " s for TTL auto-expiry...\n";
        std::this_thread::sleep_for(std::chrono::seconds(TEST_TTL_S + 2));

        assert(!fw.is_blocked(TEST_IP)
               && "is_blocked must be false after TTL expiry");
        assert(!rule_exists_in_netsh(r.rule_name_in)
               && "inbound rule must be removed after TTL");
        assert(!rule_exists_in_netsh(r.rule_name_out)
               && "outbound rule must be removed after TTL");
        std::cout << "[PASS] Test B-3: rules auto-removed after TTL expiry\n";

        // -----------------------------------------------------------------------
        // Test B-4 / C: audit chain has firewall_block + firewall_unblock
        // -----------------------------------------------------------------------
        bool found_block   = false;
        bool found_unblock = false;
        for (const auto& e : chain.get_all_entries()) {
            if (e.event_type == "firewall_block" &&
                e.payload.find(TEST_IP) != std::string::npos)
                found_block = true;
            if (e.event_type == "firewall_unblock" &&
                e.payload.find(TEST_IP) != std::string::npos)
                found_unblock = true;
        }
        assert(found_block   && "firewall_block audit entry must exist");
        assert(found_unblock && "firewall_unblock audit entry must exist");
        std::cout << "[PASS] Test B-4: audit chain has firewall_block + firewall_unblock\n";
    }

    // -----------------------------------------------------------------------
    // Test D: double-block returns already-blocked (idempotent)
    // -----------------------------------------------------------------------
    {
        // Block fresh
        BlockResult r1 = fw.block(TEST_IP, TEST_TTL_S);
        assert(r1.blocked);
        // Try to block again — must refuse
        BlockResult r2 = fw.block(TEST_IP, TEST_TTL_S);
        assert(!r2.blocked && "second block on same IP must be refused");
        assert(r2.reason.find("already") != std::string::npos);
        std::cout << "[PASS] Test D: double-block refused gracefully\n";
        // Cleanup — explicit unblock so destructor is clean
        fw.unblock(TEST_IP);
    }

    // -----------------------------------------------------------------------
    // Audit chain integrity
    // -----------------------------------------------------------------------
    {
        auto vr = chain.verify_chain();
        assert(vr.is_valid && "audit chain must be valid");
        std::cout << "[PASS] Audit chain intact ("
                  << chain.get_chain_length() << " entries)\n";
    }

    std::cout << "\n========================================\n"
              << "ALL TESTS PASSED\n"
              << "FirewallBlocker (ST-4) working!\n"
              << "========================================\n";
    return 0;
}

// Made with Bob
