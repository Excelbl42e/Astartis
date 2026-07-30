// Step 16 ST-7 -- Active Defense integration test
//
// Covers all three requirements from the Step 16 spec in one executable:
//
//  (a) QUARANTINE: feed a real file outside the sandbox → quarantined →
//      original location empty → audit entry has correct original_path and
//      virus_name.
//
//  (b) FIREWALL: RULE-01 trigger on safe test IP 240.0.0.1 → real rule
//      confirmed via netsh show rule → auto-removes after TTL → audit chain
//      has both firewall_block and firewall_unblock entries.
//
//  (c) ALLOWLIST: 127.0.0.1 is never blocked even when block() is called
//      on it directly.
//
// Exit code 2 = not elevated — skip, not fail (same as ClamdScannerTest and
// FirewallBlockerTest).  Run from an elevated (Administrator) terminal to
// exercise the full test.

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>

#include <winsock2.h>
#include <windows.h>

#include "audit_chain/audit_chain.h"
#include "quarantine/quarantine.h"
#include "firewall/firewall_blocker.h"

namespace fs = std::filesystem;
using namespace astartis::audit;
using namespace astartis::quarantine;
using namespace astartis::firewall;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

static bool rule_exists_in_netsh(const std::string& name)
{
    std::string cmd =
        "netsh advfirewall firewall show rule name=\"" + name + "\" >NUL 2>&1";
    return std::system(cmd.c_str()) == 0;
}

static fs::path write_temp_file(const fs::path& dir,
                                const std::string& name,
                                const std::string& content)
{
    fs::create_directories(dir);
    fs::path p = dir / name;
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    assert(f && "could not create temp test file");
    f << content;
    f.close();
    return fs::absolute(p);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    std::cout << "========================================\n"
              << "ASTARTIS ACTIVE DEFENSE INTEGRATION TEST\n"
              << "Step 16 ST-7                            \n"
              << "========================================\n";

    if (!is_elevated_process()) {
        std::cout << "[SKIP] Process not elevated — run as Administrator to "
                     "exercise netsh and the ProgramData quarantine path.\n";
        return 2;
    }
    std::cout << "[INFO] Running elevated — all three requirements will be tested.\n\n";

    AuditChain chain;
    auto audit_adder = [&](const std::string& et, const std::string& pl) {
        return chain.add_entry(et, pl);
    };

    // Use a temp directory for all file operations so nothing touches real
    // user paths or the sandbox root.
    fs::path tmp_root = fs::temp_directory_path() / "astartis_active_defense_test";
    fs::path src_dir  = tmp_root / "source";
    fs::path qtn_dir  = tmp_root / "quarantine";
    std::error_code ec;
    fs::remove_all(tmp_root, ec); // clean slate from any previous run
    fs::create_directories(src_dir);
    fs::create_directories(qtn_dir);

    // =========================================================================
    // Requirement (a): QUARANTINE
    // =========================================================================
    std::cout << "--- Requirement (a): ClamAV Quarantine ---\n";
    {
        Quarantine qtn(qtn_dir.string(), audit_adder);

        // Create a file outside the sandbox (in tmp) with a known payload.
        std::string file_content = "simulated infected payload — active-defense-integration-test";
        fs::path src = write_temp_file(src_dir, "infected_payload.bin", file_content);
        std::string src_str = src.string();

        QuarantineEntry e = qtn.quarantine_file(src_str, "Test.Virus.ActiveDefense");

        // Original location must be empty
        assert(!e.entry_id.empty()
               && "entry_id must be populated");
        assert(!fs::exists(src)
               && "(a) original file must not exist after quarantine");
        assert(fs::exists(e.quarantine_path)
               && "(a) quarantined .bin must exist");
        assert(!e.sha256_hash.empty()
               && "(a) SHA-256 hash must be populated");
        assert(e.original_path == src_str
               && "(a) original_path in entry must match source path");
        assert(e.virus_name == "Test.Virus.ActiveDefense"
               && "(a) virus_name must be preserved");
        std::cout << "[PASS] (a-1) file moved to quarantine\n";
        std::cout << "       entry_id:      " << e.entry_id << "\n";
        std::cout << "       original_path: " << e.original_path << "\n";

        // Audit entry must have correct original_path in its payload
        bool found_audit = false;
        for (const auto& ae : chain.get_all_entries()) {
            if (ae.event_type == "quarantine" &&
                ae.payload.find(e.original_path) != std::string::npos) {
                found_audit = true;
                break;
            }
        }
        assert(found_audit && "(a) audit entry must contain original_path");
        std::cout << "[PASS] (a-2) audit entry has correct original_path\n";

        // Restore so the temp path is clean for the next sub-test
        bool restored = qtn.restore(e.entry_id);
        assert(restored && "(a) restore must succeed");
        assert(fs::exists(src) && "(a) file must be back after restore");
        std::cout << "[PASS] (a-3) restore returned file to original path\n\n";
    }

    // =========================================================================
    // Requirement (b): FIREWALL — TTL-bound block on 240.0.0.1
    // =========================================================================
    std::cout << "--- Requirement (b): TTL-bound Firewall Block ---\n";
    {
        constexpr int TTL_S = 10; // short TTL for the test
        const std::string TEST_IP = "240.0.0.1"; // IANA reserved, unroutable

        FirewallBlocker fw(audit_adder, TTL_S);

        // Block the test IP
        BlockResult r = fw.block(TEST_IP, TTL_S);
        assert(r.blocked  && "(b) block() must succeed for 240.0.0.1");
        std::cout << "[PASS] (b-1) block() returned blocked=true\n";
        std::cout << "       rule_in:  " << r.rule_name_in  << "\n";
        std::cout << "       rule_out: " << r.rule_name_out << "\n";

        // Confirm rules exist in Windows Firewall via netsh
        assert(rule_exists_in_netsh(r.rule_name_in)
               && "(b) inbound rule must exist in netsh");
        assert(rule_exists_in_netsh(r.rule_name_out)
               && "(b) outbound rule must exist in netsh");
        std::cout << "[PASS] (b-2) netsh confirms both rules exist\n";

        // is_blocked() must be true during TTL
        assert(fw.is_blocked(TEST_IP) && "(b) is_blocked must be true during TTL");
        std::cout << "[PASS] (b-3) is_blocked() = true during TTL\n";

        // Wait for auto-expiry (+2 s margin)
        std::cout << "[INFO] Waiting " << (TTL_S + 2) << " s for TTL expiry...\n";
        std::this_thread::sleep_for(std::chrono::seconds(TTL_S + 2));

        assert(!fw.is_blocked(TEST_IP)
               && "(b) is_blocked must be false after TTL expiry");
        assert(!rule_exists_in_netsh(r.rule_name_in)
               && "(b) inbound rule must be removed after TTL");
        assert(!rule_exists_in_netsh(r.rule_name_out)
               && "(b) outbound rule must be removed after TTL");
        std::cout << "[PASS] (b-4) rules auto-removed after TTL expiry\n";

        // Audit chain must have both firewall_block and firewall_unblock
        bool found_block = false, found_unblock = false;
        for (const auto& ae : chain.get_all_entries()) {
            if (ae.event_type == "firewall_block" &&
                ae.payload.find(TEST_IP) != std::string::npos)
                found_block = true;
            if (ae.event_type == "firewall_unblock" &&
                ae.payload.find(TEST_IP) != std::string::npos)
                found_unblock = true;
        }
        assert(found_block   && "(b) firewall_block audit entry must exist");
        assert(found_unblock && "(b) firewall_unblock audit entry must exist");
        std::cout << "[PASS] (b-5) audit chain has firewall_block + firewall_unblock\n\n";
    }

    // =========================================================================
    // Requirement (c): ALLOWLIST — 127.0.0.1 never blocked
    // =========================================================================
    std::cout << "--- Requirement (c): Allowlist Rejection ---\n";
    {
        FirewallBlocker fw(audit_adder);

        BlockResult r = fw.block("127.0.0.1", 60);
        assert(!r.blocked && "(c) 127.0.0.1 must never be blocked");
        assert(r.reason.find("allowlist") != std::string::npos
               && "(c) reason must mention allowlist");
        assert(!fw.is_blocked("127.0.0.1")
               && "(c) is_blocked must remain false");
        std::cout << "[PASS] (c-1) 127.0.0.1 rejected: " << r.reason << "\n";

        // ::1 (IPv6 loopback) must also be in the allowlist
        BlockResult r2 = fw.block("::1", 60);
        assert(!r2.blocked && "(c) ::1 must never be blocked");
        std::cout << "[PASS] (c-2) ::1 (IPv6 loopback) rejected: " << r2.reason << "\n\n";
    }

    // =========================================================================
    // Audit chain integrity
    // =========================================================================
    {
        auto vr = chain.verify_chain();
        assert(vr.is_valid && "audit chain must be valid throughout");
        std::cout << "[PASS] Audit chain intact ("
                  << chain.get_chain_length() << " entries)\n";
    }

    // Cleanup
    fs::remove_all(tmp_root, ec);

    std::cout << "\n========================================\n"
              << "ALL REQUIREMENTS VERIFIED\n"
              << "(a) Quarantine, (b) TTL Firewall, (c) Allowlist\n"
              << "Step 16 ST-7 PASSED\n"
              << "========================================\n";
    return 0;
}

// Made with Bob
