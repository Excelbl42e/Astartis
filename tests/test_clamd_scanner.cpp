// Step 14 -- ClamAV integration test
#ifdef NDEBUG
#undef NDEBUG
#endif

#include <cassert>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <string>

#include "audit_chain/audit_chain.h"
#include "clamd/clamd_scanner.h"

namespace fs = std::filesystem;
using namespace astartis::clamd;

// ---------------------------------------------------------------------------
// EICAR test string (split across two literals so AV scanners don't flag
// the source file itself — clamd sees the concatenated form at runtime)
// ---------------------------------------------------------------------------

static const char EICAR_PART_A[] = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$";
static const char EICAR_PART_B[] = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

static std::string eicar_string()
{
    return std::string(EICAR_PART_A) + EICAR_PART_B;
}

// ---------------------------------------------------------------------------
// Helper — write a file, return false if AV intercepted it
// ---------------------------------------------------------------------------

static bool safe_write(const fs::path& p, const std::string& content)
{
    try {
        std::ofstream f(p, std::ios::binary | std::ios::trunc);
        if (!f) return false;
        f << content;
        f.close();
        // Verify the file still exists and has the right size
        // (Defender may quarantine it between close and stat)
        return fs::exists(p) && fs::file_size(p) == content.size();
    } catch (...) {
        return false;
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    // ------------------------------------------------------------------
    // Audit chain
    // ------------------------------------------------------------------
    astartis::audit::AuditChain audit;
    std::function<std::string(const std::string&, const std::string&)>
        audit_adder = [&](const std::string& evt, const std::string& payload) {
            return audit.add_entry(evt, payload);
        };

    ClamdScanner scanner(audit_adder, "127.0.0.1", 3310);

    // ------------------------------------------------------------------
    // Test 1: PING
    // ------------------------------------------------------------------
    bool alive = scanner.ping();
    if (!alive) {
        std::cerr << "[SKIP] clamd not reachable on 127.0.0.1:3310 — "
                     "ensure the ClamAV service is running\n";
        return 2;  // distinct exit code: "skipped"
    }
    std::cout << "[PASS] clamd PING -> PONG\n";

    // ------------------------------------------------------------------
    // Test 2: EICAR via in-memory scan (no disk write needed)
    // ------------------------------------------------------------------
    {
        std::string eicar = eicar_string();
        ScanResult r = scanner.scan_buffer(
            reinterpret_cast<const uint8_t*>(eicar.data()),
            eicar.size(),
            "eicar_in_memory");

        assert(r.status == ScanStatus::SCAN_INFECTED);
        assert(!r.virus_name.empty());
        assert(!r.audit_entry_id.empty());
        std::cout << "[PASS] in-memory EICAR detected: " << r.virus_name << "\n";
    }

    // ------------------------------------------------------------------
    // Test 3: Clean buffer scan
    // ------------------------------------------------------------------
    {
        const char clean[] = "Hello, this is a perfectly clean file.\n";
        ScanResult r = scanner.scan_buffer(
            reinterpret_cast<const uint8_t*>(clean),
            std::strlen(clean),
            "clean_in_memory");

        assert(r.status == ScanStatus::SCAN_CLEAN);
        assert(r.virus_name.empty());
        assert(!r.audit_entry_id.empty());
        std::cout << "[PASS] clean buffer correctly reported CLEAN\n";
    }

    // ------------------------------------------------------------------
    // Test 4: EICAR via file on disk
    //
    // Windows Defender may quarantine the EICAR file before clamd reads it.
    // If safe_write() returns false, skip this sub-test with a notice.
    // ------------------------------------------------------------------
    {
        fs::path tmp_dir = fs::temp_directory_path() / "astartis_clamd_test";
        fs::create_directories(tmp_dir);
        fs::path eicar_path = tmp_dir / "eicar_test.txt";

        std::string eicar = eicar_string();
        if (!safe_write(eicar_path, eicar)) {
            std::cout << "[SKIP] EICAR file test: AV intercepted write to "
                      << eicar_path << " -- expected in environments with "
                         "active real-time scanning\n";
        } else {
            ScanResult r = scanner.scan_file(eicar_path.string());

            if (r.status == ScanStatus::SCAN_ERROR && r.raw_response == "file_open_failed") {
                std::cout << "[SKIP] EICAR file test: file vanished after write "
                             "(AV quarantined it)\n";
            } else {
                assert(r.status == ScanStatus::SCAN_INFECTED);
                assert(!r.virus_name.empty());
                std::cout << "[PASS] on-disk EICAR detected: " << r.virus_name << "\n";
            }
            // Best-effort cleanup
            std::error_code ec;
            fs::remove(eicar_path, ec);
        }
        std::error_code ec;
        fs::remove_all(tmp_dir, ec);
    }

    // ------------------------------------------------------------------
    // Test 5: scan_file on a non-existent path returns ERROR gracefully
    // ------------------------------------------------------------------
    {
        ScanResult r = scanner.scan_file("C:/nonexistent_astartis_test_xyz.bin");
        assert(r.status == ScanStatus::SCAN_ERROR);
        assert(!r.audit_entry_id.empty());
        std::cout << "[PASS] missing file returns ERROR gracefully\n";
    }

    // ------------------------------------------------------------------
    // Test 6: Audit chain integrity
    // ------------------------------------------------------------------
    auto vr = audit.verify_chain();
    assert(vr.is_valid);
    std::cout << "[PASS] audit chain intact ("
              << audit.get_chain_length() << " entries)\n";

    std::cout << "[PASS] test_clamd_scanner -- all assertions passed\n";
    return 0;
}

// Made with Bob
