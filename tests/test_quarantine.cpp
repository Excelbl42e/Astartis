// Step 16 ST-3 -- Quarantine module test
//
// Tests:
//  1. quarantine_file: file moved, original empty, quarantine_path exists
//  2. sidecar .meta exists and contains original_path + virus_name
//  3. audit entry written with correct fields
//  4. list() returns the quarantined entry
//  5. restore(): file back at original path, sidecar removed, audit entry written
//  6. Audit chain integrity valid throughout

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include "audit_chain/audit_chain.h"
#include "quarantine/quarantine.h"

namespace fs = std::filesystem;
using namespace astartis::audit;
using namespace astartis::quarantine;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Write a file and return its absolute path
static fs::path write_temp_file(const fs::path& dir,
                                const std::string& name,
                                const std::string& content)
{
    fs::path p = dir / name;
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    assert(f && "could not create temp file");
    f << content;
    return fs::absolute(p);
}

// Scan a text file for a substring.
// Also checks with single backslashes replaced by double backslashes so
// Windows paths (e.g. "C:\foo") match their JSON-escaped form ("C:\\foo").
static bool file_contains(const fs::path& p, const std::string& needle)
{
    std::ifstream f(p);
    if (!f) return false;
    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
    if (content.find(needle) != std::string::npos) return true;
    // Try JSON-escaped form: replace \ with \\ in needle
    std::string escaped;
    escaped.reserve(needle.size() * 2);
    for (char c : needle) {
        if (c == '\\') escaped += "\\\\";
        else           escaped += c;
    }
    return content.find(escaped) != std::string::npos;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    std::cout << "========================================\n"
              << "ASTARTIS QUARANTINE TEST                \n"
              << "Step 16 ST-3                            \n"
              << "========================================\n";

    // Use a temp directory for both the source file and the quarantine store
    fs::path tmp_root = fs::temp_directory_path() / "astartis_qtn_test";
    fs::path src_dir  = tmp_root / "source";
    fs::path qtn_dir  = tmp_root / "quarantine_store";
    fs::create_directories(src_dir);
    fs::create_directories(qtn_dir);

    AuditChain chain;
    auto audit_adder = [&](const std::string& et, const std::string& pl) {
        return chain.add_entry(et, pl);
    };

    Quarantine qtn(qtn_dir.string(), audit_adder);

    // -----------------------------------------------------------------------
    // Test 1: quarantine_file moves the file
    // -----------------------------------------------------------------------
    {
        std::string content = "test quarantine payload — EICAR-equivalent test data";
        fs::path src = write_temp_file(src_dir, "infected.bin", content);

        std::string src_str = src.string();
        QuarantineEntry e = qtn.quarantine_file(src_str, "Test.Virus.EICAR");

        assert(!e.entry_id.empty() && "entry_id must not be empty");
        assert(!fs::exists(src)
               && "original file must not exist after quarantine");
        assert(fs::exists(e.quarantine_path)
               && "quarantined .bin must exist in quarantine dir");
        assert(!e.sha256_hash.empty() && "sha256 must be populated");
        assert(e.virus_name == "Test.Virus.EICAR");
        assert(e.original_path == src_str);

        std::cout << "[PASS] Test 1: file moved to quarantine\n";
        std::cout << "       entry_id: " << e.entry_id << "\n";
        std::cout << "       sha256:   " << e.sha256_hash.substr(0, 16) << "...\n";

        // -----------------------------------------------------------------------
        // Test 2: sidecar .meta exists and contains required fields
        // -----------------------------------------------------------------------
        {
            fs::path meta_path = fs::path(qtn_dir) / (e.entry_id + ".meta");
            assert(fs::exists(meta_path) && ".meta sidecar must exist");
            assert(file_contains(meta_path, e.original_path)
                   && ".meta must contain original_path");
            assert(file_contains(meta_path, "Test.Virus.EICAR")
                   && ".meta must contain virus_name");
            assert(file_contains(meta_path, e.sha256_hash)
                   && ".meta must contain sha256_hash");
            std::cout << "[PASS] Test 2: .meta sidecar contains required fields\n";
        }

        // -----------------------------------------------------------------------
        // Test 3: audit entry written
        // -----------------------------------------------------------------------
        {
            bool found = false;
            for (const auto& entry : chain.get_all_entries()) {
                if (entry.event_type == "quarantine" &&
                    entry.payload.find(e.original_path) != std::string::npos &&
                    entry.payload.find(e.sha256_hash)   != std::string::npos) {
                    found = true;
                    break;
                }
            }
            assert(found && "quarantine audit entry must exist with original_path+sha256");
            std::cout << "[PASS] Test 3: quarantine audit entry present\n";
        }

        // -----------------------------------------------------------------------
        // Test 4: list() returns the entry
        // -----------------------------------------------------------------------
        {
            auto lst = qtn.list();
            assert(lst.size() == 1 && "list must have exactly one entry");
            assert(lst[0].entry_id == e.entry_id);
            std::cout << "[PASS] Test 4: list() returns 1 quarantined entry\n";
        }

        // -----------------------------------------------------------------------
        // Test 5: restore() moves file back, removes sidecar
        // -----------------------------------------------------------------------
        {
            bool ok = qtn.restore(e.entry_id);
            assert(ok && "restore must return true");
            assert(fs::exists(src)
                   && "original path must be populated after restore");
            assert(!fs::exists(e.quarantine_path)
                   && "quarantine .bin must be removed after restore");

            fs::path meta_path = fs::path(qtn_dir) / (e.entry_id + ".meta");
            assert(!fs::exists(meta_path)
                   && ".meta sidecar must be removed after restore");

            auto lst = qtn.list();
            assert(lst.empty() && "list must be empty after restore");
            std::cout << "[PASS] Test 5: restore() successful, sidecar removed\n";

            // Verify quarantine_restore audit entry
            bool found_restore = false;
            for (const auto& ae : chain.get_all_entries()) {
                if (ae.event_type == "quarantine_restore" &&
                    ae.payload.find(e.entry_id) != std::string::npos) {
                    found_restore = true;
                    break;
                }
            }
            assert(found_restore && "quarantine_restore audit entry must exist");
            std::cout << "[PASS] Test 5b: quarantine_restore audit entry present\n";
        }
    }

    // -----------------------------------------------------------------------
    // Test 6: audit chain integrity
    // -----------------------------------------------------------------------
    {
        auto vr = chain.verify_chain();
        assert(vr.is_valid && "audit chain must be valid");
        std::cout << "[PASS] Test 6: audit chain intact ("
                  << chain.get_chain_length() << " entries)\n";
    }

    // Cleanup
    std::error_code ec;
    fs::remove_all(tmp_root, ec);

    std::cout << "\n========================================\n"
              << "ALL TESTS PASSED\n"
              << "Quarantine module (ST-3) working!\n"
              << "========================================\n";
    return 0;
}

// Made with Bob
