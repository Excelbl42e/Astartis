// Step 13 -- Attribution Report test
// Always define NDEBUG guard so assert() works in Release builds.
#ifdef NDEBUG
#undef NDEBUG
#endif

#include <cassert>
#include <string>
#include <fstream>
#include <filesystem>
#include <functional>
#include <iostream>

#include "audit_chain/audit_chain.h"
#include "sandbox/sandbox.h"
#include "decoy/decoy.h"
#include "active_response/active_response.h"
#include "attribution/attribution_report.h"

namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Helper: check a file contains a substring
// ---------------------------------------------------------------------------

static bool file_contains(const std::string& path, const std::string& needle)
{
    std::ifstream f(path);
    if (!f) return false;
    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
    return content.find(needle) != std::string::npos;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    // ------------------------------------------------------------------
    // 0.  Sandbox root inside the system temp directory
    // ------------------------------------------------------------------
    fs::path sb_root = fs::temp_directory_path() / "astartis_test_attribution";
    fs::remove_all(sb_root);
    fs::create_directories(sb_root);

    // ------------------------------------------------------------------
    // 1.  Audit chain
    //     Namespace: astartis::audit  Method: add_entry / verify_chain
    // ------------------------------------------------------------------
    astartis::audit::AuditChain audit;

    // MSVC requires explicit std::function type for lambdas passed to
    // constructors that accept std::function parameters.
    std::function<std::string(const std::string&, const std::string&)>
        audit_adder = [&](const std::string& evt, const std::string& payload) {
            return audit.add_entry(evt, payload);
        };

    // ------------------------------------------------------------------
    // 2.  Sandbox
    //     Constructor: Sandbox(root_path, audit_adder, lock_check)
    // ------------------------------------------------------------------
    astartis::sandbox::Sandbox sb(sb_root.string(), audit_adder);

    // ------------------------------------------------------------------
    // 3.  Plant decoy environment
    // ------------------------------------------------------------------
    astartis::decoy::DecoyEnvironment decoy(sb, audit_adder);
    size_t planted = decoy.plant();
    assert(planted > 0);
    std::cout << "[PASS] decoy planted: " << planted << " file(s)\n";

    // ------------------------------------------------------------------
    // 4.  Active response setup
    // ------------------------------------------------------------------
    astartis::active_response::ActiveResponse ar(audit_adder);

    // ------------------------------------------------------------------
    // 5.  Simulate attacker session "session-ATK-001"
    // ------------------------------------------------------------------
    const std::string session_id = "session-ATK-001";

    // Attacker reads fake credentials
    bool hit1 = decoy.touch("decoy/credentials/.aws/credentials",
                            "read", session_id, "wget clone");
    assert(hit1);

    // Attacker reads fake private key
    bool hit2 = decoy.touch("decoy/credentials/.ssh/id_rsa",
                            "read", session_id, "scp attempt");
    assert(hit2);

    // Attacker reads a data-valuation asset
    bool hit3 = decoy.touch("decoy/assets/financial-projections-2024.xlsx",
                            "exfil_attempt", session_id, "curl download");
    assert(hit3);

    // Redirect into lateral-movement subtree
    std::string dest = decoy.redirect(session_id, "decoy/credentials/.aws/credentials");
    assert(!dest.empty());
    std::cout << "[PASS] decoy redirect -> " << dest << "\n";

    // Active response: use a known-bad IOC IP so the report contains an IOC hit
    ar.serve(session_id, "decoy/credentials/.aws/credentials", "185.220.101.1");
    ar.serve(session_id, "decoy/assets/financial-projections-2024.xlsx");
    ar.serve(session_id, "decoy/server-02/etc/hostname");

    // ------------------------------------------------------------------
    // 6.  Generate attribution report
    // ------------------------------------------------------------------
    astartis::attribution::AttributionReporter reporter(sb_root.string(), audit_adder);

    auto artifact = reporter.generate(
        session_id,
        decoy.forensic_log(),
        ar.forensic_log()
    );

    // ------------------------------------------------------------------
    // 7.  Verify report artifact (in-memory)
    // ------------------------------------------------------------------
    assert(artifact.session_id == session_id);
    assert(!artifact.report_file_path.empty());
    assert(fs::exists(artifact.report_file_path));

    // Should have picked up at least 1 ATT&CK technique
    assert(!artifact.techniques.empty());
    std::cout << "[PASS] techniques mapped: " << artifact.techniques.size() << "\n";
    for (const auto& t : artifact.techniques)
        std::cout << "       " << t.technique_id << " -- " << t.name << "\n";

    // Summary must mention session ID
    assert(artifact.summary.find(session_id) != std::string::npos);
    std::cout << "[PASS] summary contains session ID\n";

    // ------------------------------------------------------------------
    // 8.  Verify report file contents
    // ------------------------------------------------------------------
    assert(file_contains(artifact.report_file_path, "ASTARTIS ATTRIBUTION REPORT"));
    assert(file_contains(artifact.report_file_path, "MITRE ATT&CK TECHNIQUE MATCHES"));
    assert(file_contains(artifact.report_file_path, "IOC CORRELATION RESULTS"));
    assert(file_contains(artifact.report_file_path, "SUMMARY"));
    assert(file_contains(artifact.report_file_path, session_id));

    // At least one ATT&CK ID should appear in the report text
    bool found_attack_id = false;
    for (const auto& t : artifact.techniques) {
        if (file_contains(artifact.report_file_path, t.technique_id)) {
            found_attack_id = true;
            break;
        }
    }
    assert(found_attack_id);
    std::cout << "[PASS] report file contains ATT&CK IDs\n";

    // ------------------------------------------------------------------
    // 9.  Static map_techniques sanity check
    // ------------------------------------------------------------------
    auto techs = astartis::attribution::AttributionReporter::map_techniques(
        "read", "decoy/credentials/.aws/credentials",
        astartis::decoy::PoisonType::CREDENTIAL);
    assert(!techs.empty());
    bool found_t1552 = false;
    for (const auto& t : techs) {
        if (t.technique_id.find("T1552") != std::string::npos) {
            found_t1552 = true; break;
        }
    }
    assert(found_t1552);
    std::cout << "[PASS] map_techniques static check: T1552 matched\n";

    // ------------------------------------------------------------------
    // 10. Audit chain integrity
    // ------------------------------------------------------------------
    auto vr = audit.verify_chain();
    assert(vr.is_valid);
    std::cout << "[PASS] audit chain intact (" << audit.get_chain_length() << " entries)\n";

    // ------------------------------------------------------------------
    // Cleanup
    // ------------------------------------------------------------------
    fs::remove_all(sb_root);

    std::cout << "[PASS] test_attribution_report -- all assertions passed\n";
    return 0;
}

// Made with Bob
