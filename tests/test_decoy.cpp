#ifdef NDEBUG
#undef NDEBUG   // force assert() active in Release builds for test executables
#endif
#include <iostream>
#include <cassert>
#include <string>
#include <filesystem>

#include "../core/audit_chain/audit_chain.h"
#include "../core/sandbox/sandbox.h"
#include "../core/decoy/decoy.h"

namespace fs = std::filesystem;
using namespace astartis::audit;
using namespace astartis::sandbox;
using namespace astartis::decoy;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::string make_root(const std::string& suffix) {
    return (fs::temp_directory_path() / ("astartis_decoy_test_" + suffix)).string();
}
static void cleanup(const std::string& root) {
    std::error_code ec;
    fs::remove_all(root, ec);
}

// Full fixture: AuditChain + Sandbox + DecoyEnvironment
struct DecoyFixture {
    AuditChain        chain;
    Sandbox           sb;
    DecoyEnvironment  decoy;

    explicit DecoyFixture(const std::string& root)
        : sb(root,
             [this](const std::string& et, const std::string& p) {
                 return chain.add_entry(et, p);
             })
        , decoy(sb,
             [this](const std::string& et, const std::string& p) {
                 return chain.add_entry(et, p);
             })
    {
        sb.populate();
    }
};

// ---------------------------------------------------------------------------
// Test 1: plant() creates all three poisoning mechanisms
// ---------------------------------------------------------------------------
void test_plant_all_mechanisms() {
    std::cout << "\n=== Test 1: plant() Creates All Three Poisoning Mechanisms ===" << std::endl;

    std::string root = make_root("t1");
    cleanup(root);
    DecoyFixture f(root);

    size_t planted = f.decoy.plant();
    std::cout << "  Planted: " << planted << " poisoned files" << std::endl;
    assert(planted == 13);  // 4 data-val + 5 lateral + 4 credential

    // Spot-check one of each type
    assert(f.decoy.is_poisoned("decoy/assets/financial-projections-2024.xlsx"));
    assert(f.decoy.poison_type_of("decoy/assets/financial-projections-2024.xlsx")
           == PoisonType::DATA_VALUATION);

    assert(f.decoy.is_poisoned("decoy/server-02/etc/hostname"));
    assert(f.decoy.poison_type_of("decoy/server-02/etc/hostname")
           == PoisonType::LATERAL_MOVEMENT);

    assert(f.decoy.is_poisoned("decoy/credentials/.aws/credentials"));
    assert(f.decoy.poison_type_of("decoy/credentials/.aws/credentials")
           == PoisonType::CREDENTIAL);

    // All poisoned files must exist on disk inside the sandbox
    for (const std::string rel : {
            "decoy/assets/financial-projections-2024.xlsx",
            "decoy/server-02/etc/hostname",
            "decoy/credentials/.aws/credentials"}) {
        fs::path p = fs::path(root) / rel;
        assert(fs::exists(p));
        std::cout << "  On-disk: " << rel << " — exists" << std::endl;
    }

    // Audit chain must have a decoy_planted entry
    bool found = false;
    for (const auto& e : f.chain.get_all_entries())
        if (e.event_type == "decoy_planted") { found = true; break; }
    assert(found);
    std::cout << "  Audit entry 'decoy_planted': present" << std::endl;

    cleanup(root);
}

// ---------------------------------------------------------------------------
// Test 2: Data valuation poisoning — forensic log entry on touch
// ---------------------------------------------------------------------------
void test_data_valuation_poisoning() {
    std::cout << "\n=== Test 2: Data Valuation Poisoning — Forensic Log ===" << std::endl;

    std::string root = make_root("t2");
    cleanup(root);
    DecoyFixture f(root);
    f.decoy.plant();

    // Simulate attacker reading the financial file
    bool r_fin = f.decoy.touch(
        "decoy/assets/financial-projections-2024.xlsx",
        "read",
        "attacker-session-A",
        "exfil attempt via SCP");
    if (!r_fin) { std::cerr << "FAIL: financial touch returned false\n"; std::exit(1); }

    // Second access — customer PII
    bool r_pii = f.decoy.touch(
        "decoy/assets/customer-pii-export.csv",
        "read",
        "attacker-session-A",
        "accessed via web shell");
    if (!r_pii) { std::cerr << "FAIL: PII touch returned false\n"; std::exit(1); }

    auto log = f.decoy.forensic_log();
    if (log.size() != 2) { std::cerr << "FAIL: expected 2 log events, got " << log.size() << "\n"; std::exit(1); }
    if (log[0].poison_type != PoisonType::DATA_VALUATION) { std::cerr << "FAIL: wrong type\n"; std::exit(1); }
    if (log[0].action != "read") { std::cerr << "FAIL: wrong action\n"; std::exit(1); }
    if (log[0].attacker_tag != "attacker-session-A") { std::cerr << "FAIL: wrong tag\n"; std::exit(1); }

    std::cout << "  Forensic events: " << log.size() << std::endl;
    for (const auto& ev : log) {
        std::cout << "    [" << poison_type_name(ev.poison_type) << "] "
                  << ev.action << " on " << ev.rel_path
                  << " by " << ev.attacker_tag << std::endl;
    }

    // Non-poisoned path returns false
    bool r_nonpoison = f.decoy.touch("etc/nginx.conf", "read", "attacker-session-A");
    if (r_nonpoison) { std::cerr << "FAIL: non-poisoned path should return false\n"; std::exit(1); }
    std::cout << "  Non-poisoned path touch: correctly ignored" << std::endl;

    cleanup(root);
}

// ---------------------------------------------------------------------------
// Test 3: Lateral movement poisoning — fabricated server-02 subtree
// ---------------------------------------------------------------------------
void test_lateral_movement_poisoning() {
    std::cout << "\n=== Test 3: Lateral Movement Poisoning — Fake Server Subtree ===" << std::endl;

    std::string root = make_root("t3");
    cleanup(root);
    DecoyFixture f(root);
    f.decoy.plant();

    // Verify the server-02 subtree exists and looks like a real server
    std::vector<std::string> server02_paths = {
        "decoy/server-02/etc/hostname",
        "decoy/server-02/etc/nginx.conf",
        "decoy/server-02/var/log/auth.log",
        "decoy/server-02/home/admin/.ssh/authorized_keys",
        "decoy/server-02/opt/app/config.json",
    };
    for (const auto& rel : server02_paths) {
        assert(f.decoy.is_poisoned(rel));
        assert(f.decoy.poison_type_of(rel) == PoisonType::LATERAL_MOVEMENT);
        SandboxEntry entry;
        auto r = f.sb.read(f.sb.root_path() + "/" + rel, entry);
        assert(r.ok);
        std::cout << "  server-02: " << rel << " — content length "
                  << entry.content.size() << " bytes" << std::endl;
    }

    // Simulate attacker lateral move into server-02
    f.decoy.touch("decoy/server-02/etc/hostname", "read",
                  "attacker-session-B", "hostname enumeration");
    f.decoy.touch("decoy/server-02/opt/app/config.json", "read",
                  "attacker-session-B", "config harvesting");

    auto log = f.decoy.forensic_log();
    size_t lateral_events = 0;
    for (const auto& ev : log)
        if (ev.poison_type == PoisonType::LATERAL_MOVEMENT) ++lateral_events;
    assert(lateral_events == 2);
    std::cout << "  Lateral movement events logged: " << lateral_events << std::endl;

    cleanup(root);
}

// ---------------------------------------------------------------------------
// Test 4: Credential poisoning — fake credentials in realistic locations
// ---------------------------------------------------------------------------
void test_credential_poisoning() {
    std::cout << "\n=== Test 4: Credential Poisoning — Fake Creds Logged ===" << std::endl;

    std::string root = make_root("t4");
    cleanup(root);
    DecoyFixture f(root);
    f.decoy.plant();

    // Read fake AWS keys
    f.decoy.touch("decoy/credentials/.aws/credentials",
                  "read", "attacker-session-C", "AWS key harvest");

    // Read fake .env (database password)
    f.decoy.touch("decoy/credentials/opt/app/.env",
                  "read", "attacker-session-C", "DB password harvest");

    auto log = f.decoy.forensic_log();
    size_t cred_events = 0;
    for (const auto& ev : log) {
        if (ev.poison_type == PoisonType::CREDENTIAL) {
            ++cred_events;
            std::cout << "  CREDENTIAL event: " << ev.action
                      << " on " << ev.rel_path
                      << " — " << ev.detail << std::endl;
        }
    }
    assert(cred_events == 2);

    // Verify the .env file contains the realistic-looking (but fake) content
    SandboxEntry entry;
    f.sb.read(root + "/decoy/credentials/opt/app/.env", entry);
    assert(entry.content.find("DATABASE_URL") != std::string::npos);
    assert(entry.content.find("DECOY") != std::string::npos);
    std::cout << "  .env contains DATABASE_URL and DECOY marker: OK" << std::endl;

    cleanup(root);
}

// ---------------------------------------------------------------------------
// Test 5: Silent redirect — simulated breach triggers redirect into server-02
// ---------------------------------------------------------------------------
void test_silent_redirect() {
    std::cout << "\n=== Test 5: Silent Redirect on Breach Threshold ===" << std::endl;

    std::string root = make_root("t5");
    cleanup(root);
    DecoyFixture f(root);
    f.decoy.plant();

    // Attacker touches a high-value asset — triggers redirect
    f.decoy.touch("decoy/assets/ip-source-code-archive.tar.gz",
                  "exfil_attempt", "attacker-session-D", "wget via web shell");

    // Caller decides threshold is met — fire redirect
    std::string dest = f.decoy.redirect("attacker-session-D",
                                         "decoy/assets/ip-source-code-archive.tar.gz");

    assert(dest == std::string(DecoyEnvironment::LATERAL_MOVEMENT_ROOT));
    std::cout << "  Redirect destination: " << dest << std::endl;

    // Forensic log must have the redirect event
    auto log = f.decoy.forensic_log();
    bool redirect_found = false;
    for (const auto& ev : log) {
        if (ev.action == "redirect") {
            redirect_found = true;
            std::cout << "  Redirect event: attacker=" << ev.attacker_tag
                      << " triggered_by in detail=" << ev.detail << std::endl;
        }
    }
    assert(redirect_found);

    cleanup(root);
}

// ---------------------------------------------------------------------------
// Test 6: Each poisoning mechanism gets its own forensic log entry (spec req)
// ---------------------------------------------------------------------------
void test_each_mechanism_has_forensic_entry() {
    std::cout << "\n=== Test 6: Each Mechanism Has Separate Forensic Log Entry ===" << std::endl;

    std::string root = make_root("t6");
    cleanup(root);
    DecoyFixture f(root);
    f.decoy.plant();

    // One touch per type
    f.decoy.touch("decoy/assets/strategic-roadmap-confidential.pdf",
                  "read", "attacker", "data val test");
    f.decoy.touch("decoy/server-02/var/log/auth.log",
                  "read", "attacker", "lateral movement test");
    f.decoy.touch("decoy/credentials/.ssh/id_rsa",
                  "read", "attacker", "credential test");

    auto log = f.decoy.forensic_log();

    bool has_data_val  = false, has_lateral = false, has_cred = false;
    for (const auto& ev : log) {
        if (ev.poison_type == PoisonType::DATA_VALUATION)   has_data_val  = true;
        if (ev.poison_type == PoisonType::LATERAL_MOVEMENT) has_lateral   = true;
        if (ev.poison_type == PoisonType::CREDENTIAL)       has_cred      = true;
    }

    assert(has_data_val  && "No DATA_VALUATION event");
    assert(has_lateral   && "No LATERAL_MOVEMENT event");
    assert(has_cred      && "No CREDENTIAL event");

    std::cout << "  DATA_VALUATION event:   present" << std::endl;
    std::cout << "  LATERAL_MOVEMENT event: present" << std::endl;
    std::cout << "  CREDENTIAL event:       present" << std::endl;

    // All three must also be in the audit chain
    size_t decoy_events = 0;
    for (const auto& e : f.chain.get_all_entries())
        if (e.event_type == "decoy_event") ++decoy_events;
    assert(decoy_events >= 3);
    std::cout << "  Audit chain decoy_event entries: " << decoy_events << std::endl;

    cleanup(root);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "ASTARTIS DECOY ENVIRONMENT TEST         " << std::endl;
    std::cout << "Step 10: DIBANET Layer 2 — Three Poison " << std::endl;
    std::cout << "========================================" << std::endl;

    try {
        test_plant_all_mechanisms();
        test_data_valuation_poisoning();
        test_lateral_movement_poisoning();
        test_credential_poisoning();
        test_silent_redirect();
        test_each_mechanism_has_forensic_entry();

        std::cout << "\n========================================" << std::endl;
        std::cout << "ALL TESTS PASSED"                         << std::endl;
        std::cout << "Decoy environment working!"               << std::endl;
        std::cout << "========================================\n" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\nTEST FAILED: " << e.what() << std::endl;
        return 1;
    }
}

// Made with Bob
