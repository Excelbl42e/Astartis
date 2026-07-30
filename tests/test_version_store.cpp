#ifdef NDEBUG
#undef NDEBUG   // force assert() active in Release builds for test executables
#endif
#include <iostream>
#include <cassert>
#include <string>

#include "../core/audit_chain/audit_chain.h"
#include "../core/version_store/version_store.h"

using namespace astartis::audit;
using namespace astartis::versioning;

// ---------------------------------------------------------------------------
// Helper: build a VersionStore wired to a real AuditChain
// ---------------------------------------------------------------------------
struct TestFixture {
    AuditChain   chain;
    VersionStore store;

    TestFixture()
        : store([this](const std::string& et, const std::string& p) {
              return chain.add_entry(et, p);
          })
    {}
};

// ---------------------------------------------------------------------------
// Test 1: first write creates version 1
// ---------------------------------------------------------------------------
void test_first_write() {
    std::cout << "\n=== Test 1: First Write Creates Version 1 ===" << std::endl;

    TestFixture f;

    auto result = f.store.write("config/max_connections", "100", "alice");

    assert(result.ok);
    assert(result.version_number == 1);
    assert(f.store.record_count() == 1);
    assert(f.store.total_version_count() == 1);

    std::cout << "  write() returned ok, version_number=1" << std::endl;
}

// ---------------------------------------------------------------------------
// Test 2: each write produces a new version; prior version is untouched
// ---------------------------------------------------------------------------
void test_versions_are_appended() {
    std::cout << "\n=== Test 2: Each Write Appends a New Version ===" << std::endl;

    TestFixture f;
    const std::string rid = "policy/firewall_rule";

    auto r1 = f.store.write(rid, "ALLOW 192.168.1.0/24", "alice");
    auto r2 = f.store.write(rid, "ALLOW 10.0.0.0/8",    "alice");
    auto r3 = f.store.write(rid, "DENY  all",            "bob");

    assert(r1.ok && r1.version_number == 1);
    assert(r2.ok && r2.version_number == 2);
    assert(r3.ok && r3.version_number == 3);
    assert(f.store.total_version_count() == 3);

    std::cout << "  Three writes produced versions 1, 2, 3" << std::endl;

    // Current is the latest
    RecordVersion cur;
    auto rc = f.store.read_current(rid, cur);
    assert(rc.ok);
    assert(cur.version_number == 3);
    assert(cur.data == "DENY  all");
    assert(cur.author == "bob");

    std::cout << "  read_current() returned version 3: \"" << cur.data << "\"" << std::endl;
}

// ---------------------------------------------------------------------------
// Test 3: prior version is still retrievable — nothing was overwritten
// ---------------------------------------------------------------------------
void test_prior_version_retrievable() {
    std::cout << "\n=== Test 3: Prior Version Still Retrievable ===" << std::endl;

    TestFixture f;
    const std::string rid = "secret/db_password";

    f.store.write(rid, "hunter2",       "alice");   // v1
    f.store.write(rid, "correct-horse", "alice");   // v2 — the "change"

    // v1 must still exist unchanged
    RecordVersion v1;
    auto r1 = f.store.read_version(rid, 1, v1);
    assert(r1.ok);
    assert(v1.data   == "hunter2");
    assert(v1.author == "alice");

    // v2 is the current value
    RecordVersion v2;
    auto r2 = f.store.read_version(rid, 2, v2);
    assert(r2.ok);
    assert(v2.data == "correct-horse");

    std::cout << "  v1 data : \"" << v1.data << "\"  (original — still intact)" << std::endl;
    std::cout << "  v2 data : \"" << v2.data << "\"  (current)" << std::endl;
    std::cout << "  Nothing was overwritten." << std::endl;
}

// ---------------------------------------------------------------------------
// Test 4: full history for a record
// ---------------------------------------------------------------------------
void test_get_history() {
    std::cout << "\n=== Test 4: Full History Returned Oldest-First ===" << std::endl;

    TestFixture f;
    const std::string rid = "config/log_level";

    f.store.write(rid, "INFO",    "alice");
    f.store.write(rid, "DEBUG",   "alice");
    f.store.write(rid, "WARNING", "bob");

    auto history = f.store.get_history(rid);

    assert(history.size() == 3);
    assert(history[0].data == "INFO");
    assert(history[1].data == "DEBUG");
    assert(history[2].data == "WARNING");

    for (const auto& v : history) {
        std::cout << "  v" << v.version_number
                  << " [" << v.author << "] " << v.data
                  << "  hash: " << v.version_hash.substr(0, 16) << "..."
                  << std::endl;
    }
}

// ---------------------------------------------------------------------------
// Test 5: every write lands in the audit chain
// ---------------------------------------------------------------------------
void test_audit_chain_integration() {
    std::cout << "\n=== Test 5: Every Write Lands in Audit Chain ===" << std::endl;

    TestFixture f;

    f.store.write("file/config.txt", "v1 content", "alice");
    f.store.write("file/config.txt", "v2 content", "bob");
    f.store.write("file/readme.md",  "hello world", "alice");

    // 3 version writes must have created 3 audit entries
    size_t chain_len = f.chain.get_chain_length();
    assert(chain_len == 3);

    // Audit chain must still be valid
    auto verify = f.chain.verify_chain();
    assert(verify.is_valid);

    std::cout << "  Audit chain has " << chain_len << " entries (one per write)" << std::endl;
    std::cout << "  Chain integrity verified: " << verify.error_message << std::endl;

    auto entries = f.chain.get_all_entries();
    for (const auto& e : entries) {
        std::cout << "  [" << e.event_type << "] " << e.payload.substr(0, 60) << std::endl;
    }
}

// ---------------------------------------------------------------------------
// Test 6: WORM hook — writes blocked when lock is active
// ---------------------------------------------------------------------------
void test_worm_hook_blocks_write() {
    std::cout << "\n=== Test 6: WORM Hook Blocks Write When Locked ===" << std::endl;

    AuditChain chain;
    bool locked = false;   // simulates Step 3's lockdown state

    VersionStore store(
        [&chain](const std::string& et, const std::string& p) {
            return chain.add_entry(et, p);
        },
        [&locked]() { return locked; }
    );

    // Write succeeds while unlocked
    auto r1 = store.write("data/sensitive", "original value", "alice");
    assert(r1.ok);
    std::cout << "  Write while UNLOCKED: ok (version " << r1.version_number << ")" << std::endl;

    // Engage lockdown
    locked = true;

    // Write must now fail
    auto r2 = store.write("data/sensitive", "overwrite attempt", "attacker");
    assert(!r2.ok);
    std::cout << "  Write while LOCKED:   blocked — \"" << r2.error << "\"" << std::endl;

    // Existing data must be unchanged
    RecordVersion v;
    auto rc = store.read_current("data/sensitive", v);
    assert(rc.ok);
    assert(v.data == "original value");
    std::cout << "  Current value still: \"" << v.data << "\" — original intact" << std::endl;
}

// ---------------------------------------------------------------------------
// Test 7: version_hash is unique per version (no hash collisions on same data)
// ---------------------------------------------------------------------------
void test_version_hashes_are_unique() {
    std::cout << "\n=== Test 7: Version Hashes Are Unique ===" << std::endl;

    TestFixture f;
    const std::string rid = "config/timeout";

    // Write the same data twice — hashes must differ (timestamp differs)
    f.store.write(rid, "30", "alice");
    f.store.write(rid, "30", "alice");

    auto history = f.store.get_history(rid);
    assert(history.size() == 2);
    assert(history[0].version_hash != history[1].version_hash);

    std::cout << "  v1 hash: " << history[0].version_hash.substr(0, 32) << "..." << std::endl;
    std::cout << "  v2 hash: " << history[1].version_hash.substr(0, 32) << "..." << std::endl;
    std::cout << "  Hashes differ despite identical data (timestamp included in hash input)" << std::endl;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "ASTARTIS VERSIONING LAYER TEST SUITE"    << std::endl;
    std::cout << "Step 2: Append-Only Version Store"       << std::endl;
    std::cout << "========================================" << std::endl;

    try {
        test_first_write();
        test_versions_are_appended();
        test_prior_version_retrievable();
        test_get_history();
        test_audit_chain_integration();
        test_worm_hook_blocks_write();
        test_version_hashes_are_unique();

        std::cout << "\n========================================" << std::endl;
        std::cout << "ALL TESTS PASSED"                         << std::endl;
        std::cout << "Versioning layer is working correctly!"   << std::endl;
        std::cout << "========================================\n" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\nTEST FAILED: " << e.what() << std::endl;
        return 1;
    }
}

// Made with Bob
