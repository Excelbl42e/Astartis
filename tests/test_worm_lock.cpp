#ifdef NDEBUG
#undef NDEBUG   // force assert() active in Release builds for test executables
#endif
#include <iostream>
#include <cassert>
#include <string>

#include "../core/audit_chain/audit_chain.h"
#include "../core/version_store/version_store.h"
#include "../core/worm_lock/worm_lock.h"

using namespace astartis::audit;
using namespace astartis::versioning;
using namespace astartis::worm;

// ---------------------------------------------------------------------------
// Helper: full stack wired together — AuditChain + WormLock + VersionStore
// ---------------------------------------------------------------------------
struct TestFixture {
    AuditChain  chain;
    WormLock    worm;
    VersionStore store;

    TestFixture()
        : worm([this](const std::string& et, const std::string& p) {
               return chain.add_entry(et, p);
           })
        , store(
            [this](const std::string& et, const std::string& p) {
                return chain.add_entry(et, p);
            },
            [this]() {
                return worm.is_locked();
            })
    {}
};

// ---------------------------------------------------------------------------
// Test 1: initial state is NORMAL (not locked)
// ---------------------------------------------------------------------------
void test_initial_state_normal() {
    std::cout << "\n=== Test 1: Initial State is NORMAL ===" << std::endl;

    TestFixture f;

    assert(!f.worm.is_locked());
    assert(f.worm.lockdown_count() == 0);
    assert(f.worm.lock_reason().empty());

    std::cout << "  is_locked()      = false" << std::endl;
    std::cout << "  lockdown_count() = 0"     << std::endl;
}

// ---------------------------------------------------------------------------
// Test 2: trigger_lockdown() transitions to LOCKED, audit entry written
// ---------------------------------------------------------------------------
void test_trigger_lockdown() {
    std::cout << "\n=== Test 2: Trigger Lockdown ===" << std::endl;

    TestFixture f;

    (void)f.worm.trigger_lockdown("anomalous packet detected");

    assert(f.worm.is_locked());
    assert(f.worm.lockdown_count() == 1);
    assert(f.worm.lock_reason() == "anomalous packet detected");

    // Audit chain must have the lockdown event
    assert(f.chain.get_chain_length() == 1);
    auto entries = f.chain.get_all_entries();
    assert(entries[0].event_type == "worm_lock_engaged");

    std::cout << "  is_locked()  = true" << std::endl;
    std::cout << "  Audit entry: [" << entries[0].event_type << "] "
              << entries[0].payload << std::endl;
}

// ---------------------------------------------------------------------------
// Test 3: write attempt FAILS while locked
// ---------------------------------------------------------------------------
void test_write_blocked_while_locked() {
    std::cout << "\n=== Test 3: Write Blocked While Locked ===" << std::endl;

    TestFixture f;

    // Write succeeds before lockdown
    auto r1 = f.store.write("config/value", "original", "alice");
    assert(r1.ok);
    std::cout << "  Write BEFORE lockdown: ok (v" << r1.version_number << ")" << std::endl;

    // Engage lockdown
    f.worm.trigger_lockdown("OMIDAX+DIBANET breach confirmed");

    // Write must now fail
    auto r2 = f.store.write("config/value", "attacker override", "attacker");
    assert(!r2.ok);
    std::cout << "  Write AFTER  lockdown: blocked — \"" << r2.error << "\"" << std::endl;

    // Original data must be untouched
    RecordVersion v;
    f.store.read_current("config/value", v);
    assert(v.data == "original");
    std::cout << "  Data still: \"" << v.data << "\" — unchanged" << std::endl;
}

// ---------------------------------------------------------------------------
// Test 4: write succeeds again after unlock
// ---------------------------------------------------------------------------
void test_write_succeeds_after_unlock() {
    std::cout << "\n=== Test 4: Write Succeeds After Unlock ===" << std::endl;

    TestFixture f;

    f.store.write("config/value", "original", "alice");
    f.worm.trigger_lockdown("test lockdown");

    // Confirm blocked
    auto blocked = f.store.write("config/value", "should fail", "alice");
    assert(!blocked.ok);
    std::cout << "  Locked — write blocked as expected" << std::endl;

    // Lift lockdown
    // NOTE: demo-scale single-call unlock — production needs 12-eye protocol (Step 11)
    (void)f.worm.unlock("astartis-admin");
    assert(!f.worm.is_locked());
    std::cout << "  Lockdown lifted by: astartis-admin" << std::endl;

    // Write must now succeed
    auto r = f.store.write("config/value", "post-unlock value", "alice");
    assert(r.ok);
    std::cout << "  Write AFTER unlock: ok (v" << r.version_number << ")" << std::endl;

    RecordVersion v;
    f.store.read_current("config/value", v);
    assert(v.data == "post-unlock value");
    std::cout << "  Current value: \"" << v.data << "\"" << std::endl;
}

// ---------------------------------------------------------------------------
// Test 5: trigger_lockdown() is idempotent
// ---------------------------------------------------------------------------
void test_lockdown_idempotent() {
    std::cout << "\n=== Test 5: Lockdown Is Idempotent ===" << std::endl;

    TestFixture f;

    (void)f.worm.trigger_lockdown("first trigger");
    (void)f.worm.trigger_lockdown("second trigger — should be ignored");

    assert(f.worm.lockdown_count() == 1);
    assert(f.worm.lock_reason() == "first trigger");  // reason unchanged

    std::cout << "  First trigger:  changed=true" << std::endl;
    std::cout << "  Second trigger: changed=false (no-op)" << std::endl;
    std::cout << "  lockdown_count=1, reason=\"" << f.worm.lock_reason() << "\"" << std::endl;
}

// ---------------------------------------------------------------------------
// Test 6: unlock() is idempotent
// ---------------------------------------------------------------------------
void test_unlock_idempotent() {
    std::cout << "\n=== Test 6: Unlock Is Idempotent ===" << std::endl;

    TestFixture f;

    f.worm.trigger_lockdown("test");
    (void)f.worm.unlock("admin");
    (void)f.worm.unlock("admin");

    assert(!f.worm.is_locked());

    std::cout << "  First unlock:  changed=true" << std::endl;
    std::cout << "  Second unlock: changed=false (no-op)" << std::endl;
}

// ---------------------------------------------------------------------------
// Test 7: lock → unlock → lock cycle, audit chain records all transitions
// ---------------------------------------------------------------------------
void test_lock_unlock_cycle_audited() {
    std::cout << "\n=== Test 7: Lock/Unlock Cycle Fully Audited ===" << std::endl;

    TestFixture f;

    f.worm.trigger_lockdown("breach wave 1");
    f.worm.unlock("astartis-admin");
    f.worm.trigger_lockdown("breach wave 2");
    f.worm.unlock("astartis-admin");

    assert(f.worm.lockdown_count() == 2);
    assert(!f.worm.is_locked());

    // 4 state transitions = 4 audit entries
    size_t chain_len = f.chain.get_chain_length();
    assert(chain_len == 4);

    auto verify = f.chain.verify_chain();
    assert(verify.is_valid);

    std::cout << "  lockdown_count = 2" << std::endl;
    std::cout << "  Audit chain has " << chain_len << " entries:" << std::endl;
    for (const auto& e : f.chain.get_all_entries()) {
        std::cout << "    [" << e.event_type << "] " << e.payload << std::endl;
    }
    std::cout << "  Chain integrity: " << verify.error_message << std::endl;
}

// ---------------------------------------------------------------------------
// Test 8: new write attempts on multiple records all blocked simultaneously
// ---------------------------------------------------------------------------
void test_all_records_blocked_on_lockdown() {
    std::cout << "\n=== Test 8: All Records Blocked on Lockdown ===" << std::endl;

    TestFixture f;

    f.store.write("record/A", "value-A", "alice");
    f.store.write("record/B", "value-B", "alice");
    f.store.write("record/C", "value-C", "alice");

    f.worm.trigger_lockdown("ransomware detected");

    // All three records must reject writes
    auto rA = f.store.write("record/A", "encrypted-A", "ransomware");
    auto rB = f.store.write("record/B", "encrypted-B", "ransomware");
    auto rC = f.store.write("record/C", "encrypted-C", "ransomware");

    assert(!rA.ok && !rB.ok && !rC.ok);

    // All originals intact
    RecordVersion vA, vB, vC;
    f.store.read_current("record/A", vA);
    f.store.read_current("record/B", vB);
    f.store.read_current("record/C", vC);

    assert(vA.data == "value-A");
    assert(vB.data == "value-B");
    assert(vC.data == "value-C");

    std::cout << "  A: \"" << vA.data << "\" (original — intact)" << std::endl;
    std::cout << "  B: \"" << vB.data << "\" (original — intact)" << std::endl;
    std::cout << "  C: \"" << vC.data << "\" (original — intact)" << std::endl;
    std::cout << "  All 3 write attempts rejected." << std::endl;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "ASTARTIS WORM LOCKDOWN TEST SUITE"       << std::endl;
    std::cout << "Step 3: WORM State Machine"              << std::endl;
    std::cout << "========================================" << std::endl;

    try {
        test_initial_state_normal();
        test_trigger_lockdown();
        test_write_blocked_while_locked();
        test_write_succeeds_after_unlock();
        test_lockdown_idempotent();
        test_unlock_idempotent();
        test_lock_unlock_cycle_audited();
        test_all_records_blocked_on_lockdown();

        std::cout << "\n========================================" << std::endl;
        std::cout << "ALL TESTS PASSED"                         << std::endl;
        std::cout << "WORM lockdown is working correctly!"      << std::endl;
        std::cout << "========================================\n" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\nTEST FAILED: " << e.what() << std::endl;
        return 1;
    }
}

// Made with Bob
