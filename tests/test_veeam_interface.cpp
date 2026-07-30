// Step 19 -- VeeamInterface integration test
//
// Tests:
//  1. Initial state: UNLOCKED, backup_count seeded, integrity_check_count == 0.
//  2. lock_backups() → IMMUTABLE, audit entry "veeam_backup_locked" written,
//     locked_at_ms non-zero, locked_by_reason matches.
//  3. unlock_backups() → UNLOCKED, audit entry "veeam_backup_unlocked" written.
//  4. Idempotency: lock_backups() while already IMMUTABLE returns success=false.
//  5. integrity_check() → passed=true, counter incremented, audit entry written.
//  6. Audit chain integrity: verify_chain() passes after all transitions.
//
// No external service dependency → no SKIP_RETURN_CODE needed.

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <cassert>
#include <iostream>
#include <string>

#include "audit_chain/audit_chain.h"
#include "worm_lock/worm_lock.h"
#include "veeam_interface/veeam_interface.h"

using namespace astartis::audit;
using namespace astartis::worm;
using namespace astartis::backup;

// ---------------------------------------------------------------------------
// Shared fixture — mirrors the wired-together pattern from test_worm_lock.cpp
// ---------------------------------------------------------------------------

struct Fixture {
    AuditChain     chain;
    WormLock       worm;
    VeeamInterface veeam;

    Fixture()
        : worm([this](const std::string& et, const std::string& p){
               return chain.add_entry(et, p); })
        , veeam([this](const std::string& et, const std::string& p){
                return chain.add_entry(et, p); })
    {}
};

// ---------------------------------------------------------------------------
// Test 1: Initial state
// ---------------------------------------------------------------------------
static void test_initial_state()
{
    std::cout << "\n=== Test 1: Initial state — UNLOCKED, seeded backup count ===\n";
    Fixture f;

    auto s = f.veeam.status();

    assert(s.lock_state == BackupLockState::UNLOCKED
           && "initial lock_state must be UNLOCKED");
    assert(s.backup_count == VeeamInterface::STUB_BACKUP_COUNT
           && "backup_count must be seeded at STUB_BACKUP_COUNT");
    assert(s.integrity_check_count == 0
           && "integrity_check_count must start at 0");
    assert(s.locked_at_ms == 0
           && "locked_at_ms must be 0 when unlocked");
    assert(s.locked_by_reason.empty()
           && "locked_by_reason must be empty when unlocked");
    assert(s.repo_id == std::string(VeeamInterface::STUB_REPO_ID)
           && "repo_id must match STUB_REPO_ID");

    std::cout << "  repo_id=" << s.repo_id << "\n"
              << "  lock_state=UNLOCKED\n"
              << "  backup_count=" << s.backup_count << "\n"
              << "  integrity_check_count=0\n"
              << "[PASS]\n";
}

// ---------------------------------------------------------------------------
// Test 2: lock_backups() — UNLOCKED → IMMUTABLE
// ---------------------------------------------------------------------------
static void test_lock_backups()
{
    std::cout << "\n=== Test 2: lock_backups() → IMMUTABLE ===\n";
    Fixture f;

    auto r = f.veeam.lock_backups("worm_lockdown: anomalous packet detected");

    assert(r.success && "lock_backups must succeed from UNLOCKED state");
    assert(r.lock_state == BackupLockState::IMMUTABLE
           && "lock_state must be IMMUTABLE after locking");
    assert(r.backup_count == VeeamInterface::STUB_BACKUP_COUNT
           && "backup_count must be preserved");
    assert(r.locked_at_ms > 0
           && "locked_at_ms must be non-zero after locking");
    assert(r.locked_by_reason == "worm_lockdown: anomalous packet detected"
           && "locked_by_reason must match reason passed to lock_backups");
    assert(!r.audit_entry_id.empty()
           && "audit entry must be written");

    // Confirm "veeam_backup_locked" appears in the chain
    bool found = false;
    for (const auto& e : f.chain.get_all_entries())
        if (e.event_type == "veeam_backup_locked") found = true;
    assert(found && "audit chain must contain veeam_backup_locked entry");

    // status() must now reflect the locked state
    auto s = f.veeam.status();
    assert(s.lock_state == BackupLockState::IMMUTABLE);
    assert(s.locked_at_ms > 0);

    std::cout << "  lock_state=IMMUTABLE\n"
              << "  locked_at_ms=" << r.locked_at_ms << "\n"
              << "  locked_by_reason=" << r.locked_by_reason << "\n"
              << "  audit_entry_id=" << r.audit_entry_id << "\n"
              << "[PASS]\n";
}

// ---------------------------------------------------------------------------
// Test 3: unlock_backups() — IMMUTABLE → UNLOCKED
// ---------------------------------------------------------------------------
static void test_unlock_backups()
{
    std::cout << "\n=== Test 3: unlock_backups() → UNLOCKED ===\n";
    Fixture f;

    f.veeam.lock_backups("worm_lockdown: test");

    auto r = f.veeam.unlock_backups("astartis-admin-1");

    assert(r.success && "unlock_backups must succeed from IMMUTABLE state");
    assert(r.lock_state == BackupLockState::UNLOCKED
           && "lock_state must be UNLOCKED after unlock");
    assert(!r.audit_entry_id.empty()
           && "audit entry must be written on unlock");

    bool found = false;
    for (const auto& e : f.chain.get_all_entries())
        if (e.event_type == "veeam_backup_unlocked") found = true;
    assert(found && "audit chain must contain veeam_backup_unlocked entry");

    auto s = f.veeam.status();
    assert(s.lock_state == BackupLockState::UNLOCKED);
    assert(s.locked_at_ms == 0);
    assert(s.locked_by_reason.empty());

    std::cout << "  lock_state=UNLOCKED after unlock by astartis-admin-1\n"
              << "  audit_entry_id=" << r.audit_entry_id << "\n"
              << "[PASS]\n";
}

// ---------------------------------------------------------------------------
// Test 4: Idempotency — lock while already IMMUTABLE returns success=false
// ---------------------------------------------------------------------------
static void test_lock_idempotent()
{
    std::cout << "\n=== Test 4: Idempotency — double-lock returns success=false ===\n";
    Fixture f;

    auto r1 = f.veeam.lock_backups("first lock");
    assert(r1.success);

    auto r2 = f.veeam.lock_backups("second lock — must be rejected");
    assert(!r2.success && "second lock_backups must return success=false");
    assert(r2.lock_state == BackupLockState::IMMUTABLE
           && "lock_state must remain IMMUTABLE after rejected call");
    assert(r2.error_message == "already_locked"
           && "error_message must be already_locked");

    // Confirm the reason from the first lock is preserved, not overwritten
    auto s = f.veeam.status();
    assert(s.locked_by_reason == "first lock"
           && "locked_by_reason must not be overwritten by idempotent call");

    // Only one veeam_backup_locked entry should exist
    int lock_entries = 0;
    for (const auto& e : f.chain.get_all_entries())
        if (e.event_type == "veeam_backup_locked") ++lock_entries;
    assert(lock_entries == 1 && "only one veeam_backup_locked audit entry expected");

    std::cout << "  first lock: success=true\n"
              << "  second lock: success=false, error=" << r2.error_message << "\n"
              << "  locked_by_reason preserved: " << s.locked_by_reason << "\n"
              << "  veeam_backup_locked audit entries: " << lock_entries << "\n"
              << "[PASS]\n";
}

// ---------------------------------------------------------------------------
// Test 5: integrity_check() — passes, increments counter, writes audit entry
// ---------------------------------------------------------------------------
static void test_integrity_check()
{
    std::cout << "\n=== Test 5: integrity_check() — passes, audit entry written ===\n";
    Fixture f;

    // Run twice to confirm counter increments
    auto r1 = f.veeam.integrity_check();
    auto r2 = f.veeam.integrity_check();

    assert(r1.passed && "integrity_check must pass");
    assert(r1.violations_found == 0);
    assert(r1.checked_count == VeeamInterface::STUB_BACKUP_COUNT);
    assert(r1.checked_at_ms > 0);
    assert(!r1.audit_entry_id.empty());

    assert(r2.passed);

    auto s = f.veeam.status();
    assert(s.integrity_check_count == 2
           && "integrity_check_count must be 2 after two checks");
    assert(s.last_integrity_check_ms == r2.checked_at_ms
           && "last_integrity_check_ms must match last check timestamp");

    int check_entries = 0;
    for (const auto& e : f.chain.get_all_entries())
        if (e.event_type == "veeam_integrity_check") ++check_entries;
    assert(check_entries == 2 && "two veeam_integrity_check audit entries expected");

    std::cout << "  check 1: passed, entry=" << r1.audit_entry_id << "\n"
              << "  check 2: passed, entry=" << r2.audit_entry_id << "\n"
              << "  integrity_check_count=" << s.integrity_check_count << "\n"
              << "[PASS]\n";
}

// ---------------------------------------------------------------------------
// Test 6: Full lifecycle + audit chain integrity
// ---------------------------------------------------------------------------
static void test_audit_chain_integrity()
{
    std::cout << "\n=== Test 6: Full lifecycle — audit chain integrity ===\n";
    Fixture f;

    // Sequence: lock → integrity check → unlock → integrity check
    f.veeam.lock_backups("breach detected");
    f.veeam.integrity_check();
    f.veeam.unlock_backups("astartis-admin-1");
    f.veeam.integrity_check();

    // 4 events → 4 audit entries (all routed through the shared AuditChain)
    size_t len = f.chain.get_chain_length();
    assert(len == 4 && "4 veeam events must produce 4 audit entries");

    auto vr = f.chain.verify_chain();
    assert(vr.is_valid && "audit chain must be valid after full lifecycle");

    // Also confirm WormLock sharing the same chain doesn't corrupt it
    f.worm.trigger_lockdown("post-veeam worm trigger");
    assert(f.chain.get_chain_length() == 5);
    auto vr2 = f.chain.verify_chain();
    assert(vr2.is_valid && "chain must remain valid after adding WormLock entry");

    std::cout << "  chain entries: " << f.chain.get_chain_length() << "\n"
              << "  chain valid: " << vr2.is_valid << "\n";
    for (const auto& e : f.chain.get_all_entries())
        std::cout << "    [" << e.event_type << "] " << e.payload << "\n";
    std::cout << "[PASS]\n";
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    std::cout << "========================================\n"
              << "ASTARTIS VEEAM INTERFACE TEST           \n"
              << "Step 19 — Stubbed backup repo           \n"
              << "========================================\n";

    try {
        test_initial_state();
        test_lock_backups();
        test_unlock_backups();
        test_lock_idempotent();
        test_integrity_check();
        test_audit_chain_integrity();

        std::cout << "\n========================================\n"
                  << "ALL TESTS PASSED\n"
                  << "VeeamInterface (Step 19) working!\n"
                  << "========================================\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\nTEST FAILED: " << e.what() << "\n";
        return 1;
    }
}

// Made with Bob
