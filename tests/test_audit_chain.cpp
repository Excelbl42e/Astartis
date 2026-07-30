#ifdef NDEBUG
#undef NDEBUG   // force assert() active in Release builds for test executables
#endif
#include <iostream>
#include <cassert>
#include "../core/audit_chain/audit_chain.h"

using namespace astartis::audit;

void test_genesis_entry() {
    std::cout << "\n=== Test 1: Genesis Entry ===" << std::endl;

    AuditChain chain;
    std::string entry_id = chain.add_entry("system_start", "System initialized");

    assert(chain.get_chain_length() == 1);

    const AuditEntry* entry = chain.get_entry(entry_id);
    assert(entry != nullptr);
    assert(entry->previous_hash == "0000000000000000000000000000000000000000000000000000000000000000");

    std::cout << "  Genesis entry created with correct previous_hash" << std::endl;
    std::cout << "  Entry ID: " << entry->entry_id << std::endl;
    std::cout << "  Hash: " << entry->current_hash << std::endl;
}

void test_chain_growth() {
    std::cout << "\n=== Test 2: Chain Growth ===" << std::endl;

    AuditChain chain;

    chain.add_entry("login",  "User alice logged in");
    chain.add_entry("access", "Alice accessed resource X");
    chain.add_entry("modify", "Alice modified resource X");
    chain.add_entry("access", "Alice accessed resource Y");
    chain.add_entry("logout", "User alice logged out");

    assert(chain.get_chain_length() == 5);

    std::cout << "  Chain grew to 5 entries" << std::endl;
}

void test_hash_linking() {
    std::cout << "\n=== Test 3: Hash Linking ===" << std::endl;

    AuditChain chain;

    chain.add_entry("event1", "First event");
    chain.add_entry("event2", "Second event");
    chain.add_entry("event3", "Third event");

    auto entries = chain.get_all_entries();

    assert(entries[1].previous_hash == entries[0].current_hash);
    assert(entries[2].previous_hash == entries[1].current_hash);

    std::cout << "  Each entry's previous_hash correctly links to prior entry's current_hash" << std::endl;
    std::cout << "  Entry 0 hash: " << entries[0].current_hash.substr(0, 16) << "..." << std::endl;
    std::cout << "  Entry 1 prev: " << entries[1].previous_hash.substr(0, 16) << "..." << std::endl;
    std::cout << "  Entry 1 hash: " << entries[1].current_hash.substr(0, 16) << "..." << std::endl;
    std::cout << "  Entry 2 prev: " << entries[2].previous_hash.substr(0, 16) << "..." << std::endl;
}

void test_tampering_detection() {
    std::cout << "\n=== Test 4: TAMPERING DETECTION (Critical Test) ===" << std::endl;

    AuditChain chain;

    chain.add_entry("event1", "Entry 1");
    chain.add_entry("event2", "Entry 2");
    chain.add_entry("event3", "Entry 3 - ORIGINAL");
    chain.add_entry("event4", "Entry 4");
    chain.add_entry("event5", "Entry 5");

    std::cout << "  Created chain with 5 entries" << std::endl;

    // Verify chain is valid before tampering
    VerificationResult result_before = chain.verify_chain();
    assert(result_before.is_valid);
    std::cout << "  Chain verification PASSED before tampering" << std::endl;

    // DELIBERATELY TAMPER: corrupt entry #3 (index 2) directly in storage —
    // payload changed but stored hash is NOT updated, exactly like an attacker
    // editing a database row directly.
    (void)chain.tamper_entry_for_testing(2, "Entry 3 - TAMPERED DATA!!!");
    std::cout << "\n  [TAMPER] Payload of entry index 2 overwritten in storage." << std::endl;
    std::cout << "  [TAMPER] Stored hash was NOT updated (simulates direct DB edit)." << std::endl;

    // Now verify — chain MUST be detected as invalid
    VerificationResult result_after = chain.verify_chain();

    std::cout << "\n=== VERIFICATION RESULT AFTER TAMPERING ===" << std::endl;
    std::cout << "  Chain valid: " << (result_after.is_valid ? "YES" : "NO") << std::endl;
    std::cout << "  Error: " << result_after.error_message << std::endl;
    std::cout << "  Tampered index: " << result_after.tampered_entry_index << std::endl;
    if (!result_after.expected_hash.empty()) {
        std::cout << "  Expected hash: " << result_after.expected_hash.substr(0, 32) << "..." << std::endl;
        std::cout << "  Actual hash:   " << result_after.actual_hash.substr(0, 32)   << "..." << std::endl;
    }

    // Critical assertion — tampering MUST be detected
    assert(!result_after.is_valid);
    assert(result_after.tampered_entry_index == 2);

    std::cout << "\n  TAMPERING SUCCESSFULLY DETECTED" << std::endl;
    std::cout << "  The audit chain caught the direct storage modification!" << std::endl;
}

void test_tamper_location() {
    std::cout << "\n=== Test 5: Tamper Location Identification ===" << std::endl;

    AuditChain chain;

    chain.add_entry("event1", "Entry 1");
    chain.add_entry("event2", "Entry 2");
    chain.add_entry("event3", "Entry 3");
    chain.add_entry("event4", "Entry 4");
    chain.add_entry("event5", "Entry 5");

    // Corrupt entry #4 (index 3) directly in storage
    (void)chain.tamper_entry_for_testing(3, "TAMPERED ENTRY 4");

    VerificationResult result = chain.verify_chain();

    assert(!result.is_valid);
    // Hash mismatch is detected at the corrupted entry itself (index 3)
    assert(result.tampered_entry_index == 3);

    std::cout << "  Tampered entry correctly identified at index: "
              << result.tampered_entry_index << std::endl;
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "ASTARTIS AUDIT CHAIN TEST SUITE" << std::endl;
    std::cout << "Testing SHA-256 Merkle Chain Implementation" << std::endl;
    std::cout << "========================================" << std::endl;

    try {
        test_genesis_entry();
        test_chain_growth();
        test_hash_linking();
        test_tampering_detection();  // CRITICAL TEST
        test_tamper_location();

        std::cout << "\n========================================" << std::endl;
        std::cout << "ALL TESTS PASSED" << std::endl;
        std::cout << "Audit chain is working correctly!" << std::endl;
        std::cout << "========================================\n" << std::endl;

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\nTEST FAILED: " << e.what() << std::endl;
        return 1;
    }
}

// Made with Bob
