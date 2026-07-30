#ifdef NDEBUG
#undef NDEBUG   // force assert() active in Release builds for test executables
#endif
#include <iostream>
#include <cassert>
#include <string>
#include <thread>
#include <chrono>

#include "../core/audit_chain/audit_chain.h"
#include "../core/access_token/access_token.h"

using namespace astartis::audit;
using namespace astartis::access;

// ---------------------------------------------------------------------------
// Test 1: Grant a token, access succeeds immediately
// ---------------------------------------------------------------------------
void test_grant_and_check() {
    std::cout << "\n=== Test 1: Grant and Check Access ===" << std::endl;

    AuditChain chain;
    TokenStore store([&chain](const std::string& et, const std::string& p) {
        return chain.add_entry(et, p);
    });

    AccessToken tok = store.grant("alice", "read:config", 5000);
    std::cout << "  Granted token_id: " << tok.token_id << std::endl;
    std::cout << "  Scope: " << tok.scope << "  TTL: 5000ms" << std::endl;

    AccessResult r = store.check_access(tok.token_id, "read:config");
    assert(r.granted);
    assert(r.reason == "ok");
    std::cout << "  check_access(\"read:config\"): " << r.reason << " (granted)" << std::endl;

    // 1 grant audit entry, 0 deny entries
    assert(chain.get_chain_length() == 1);
}

// ---------------------------------------------------------------------------
// Test 2: Token expires — access denied after TTL
// ---------------------------------------------------------------------------
void test_token_expiry() {
    std::cout << "\n=== Test 2: Token Expiry Denies Access ===" << std::endl;

    AuditChain chain;
    TokenStore store([&chain](const std::string& et, const std::string& p) {
        return chain.add_entry(et, p);
    });

    // 100 ms TTL — short enough that we can wait for it
    AccessToken tok = store.grant("bob", "write:records", 100);
    std::cout << "  Granted with 100ms TTL" << std::endl;

    // Must succeed immediately
    auto r1 = store.check_access(tok.token_id, "write:records");
    assert(r1.granted);
    std::cout << "  Immediate check: " << r1.reason << " (ok)" << std::endl;

    // Wait for expiry
    std::this_thread::sleep_for(std::chrono::milliseconds(120));

    // Must now be denied
    auto r2 = store.check_access(tok.token_id, "write:records");
    assert(!r2.granted);
    assert(r2.reason == "expired");
    std::cout << "  After 120ms:     " << r2.reason << " (denied — correct)" << std::endl;

    // The denial is in the audit chain
    size_t n = chain.get_chain_length();
    assert(n == 2);  // 1 grant + 1 deny
    auto v = chain.verify_chain();
    assert(v.is_valid);
    std::cout << "  Audit chain length: " << n << " (grant + denial)" << std::endl;
}

// ---------------------------------------------------------------------------
// Test 3: Scope mismatch — access denied
// ---------------------------------------------------------------------------
void test_scope_mismatch() {
    std::cout << "\n=== Test 3: Scope Mismatch Denies Access ===" << std::endl;

    AuditChain chain;
    TokenStore store([&chain](const std::string& et, const std::string& p) {
        return chain.add_entry(et, p);
    });

    AccessToken tok = store.grant("carol", "read:config", 5000);

    // Wrong scope
    auto r = store.check_access(tok.token_id, "write:records");
    assert(!r.granted);
    assert(r.reason == "scope_mismatch");
    std::cout << "  Token scope: read:config  Required: write:records" << std::endl;
    std::cout << "  Result: " << r.reason << " (denied — correct)" << std::endl;
}

// ---------------------------------------------------------------------------
// Test 4: Explicit revoke before expiry
// ---------------------------------------------------------------------------
void test_explicit_revoke() {
    std::cout << "\n=== Test 4: Explicit Revoke Before Expiry ===" << std::endl;

    AuditChain chain;
    TokenStore store([&chain](const std::string& et, const std::string& p) {
        return chain.add_entry(et, p);
    });

    AccessToken tok = store.grant("dave", "admin:unlock", 30000);

    auto r1 = store.check_access(tok.token_id, "admin:unlock");
    assert(r1.granted);
    std::cout << "  Before revoke: " << r1.reason << " (ok)" << std::endl;

    assert(store.revoke(tok.token_id, "session terminated by admin"));

    auto r2 = store.check_access(tok.token_id, "admin:unlock");
    assert(!r2.granted);
    assert(r2.reason == "revoked");
    std::cout << "  After revoke:  " << r2.reason << " (denied — correct)" << std::endl;

    // Audit chain: 1 grant + 1 revoke + 1 deny
    assert(chain.get_chain_length() == 3);
    auto entries = chain.get_all_entries();
    assert(entries[0].event_type == "token_granted");
    assert(entries[1].event_type == "token_revoked");
    assert(entries[2].event_type == "token_denied");
    std::cout << "  Audit entries: grant -> revoked -> denied (correct)" << std::endl;
}

// ---------------------------------------------------------------------------
// Test 5: Unknown token_id returns not_found
// ---------------------------------------------------------------------------
void test_unknown_token() {
    std::cout << "\n=== Test 5: Unknown Token ID Returns not_found ===" << std::endl;

    AuditChain chain;
    TokenStore store([&chain](const std::string& et, const std::string& p) {
        return chain.add_entry(et, p);
    });

    auto r = store.check_access("deadbeefdeadbeefdeadbeefdeadbeef", "read:config");
    assert(!r.granted);
    assert(r.reason == "not_found");
    std::cout << "  Result: " << r.reason << " (denied — correct)" << std::endl;
}

// ---------------------------------------------------------------------------
// Test 6: live_token_count() reflects state correctly
// ---------------------------------------------------------------------------
void test_live_token_count() {
    std::cout << "\n=== Test 6: live_token_count() Reflects State ===" << std::endl;

    AuditChain chain;
    TokenStore store([&chain](const std::string& et, const std::string& p) {
        return chain.add_entry(et, p);
    });

    assert(store.live_token_count() == 0);

    auto t1 = store.grant("u1", "scope:a", 5000);
    auto t2 = store.grant("u2", "scope:b", 5000);
    assert(store.live_token_count() == 2);
    std::cout << "  After 2 grants: live=" << store.live_token_count() << std::endl;

    store.revoke(t1.token_id, "test");
    assert(store.live_token_count() == 1);
    std::cout << "  After 1 revoke: live=" << store.live_token_count() << std::endl;

    // Short-TTL token — expires
    store.grant("u3", "scope:c", 50);
    std::this_thread::sleep_for(std::chrono::milliseconds(70));
    assert(store.live_token_count() == 1);   // t2 still live; u3 expired
    std::cout << "  After u3 expires: live=" << store.live_token_count() << std::endl;

    (void)t2;  // silence unused warning
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "ASTARTIS ZERO-TRUST ACCESS TOKEN TEST  " << std::endl;
    std::cout << "Step 8: Short-lived Scoped Tokens       " << std::endl;
    std::cout << "========================================" << std::endl;

    try {
        test_grant_and_check();
        test_token_expiry();
        test_scope_mismatch();
        test_explicit_revoke();
        test_unknown_token();
        test_live_token_count();

        std::cout << "\n========================================" << std::endl;
        std::cout << "ALL TESTS PASSED"                         << std::endl;
        std::cout << "Zero-trust access layer working!"         << std::endl;
        std::cout << "========================================\n" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\nTEST FAILED: " << e.what() << std::endl;
        return 1;
    }
}

// Made with Bob
