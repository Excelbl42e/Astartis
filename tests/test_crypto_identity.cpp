#ifdef NDEBUG
#undef NDEBUG   // force assert() active in Release builds for test executables
#endif
#include <iostream>
#include <cassert>
#include <string>
#include <vector>
#include <algorithm>

#include "../core/audit_chain/audit_chain.h"
#include "../core/crypto_identity/crypto_identity.h"

using namespace astartis::audit;
using namespace astartis::crypto;

// ---------------------------------------------------------------------------
// Test 1: keypair generation succeeds, public key is non-empty
// ---------------------------------------------------------------------------
void test_keypair_generation() {
    std::cout << "\n=== Test 1: Keypair Generation ===" << std::endl;

    Identity alice("alice");

    assert(alice.name() == "alice");

    auto pubkey = alice.public_key_der();
    assert(!pubkey.empty());

    std::cout << "  Identity name: " << alice.name() << std::endl;
    std::cout << "  Public key DER length: " << pubkey.size() << " bytes" << std::endl;
}

// ---------------------------------------------------------------------------
// Test 2: sign + verify round-trip with valid keypair
// ---------------------------------------------------------------------------
void test_valid_signature_passes() {
    std::cout << "\n=== Test 2: Valid Signature Passes ===" << std::endl;

    Identity alice("alice");
    auto pubkey = alice.public_key_der();

    std::vector<uint8_t> challenge = generate_challenge(32);
    SignedRequest req = make_signed_request(alice, challenge);

    if (!verify_signed_request(req, challenge, pubkey)) {
        std::cerr << "FAIL: valid signature rejected\n"; std::exit(1);
    }

    std::cout << "  Challenge length: " << challenge.size() << " bytes" << std::endl;
    std::cout << "  Signature length: " << req.signature.size() << " bytes" << std::endl;
    std::cout << "  verify_signed_request() = true  (PASS)" << std::endl;
}

// ---------------------------------------------------------------------------
// Test 3: forged signature is rejected
// ---------------------------------------------------------------------------
void test_forged_signature_rejected() {
    std::cout << "\n=== Test 3: Forged Signature Rejected ===" << std::endl;

    Identity alice("alice");
    auto pubkey = alice.public_key_der();

    std::vector<uint8_t> challenge = generate_challenge(32);
    SignedRequest req = make_signed_request(alice, challenge);

    // Flip one byte in the signature — this is the forged signature
    SignedRequest forged = req;
    forged.signature[0] ^= 0xFF;

    assert(!verify_signed_request(forged, challenge, pubkey));

    std::cout << "  Signature byte[0] flipped: 0x"
              << std::hex << (int)req.signature[0]
              << " -> 0x" << (int)forged.signature[0] << std::dec << std::endl;
    std::cout << "  verify_signed_request() = false  (PASS — forgery detected)" << std::endl;
}

// ---------------------------------------------------------------------------
// Test 4: replayed challenge is rejected (wrong challenge supplied to verifier)
// ---------------------------------------------------------------------------
void test_replayed_challenge_rejected() {
    std::cout << "\n=== Test 4: Replayed Challenge Rejected ===" << std::endl;

    Identity alice("alice");
    auto pubkey = alice.public_key_der();

    // Attacker replays an old valid request with a different challenge
    std::vector<uint8_t> original_challenge = generate_challenge(32);
    std::vector<uint8_t> new_challenge      = generate_challenge(32);

    // Ensure the two challenges differ (practically guaranteed with 32 random bytes)
    assert(original_challenge != new_challenge);

    SignedRequest req = make_signed_request(alice, original_challenge);

    // Verifier issues new_challenge but attacker presents the old signed request
    assert(!verify_signed_request(req, new_challenge, pubkey));

    std::cout << "  Request signed against challenge A" << std::endl;
    std::cout << "  Verifier checks against challenge B (different)" << std::endl;
    std::cout << "  verify_signed_request() = false  (PASS — replay rejected)" << std::endl;
}

// ---------------------------------------------------------------------------
// Test 5: wrong identity's key is rejected
// ---------------------------------------------------------------------------
void test_wrong_key_rejected() {
    std::cout << "\n=== Test 5: Wrong Key Rejected ===" << std::endl;

    Identity alice("alice");
    Identity eve("eve");   // attacker with her own valid keypair

    auto alice_pubkey = alice.public_key_der();

    std::vector<uint8_t> challenge = generate_challenge(32);

    // Eve signs her own request claiming to be alice
    SignedRequest eve_req = make_signed_request(eve, challenge);
    eve_req.identity_name = "alice";   // impersonation attempt

    // Verify against alice's real public key — must fail
    assert(!verify_signed_request(eve_req, challenge, alice_pubkey));

    std::cout << "  Eve signs with her own key, claims to be alice" << std::endl;
    std::cout << "  Verified against alice's public key" << std::endl;
    std::cout << "  verify_signed_request() = false  (PASS — impersonation rejected)" << std::endl;
}

// ---------------------------------------------------------------------------
// Test 6: two different identities have different public keys
// ---------------------------------------------------------------------------
void test_distinct_keypairs() {
    std::cout << "\n=== Test 6: Distinct Keypairs Per Identity ===" << std::endl;

    Identity alice("alice");
    Identity bob("bob");

    auto pk_alice = alice.public_key_der();
    auto pk_bob   = bob.public_key_der();

    assert(pk_alice != pk_bob);

    std::cout << "  alice pubkey: " << pk_alice.size() << " bytes, starts 0x"
              << std::hex << (int)pk_alice[0] << (int)pk_alice[1] << std::dec << std::endl;
    std::cout << "  bob   pubkey: " << pk_bob.size() << " bytes, starts 0x"
              << std::hex << (int)pk_bob[0] << (int)pk_bob[1] << std::dec << std::endl;
    std::cout << "  Keys differ  (PASS)" << std::endl;
}

// ---------------------------------------------------------------------------
// Test 7: each request gets a fresh challenge — two requests from same identity differ
// ---------------------------------------------------------------------------
void test_per_request_signing() {
    std::cout << "\n=== Test 7: Per-Request Signing (No Session Tokens) ===" << std::endl;

    Identity alice("alice");
    auto pubkey = alice.public_key_der();

    std::vector<uint8_t> c1 = generate_challenge(32);
    std::vector<uint8_t> c2 = generate_challenge(32);
    assert(c1 != c2);

    SignedRequest r1 = make_signed_request(alice, c1);
    SignedRequest r2 = make_signed_request(alice, c2);

    // Each request verifies against its own challenge
    assert( verify_signed_request(r1, c1, pubkey));
    assert( verify_signed_request(r2, c2, pubkey));

    // And not against the other's challenge
    assert(!verify_signed_request(r1, c2, pubkey));
    assert(!verify_signed_request(r2, c1, pubkey));

    // Signatures must differ
    assert(r1.signature != r2.signature);

    std::cout << "  r1 verifies against c1: true" << std::endl;
    std::cout << "  r2 verifies against c2: true" << std::endl;
    std::cout << "  r1 verifies against c2: false (cross-challenge rejected)" << std::endl;
    std::cout << "  r2 verifies against c1: false (cross-challenge rejected)" << std::endl;
    std::cout << "  Signatures are distinct per request  (PASS)" << std::endl;
}

// ---------------------------------------------------------------------------
// Test 8: audit chain integration — sign/verify events logged
// ---------------------------------------------------------------------------
void test_audit_chain_integration() {
    std::cout << "\n=== Test 8: Audit Chain Integration ===" << std::endl;

    AuditChain chain;
    Identity alice("alice");
    auto pubkey = alice.public_key_der();

    auto challenge = generate_challenge(32);
    auto req       = make_signed_request(alice, challenge);
    bool valid     = verify_signed_request(req, challenge, pubkey);

    // Log the result to the audit chain
    std::string event = valid ? "auth_success" : "auth_failure";
    chain.add_entry(event, "identity=" + req.identity_name + " result=" + (valid ? "pass" : "fail"));

    assert(chain.get_chain_length() == 1);
    auto entries = chain.get_all_entries();
    assert(entries[0].event_type == "auth_success");

    auto verify_result = chain.verify_chain();
    assert(verify_result.is_valid);

    std::cout << "  Auth event logged: [" << entries[0].event_type << "] "
              << entries[0].payload << std::endl;
    std::cout << "  Chain integrity: " << verify_result.error_message << std::endl;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "ASTARTIS CRYPTO IDENTITY TEST SUITE"     << std::endl;
    std::cout << "Step 4: secp256k1 ECDSA Identity"        << std::endl;
    std::cout << "========================================" << std::endl;

    try {
        test_keypair_generation();
        test_valid_signature_passes();
        test_forged_signature_rejected();
        test_replayed_challenge_rejected();
        test_wrong_key_rejected();
        test_distinct_keypairs();
        test_per_request_signing();
        test_audit_chain_integration();

        std::cout << "\n========================================" << std::endl;
        std::cout << "ALL TESTS PASSED"                         << std::endl;
        std::cout << "Cryptographic identity working correctly!"<< std::endl;
        std::cout << "========================================\n" << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\nTEST FAILED: " << e.what() << std::endl;
        return 1;
    }
}

// Made with Bob
