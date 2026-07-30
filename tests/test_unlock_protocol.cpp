// Step 17 -- 12-Eye Unlock Protocol test
//
// DEMO-SCALE STAND-IN: 3 approvers represent 12 in production.
// All threshold constants are clearly marked — do not read demo values as
// production values.
//
// Tests:
//  1. Fresh lockdown → state == COLLECTING
//  2. Votes below threshold → still locked after each vote
//  3. Final vote reaches threshold → unlocked, audit entry present
//  4. Duplicate vote from same approver → rejected, "duplicate" reason
//  5. Invalid signature → rejected, "bad_signature" reason, audit entry written
//  6. Approver without valid scope token → rejected, "scope_denied" reason
//  7. Full audit chain integrity check

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <cassert>
#include <iostream>
#include <string>
#include <vector>

#include "audit_chain/audit_chain.h"
#include "worm_lock/worm_lock.h"
#include "access_token/access_token.h"
#include "crypto_identity/crypto_identity.h"
#include "unlock_protocol/unlock_protocol.h"

using namespace astartis::audit;
using namespace astartis::worm;
using namespace astartis::access;
using namespace astartis::crypto;
using namespace astartis::unlock;

// ---------------------------------------------------------------------------
// Test fixture — wires all modules together for one test scenario
// ---------------------------------------------------------------------------

struct Fixture {
    AuditChain  chain;
    WormLock    worm;
    TokenStore  tokens;

    // DEMO-SCALE: 3 approvers (1 Astartis-side + 2 client-side)
    Identity    approver_ast  {"astartis-admin-1"};
    Identity    approver_cl1  {"client-rep-1"};
    Identity    approver_cl2  {"client-rep-2"};

    UnlockProtocol protocol;

    Fixture()
        : worm([this](const std::string& et, const std::string& p){
              return chain.add_entry(et, p); })
        , tokens([this](const std::string& et, const std::string& p){
              return chain.add_entry(et, p); })
        , protocol(
              [this](const std::string& et, const std::string& p){
                  return chain.add_entry(et, p); },
              tokens,
              [this](const std::string& authority){
                  worm.unlock(authority); },
              UnlockProtocol::DEMO_THRESHOLD)   // 3 — DEMO-SCALE STAND-IN
    {
        // Issue long-lived scope tokens for each approver (24 h)
        constexpr int64_t TTL_24H = 24LL * 60 * 60 * 1000;
        auto t_ast = tokens.grant("astartis-admin-1", "worm_unlock_vote", TTL_24H);
        auto t_cl1 = tokens.grant("client-rep-1",     "worm_unlock_vote", TTL_24H);
        auto t_cl2 = tokens.grant("client-rep-2",     "worm_unlock_vote", TTL_24H);

        // Register approvers with their public keys and token IDs
        protocol.register_approver("astartis-admin-1", ApproverSide::ASTARTIS,
                                    approver_ast.public_key_der(), t_ast.token_id);
        protocol.register_approver("client-rep-1",     ApproverSide::CLIENT,
                                    approver_cl1.public_key_der(), t_cl1.token_id);
        protocol.register_approver("client-rep-2",     ApproverSide::CLIENT,
                                    approver_cl2.public_key_der(), t_cl2.token_id);
    }

    // Helper: trigger lockdown and open a voting session
    void trigger_and_open() {
        worm.trigger_lockdown("test_lockdown");
        protocol.begin_session();
    }

    // Helper: cast a valid vote from named approver using the correct Identity
    VoteResult valid_vote(const std::string& name, Identity& id) {
        auto challenge = protocol.get_challenge(name);
        assert(!challenge.empty());
        auto signed_req = make_signed_request(id, challenge);
        return protocol.cast_vote(name, signed_req);
    }
};

// ---------------------------------------------------------------------------
// Test 1: trigger lockdown → state == COLLECTING
// ---------------------------------------------------------------------------
static void test_lockdown_begins_collecting()
{
    std::cout << "\n=== Test 1: Lockdown → COLLECTING ===\n";
    Fixture f;
    f.trigger_and_open();

    assert(f.worm.is_locked());
    assert(f.protocol.state() == ProtocolState::COLLECTING);
    assert(f.protocol.votes_collected() == 0);

    auto st = f.protocol.status();
    assert(st.votes_collected == 0);
    assert(st.threshold == UnlockProtocol::DEMO_THRESHOLD);
    assert(st.approvers.size() == 3);

    std::cout << "  state=COLLECTING, votes=0/" << st.threshold << "\n";
    std::cout << "[PASS]\n";
}

// ---------------------------------------------------------------------------
// Test 2: votes below threshold → still locked
// ---------------------------------------------------------------------------
static void test_insufficient_votes_stay_locked()
{
    std::cout << "\n=== Test 2: Insufficient votes → still locked ===\n";
    Fixture f;
    f.trigger_and_open();

    // Cast 2 of 3 needed votes — DEMO_THRESHOLD is 3
    auto r1 = f.valid_vote("astartis-admin-1", f.approver_ast);
    assert(r1.accepted && !r1.unlocked);
    assert(f.worm.is_locked());
    std::cout << "  vote 1 accepted, still locked (" << r1.votes_now << "/" << r1.threshold << ")\n";

    auto r2 = f.valid_vote("client-rep-1", f.approver_cl1);
    assert(r2.accepted && !r2.unlocked);
    assert(f.worm.is_locked());
    std::cout << "  vote 2 accepted, still locked (" << r2.votes_now << "/" << r2.threshold << ")\n";

    std::cout << "[PASS]\n";
}

// ---------------------------------------------------------------------------
// Test 3: final vote → unlocked, audit entries correct
// ---------------------------------------------------------------------------
static void test_threshold_unlocks()
{
    std::cout << "\n=== Test 3: Final vote → threshold reached → unlocked ===\n";
    Fixture f;
    f.trigger_and_open();

    f.valid_vote("astartis-admin-1", f.approver_ast);
    f.valid_vote("client-rep-1",     f.approver_cl1);
    auto r3 = f.valid_vote("client-rep-2", f.approver_cl2);

    assert(r3.accepted);
    assert(r3.unlocked);
    assert(r3.votes_now == UnlockProtocol::DEMO_THRESHOLD);
    assert(!f.worm.is_locked());
    assert(f.protocol.state() == ProtocolState::GRANTED);
    std::cout << "  all " << r3.votes_now << " votes accepted → GRANTED, worm unlocked\n";

    // Audit chain must contain worm_unlock_vote × 3 and worm_unlock_granted × 1
    int vote_entries = 0, granted_entries = 0;
    for (const auto& e : f.chain.get_all_entries()) {
        if (e.event_type == "worm_unlock_vote")    ++vote_entries;
        if (e.event_type == "worm_unlock_granted") ++granted_entries;
    }
    assert(vote_entries   == UnlockProtocol::DEMO_THRESHOLD);
    assert(granted_entries == 1);
    std::cout << "  audit: " << vote_entries << " votes + " << granted_entries << " granted\n";

    std::cout << "[PASS]\n";
}

// ---------------------------------------------------------------------------
// Test 4: duplicate vote rejected
// ---------------------------------------------------------------------------
static void test_duplicate_vote_rejected()
{
    std::cout << "\n=== Test 4: Duplicate vote rejected ===\n";
    Fixture f;
    f.trigger_and_open();

    f.valid_vote("astartis-admin-1", f.approver_ast);

    // Second vote from same approver — must fail
    // Need a fresh challenge; get_challenge returns empty after vote consumed
    // so we manufacture a request directly
    auto ch = f.protocol.get_challenge("astartis-admin-1");
    // challenge is empty because vote already cast (challenge was consumed)
    // cast_vote will reject before reaching sig check
    astartis::crypto::SignedRequest dummy_req;
    dummy_req.identity_name = "astartis-admin-1";
    dummy_req.challenge     = ch; // empty or stale — doesn't matter; duplicate check fires first
    dummy_req.timestamp_ms  = 0;
    auto r2 = f.protocol.cast_vote("astartis-admin-1", dummy_req);

    assert(!r2.accepted);
    assert(r2.reason == "duplicate");
    std::cout << "  duplicate vote rejected: " << r2.reason << "\n";

    // Confirm rejection audit entry
    bool found_rejected = false;
    for (const auto& e : f.chain.get_all_entries())
        if (e.event_type == "worm_unlock_vote_rejected" &&
            e.payload.find("duplicate") != std::string::npos)
            found_rejected = true;
    assert(found_rejected);
    std::cout << "  audit entry worm_unlock_vote_rejected present\n";

    std::cout << "[PASS]\n";
}

// ---------------------------------------------------------------------------
// Test 5: bad signature rejected
// ---------------------------------------------------------------------------
static void test_bad_signature_rejected()
{
    std::cout << "\n=== Test 5: Bad signature rejected ===\n";
    Fixture f;
    f.trigger_and_open();

    auto challenge = f.protocol.get_challenge("client-rep-1");

    // Sign with the WRONG identity (cl2 signs cl1's challenge)
    auto forged_req = make_signed_request(f.approver_cl2, challenge);
    forged_req.identity_name = "client-rep-1"; // claim to be cl1

    auto r = f.protocol.cast_vote("client-rep-1", forged_req);
    assert(!r.accepted);
    assert(r.reason == "bad_signature");
    std::cout << "  forged signature rejected: " << r.reason << "\n";

    bool found = false;
    for (const auto& e : f.chain.get_all_entries())
        if (e.event_type == "worm_unlock_vote_rejected" &&
            e.payload.find("bad_signature") != std::string::npos)
            found = true;
    assert(found);
    std::cout << "  audit entry worm_unlock_vote_rejected present\n";

    std::cout << "[PASS]\n";
}

// ---------------------------------------------------------------------------
// Test 6: approver without valid scope token rejected
// ---------------------------------------------------------------------------
static void test_scope_token_required()
{
    std::cout << "\n=== Test 6: No scope token → rejected ===\n";

    // Build a fixture with an extra approver whose token has the wrong scope
    AuditChain  chain;
    WormLock    worm([&](const std::string& et, const std::string& p){
                         return chain.add_entry(et, p); });
    TokenStore  tokens([&](const std::string& et, const std::string& p){
                           return chain.add_entry(et, p); });
    UnlockProtocol protocol(
        [&](const std::string& et, const std::string& p){
            return chain.add_entry(et, p); },
        tokens,
        [&](const std::string& auth){ worm.unlock(auth); },
        1  // threshold=1 so we'd unlock immediately if the vote were valid
    );

    Identity interloper{"interloper"};

    // Grant a token with the WRONG scope
    auto bad_token = tokens.grant("interloper", "read:config", 60'000);
    protocol.register_approver("interloper", ApproverSide::CLIENT,
                                interloper.public_key_der(), bad_token.token_id);

    worm.trigger_lockdown("test");
    protocol.begin_session();

    auto challenge = protocol.get_challenge("interloper");
    auto req = make_signed_request(interloper, challenge);
    auto r = protocol.cast_vote("interloper", req);

    assert(!r.accepted);
    assert(r.reason.find("scope_denied") != std::string::npos);
    assert(worm.is_locked()); // must still be locked
    std::cout << "  vote rejected: " << r.reason << "\n";
    std::cout << "  worm still locked: " << worm.is_locked() << "\n";

    std::cout << "[PASS]\n";
}

// ---------------------------------------------------------------------------
// Test 7: audit chain integrity throughout
// ---------------------------------------------------------------------------
static void test_audit_chain_integrity()
{
    std::cout << "\n=== Test 7: Audit chain integrity ===\n";
    Fixture f;
    f.trigger_and_open();
    f.valid_vote("astartis-admin-1", f.approver_ast);
    f.valid_vote("client-rep-1",     f.approver_cl1);
    f.valid_vote("client-rep-2",     f.approver_cl2);

    auto vr = f.chain.verify_chain();
    assert(vr.is_valid);
    std::cout << "  chain length=" << f.chain.get_chain_length()
              << " valid=" << vr.is_valid << "\n";
    std::cout << "[PASS]\n";
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main()
{
    std::cout << "========================================\n"
              << "ASTARTIS 12-EYE UNLOCK PROTOCOL TEST   \n"
              << "Step 17 (DEMO-SCALE: 3 of 12 approvers)\n"
              << "========================================\n";

    try {
        test_lockdown_begins_collecting();
        test_insufficient_votes_stay_locked();
        test_threshold_unlocks();
        test_duplicate_vote_rejected();
        test_bad_signature_rejected();
        test_scope_token_required();
        test_audit_chain_integrity();

        std::cout << "\n========================================\n"
                  << "ALL TESTS PASSED\n"
                  << "12-Eye Unlock Protocol (Step 17) working!\n"
                  << "========================================\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\nTEST FAILED: " << e.what() << "\n";
        return 1;
    }
}

// Made with Bob
