#ifndef ASTARTIS_UNLOCK_PROTOCOL_H
#define ASTARTIS_UNLOCK_PROTOCOL_H

// Step 17 -- 12-Eye Unlock Protocol
//
// Gated multi-party approval mechanism for lifting a WORM lockdown.
//
// PRODUCTION THRESHOLD : 12 approvers (6 Astartis-side + 6 client-side)
// DEMO-SCALE STAND-IN  : 3 approvers (1 Astartis-side + 2 client-side)
//                        Clearly marked as a stand-in everywhere — do not
//                        interpret the demo threshold as the production value.
//
// Flow per approver:
//   1. Protocol issues a fresh challenge for the named approver.
//   2. Approver signs the challenge via their Identity (Step 4 ECDSA).
//   3. Protocol verifies the SignedRequest against the registered public key.
//   4. Approver must also hold a valid AccessToken with scope
//      "worm_unlock_vote" (Step 8 zero-trust integration).
//   5. On success: vote recorded, "worm_unlock_vote" audit entry written.
//   6. Once votes_collected >= threshold: WormLock::unlock() called,
//      "worm_unlock_granted" audit entry written, session closed.
//
// Rejected votes (bad sig, wrong scope, duplicate) each get a
// "worm_unlock_vote_rejected" audit entry with the reason.

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <mutex>
#include <cstdint>

#include "crypto_identity/crypto_identity.h"
#include "access_token/access_token.h"

namespace astartis {
namespace unlock {

// ---------------------------------------------------------------------------
// Approver side
// ---------------------------------------------------------------------------

enum class ApproverSide { ASTARTIS, CLIENT };

struct ApproverRecord {
    std::string          name;
    ApproverSide         side;
    std::vector<uint8_t> public_key_der;  ///< secp256k1 DER public key
    std::string          token_id;        ///< AccessToken ID for scope check
};

// ---------------------------------------------------------------------------
// Vote result
// ---------------------------------------------------------------------------

struct VoteResult {
    bool        accepted;
    std::string reason;       ///< "ok", "bad_signature", "duplicate", "scope_denied",
                              ///< "unknown_approver", "not_collecting", "already_granted"
    int         votes_now;    ///< votes collected after this call
    int         threshold;    ///< votes required to unlock
    bool        unlocked;     ///< true if this vote triggered the unlock
};

// ---------------------------------------------------------------------------
// Protocol state
// ---------------------------------------------------------------------------

enum class ProtocolState {
    IDLE,        ///< WORM not locked, no session open
    COLLECTING,  ///< Accumulating votes
    GRANTED,     ///< Threshold reached, lockdown lifted
};

// ---------------------------------------------------------------------------
// UnlockStatus — snapshot for the tick / dashboard
// ---------------------------------------------------------------------------

struct ApproverStatus {
    std::string  name;
    ApproverSide side;
    bool         voted;
};

struct UnlockStatus {
    ProtocolState            state;
    int                      votes_collected;
    int                      threshold;
    std::vector<ApproverStatus> approvers;  ///< all registered approvers + their vote status
};

// ---------------------------------------------------------------------------
// UnlockProtocol
// ---------------------------------------------------------------------------

class UnlockProtocol {
public:
    // DEMO-SCALE STAND-IN: 3 approvers stand in for 12 in production.
    static constexpr int DEMO_THRESHOLD       = 3;
    static constexpr int PRODUCTION_THRESHOLD = 12;

    /**
     * @param audit_adder   Callable (event_type, payload) -> entry_id.
     * @param token_store   Step 8 TokenStore — used to validate scope tokens.
     * @param worm_unlock   Callable that lifts the WormLock (calls WormLock::unlock).
     * @param threshold     Votes required (default DEMO_THRESHOLD — stand-in for 12).
     */
    explicit UnlockProtocol(
        std::function<std::string(const std::string&, const std::string&)> audit_adder,
        astartis::access::TokenStore& token_store,
        std::function<void(const std::string&)> worm_unlock,
        int threshold = DEMO_THRESHOLD
    );

    ~UnlockProtocol()                            = default;
    UnlockProtocol(const UnlockProtocol&)        = delete;
    UnlockProtocol& operator=(const UnlockProtocol&) = delete;

    // -----------------------------------------------------------------------
    // Approver registration (call before any lockdown occurs)
    // -----------------------------------------------------------------------

    /**
     * @brief Register an approver with their public key and pre-issued token.
     *
     * The token_id must already exist in the TokenStore with scope
     * "worm_unlock_vote".  Registration fails silently if name is duplicate.
     */
    void register_approver(const std::string&          name,
                           ApproverSide                side,
                           const std::vector<uint8_t>& public_key_der,
                           const std::string&          token_id);

    // -----------------------------------------------------------------------
    // Session control
    // -----------------------------------------------------------------------

    /**
     * @brief Open a new voting session.
     *
     * Called when WormLock transitions to LOCKED.  Clears any previous votes.
     * No-op if a session is already COLLECTING.
     */
    void begin_session();

    // -----------------------------------------------------------------------
    // Voting
    // -----------------------------------------------------------------------

    /**
     * @brief Get the challenge the named approver must sign.
     *
     * Issues a fresh random challenge if none is pending for this approver.
     * Returns empty vector if approver is unknown.
     */
    std::vector<uint8_t> get_challenge(const std::string& approver_name);

    /**
     * @brief Cast a vote with a signed request.
     *
     * Verifies the ECDSA signature, checks the scope token, records the vote.
     * If this vote reaches the threshold, calls worm_unlock_.
     */
    VoteResult cast_vote(const std::string&                  approver_name,
                         const astartis::crypto::SignedRequest& signed_req);

    // -----------------------------------------------------------------------
    // Status
    // -----------------------------------------------------------------------

    UnlockStatus status() const;
    ProtocolState state()  const;
    int votes_collected()  const;
    int threshold()        const { return threshold_; }

private:
    std::function<std::string(const std::string&, const std::string&)> audit_adder_;
    astartis::access::TokenStore&    token_store_;
    std::function<void(const std::string&)> worm_unlock_;
    int threshold_;

    mutable std::mutex mutex_;

    ProtocolState state_ = ProtocolState::IDLE;

    std::map<std::string, ApproverRecord>        approvers_;    // key = name
    std::map<std::string, std::vector<uint8_t>>  challenges_;   // key = name, pending challenge
    std::map<std::string, bool>                  votes_;        // key = name, true = voted
};

} // namespace unlock
} // namespace astartis

#endif // ASTARTIS_UNLOCK_PROTOCOL_H

// Made with Bob
