// Step 17 -- UnlockProtocol implementation
// See unlock_protocol.h for API documentation.

#include "unlock_protocol/unlock_protocol.h"

#include <sstream>
#include <algorithm>
#include <stdexcept>

namespace astartis {
namespace unlock {

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

UnlockProtocol::UnlockProtocol(
    std::function<std::string(const std::string&, const std::string&)> audit_adder,
    astartis::access::TokenStore& token_store,
    std::function<void(const std::string&)> worm_unlock,
    int threshold
)
    : audit_adder_(std::move(audit_adder))
    , token_store_(token_store)
    , worm_unlock_(std::move(worm_unlock))
    , threshold_(threshold > 0 ? threshold : DEMO_THRESHOLD)
{}

// ---------------------------------------------------------------------------
// register_approver
// ---------------------------------------------------------------------------

void UnlockProtocol::register_approver(const std::string&          name,
                                        ApproverSide                side,
                                        const std::vector<uint8_t>& public_key_der,
                                        const std::string&          token_id)
{
    std::lock_guard<std::mutex> lk(mutex_);
    if (approvers_.count(name)) return; // silently ignore duplicates
    approvers_[name] = ApproverRecord{name, side, public_key_der, token_id};
    votes_[name]     = false;
}

// ---------------------------------------------------------------------------
// begin_session
// ---------------------------------------------------------------------------

void UnlockProtocol::begin_session()
{
    std::lock_guard<std::mutex> lk(mutex_);
    if (state_ == ProtocolState::COLLECTING) return; // already open

    // Reset votes and challenges for a fresh session
    for (auto& kv : votes_)     kv.second = false;
    challenges_.clear();
    state_ = ProtocolState::COLLECTING;
}

// ---------------------------------------------------------------------------
// get_challenge
// ---------------------------------------------------------------------------

std::vector<uint8_t> UnlockProtocol::get_challenge(const std::string& approver_name)
{
    std::lock_guard<std::mutex> lk(mutex_);
    if (!approvers_.count(approver_name)) return {};

    // Issue a fresh challenge if none pending (or refresh if already voted)
    if (!challenges_.count(approver_name)) {
        challenges_[approver_name] = astartis::crypto::generate_challenge(32);
    }
    return challenges_[approver_name];
}

// ---------------------------------------------------------------------------
// cast_vote
// ---------------------------------------------------------------------------

VoteResult UnlockProtocol::cast_vote(
    const std::string&                      approver_name,
    const astartis::crypto::SignedRequest&  signed_req)
{
    std::lock_guard<std::mutex> lk(mutex_);

    auto reject = [&](const std::string& reason) -> VoteResult {
        std::ostringstream pl;
        pl << "approver=" << approver_name << " reason=" << reason;
        audit_adder_("worm_unlock_vote_rejected", pl.str());
        int collected = static_cast<int>(
            std::count_if(votes_.begin(), votes_.end(),
                          [](const auto& kv){ return kv.second; }));
        return VoteResult{false, reason, collected, threshold_, false};
    };

    // 1. Session must be open
    if (state_ == ProtocolState::IDLE)
        return reject("not_collecting");
    if (state_ == ProtocolState::GRANTED)
        return reject("already_granted");

    // 2. Approver must be registered
    auto ap_it = approvers_.find(approver_name);
    if (ap_it == approvers_.end())
        return reject("unknown_approver");

    // 3. Duplicate vote check
    if (votes_[approver_name])
        return reject("duplicate");

    // 4. Step 8 scope-token check
    {
        auto ar = token_store_.check_access(ap_it->second.token_id, "worm_unlock_vote");
        if (!ar.granted)
            return reject("scope_denied:" + ar.reason);
    }

    // 5. ECDSA signature verification
    {
        auto ch_it = challenges_.find(approver_name);
        if (ch_it == challenges_.end())
            return reject("no_challenge_issued");

        bool sig_ok = astartis::crypto::verify_signed_request(
            signed_req, ch_it->second, ap_it->second.public_key_der);
        if (!sig_ok)
            return reject("bad_signature");
    }

    // 6. Accept the vote
    votes_[approver_name] = true;
    challenges_.erase(approver_name); // challenge consumed — single-use

    int collected = static_cast<int>(
        std::count_if(votes_.begin(), votes_.end(),
                      [](const auto& kv){ return kv.second; }));

    std::ostringstream pl;
    pl << "approver=" << approver_name
       << " votes_now=" << collected
       << "/" << threshold_;
    audit_adder_("worm_unlock_vote", pl.str());

    // 7. Check threshold
    if (collected >= threshold_) {
        state_ = ProtocolState::GRANTED;
        audit_adder_("worm_unlock_granted",
                     "votes=" + std::to_string(collected) +
                     " threshold=" + std::to_string(threshold_));
        worm_unlock_("12eye_protocol_demo_scale");
        return VoteResult{true, "ok", collected, threshold_, true};
    }

    return VoteResult{true, "ok", collected, threshold_, false};
}

// ---------------------------------------------------------------------------
// status / accessors
// ---------------------------------------------------------------------------

UnlockStatus UnlockProtocol::status() const
{
    std::lock_guard<std::mutex> lk(mutex_);

    int collected = static_cast<int>(
        std::count_if(votes_.begin(), votes_.end(),
                      [](const auto& kv){ return kv.second; }));

    std::vector<ApproverStatus> approver_list;
    approver_list.reserve(approvers_.size());
    for (const auto& kv : approvers_) {
        auto it = votes_.find(kv.first);
        approver_list.push_back({kv.first, kv.second.side,
                                 it != votes_.end() && it->second});
    }

    return UnlockStatus{state_, collected, threshold_, approver_list};
}

ProtocolState UnlockProtocol::state() const
{
    std::lock_guard<std::mutex> lk(mutex_);
    return state_;
}

int UnlockProtocol::votes_collected() const
{
    std::lock_guard<std::mutex> lk(mutex_);
    return static_cast<int>(
        std::count_if(votes_.begin(), votes_.end(),
                      [](const auto& kv){ return kv.second; }));
}

} // namespace unlock
} // namespace astartis

// Made with Bob
