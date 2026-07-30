#include "worm_lock.h"
#include <sstream>

namespace astartis {
namespace worm {

WormLock::WormLock(
    std::function<std::string(const std::string&, const std::string&)> audit_adder)
    : audit_adder_(std::move(audit_adder))
{}

bool WormLock::is_locked() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return state_ == State::LOCKED;
}

bool WormLock::trigger_lockdown(const std::string& reason)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (state_ == State::LOCKED) {
        return false;   // already locked — idempotent
    }

    state_       = State::LOCKED;
    lock_reason_ = reason;
    ++lockdown_count_;

    std::ostringstream payload;
    payload << "reason=\"" << reason << "\""
            << " lockdown_count=" << lockdown_count_;
    audit_adder_("worm_lock_engaged", payload.str());

    return true;
}

bool WormLock::unlock(const std::string& authority)
{
    std::lock_guard<std::mutex> lock(mutex_);

    if (state_ == State::NORMAL) {
        return false;   // already unlocked — idempotent
    }

    // DEMO-SCALE STAND-IN: single-call unlock.
    // Production requires 12-eye approval protocol (Step 11).
    state_ = State::NORMAL;

    std::ostringstream payload;
    payload << "authority=\"" << authority << "\""
            << " previous_reason=\"" << lock_reason_ << "\"";
    audit_adder_("worm_lock_lifted", payload.str());

    return true;
}

std::string WormLock::lock_reason() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return lock_reason_;
}

uint64_t WormLock::lockdown_count() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return lockdown_count_;
}

} // namespace worm
} // namespace astartis

// Made with Bob
