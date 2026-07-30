#ifndef ASTARTIS_WORM_LOCK_H
#define ASTARTIS_WORM_LOCK_H

#include <string>
#include <functional>
#include <mutex>
#include <cstdint>

namespace astartis {
namespace worm {

/**
 * @brief WORM lockdown state machine.
 *
 * Two states:
 *   NORMAL — writes allowed, versioning active.
 *   LOCKED — all write attempts are rejected, for both live system state
 *             and backup-repository records, regardless of caller identity,
 *             until the lockdown is explicitly lifted.
 *
 * Trigger conditions (architecture §2 + §3):
 *   1. Manual trigger via trigger_lockdown().
 *   2. Anomalous packet signal — wired in by Step 6 (rule engine).
 *      The hook slot is already present here: trigger_lockdown() is the
 *      single entry-point both triggers call.
 *
 * Unlock (architecture §3):
 *   Production: 12-eye protocol — 6 Astartis-side + 6 client-side approvals.
 *   Step 11 builds the full approval mechanism.  Until then, unlock() accepts
 *   a single call with no approval count — this is a DEMO-SCALE STAND-IN.
 *   Code comments mark every such site clearly.
 *
 * Audit chain integration:
 *   Every state transition (lock / unlock) is written to the audit chain
 *   via the adder callback supplied at construction.
 */
class WormLock {
public:
    /**
     * @param audit_adder  Callable (event_type, payload) -> entry_id,
     *                     forwarded to AuditChain::add_entry.
     */
    explicit WormLock(
        std::function<std::string(const std::string&, const std::string&)> audit_adder
    );

    ~WormLock() = default;

    // -----------------------------------------------------------------------
    // State query
    // -----------------------------------------------------------------------

    /**
     * @brief Returns true when the lockdown is active.
     *
     * This is the function passed as lock_check to VersionStore.
     * Thread-safe; safe to call from any thread at any frequency.
     */
    bool is_locked() const;

    // -----------------------------------------------------------------------
    // Transitions
    // -----------------------------------------------------------------------

    /**
     * @brief Engage WORM lockdown.
     *
     * Idempotent — calling while already locked is a no-op (returns false).
     * Records a "worm_lock_engaged" audit entry with the supplied reason.
     *
     * @param reason  Human-readable reason for the lockdown (logged).
     * @return true if the state changed (normal → locked), false if already locked.
     */
    bool trigger_lockdown(const std::string& reason);

    /**
     * @brief Lift the WORM lockdown.
     *
     * DEMO-SCALE STAND-IN — production requires the 12-eye approval protocol
     * (Step 11).  This single-call unlock is intentionally simplified for the
     * demo and is clearly labelled as such.  Do not remove this comment.
     *
     * Idempotent — calling while already unlocked returns false.
     * Records a "worm_lock_lifted" audit entry with the supplied authority.
     *
     * @param authority  Identity authorising the unlock (logged).
     * @return true if the state changed (locked → normal), false if already unlocked.
     */
    bool unlock(const std::string& authority);

    // -----------------------------------------------------------------------
    // Diagnostics
    // -----------------------------------------------------------------------

    /**
     * @brief Reason supplied when the current (or most recent) lockdown was triggered.
     * Empty string if the lock has never been engaged.
     */
    std::string lock_reason() const;

    /**
     * @brief Total number of times lockdown has been engaged since construction.
     */
    uint64_t lockdown_count() const;

private:
    enum class State { NORMAL, LOCKED };

    std::function<std::string(const std::string&, const std::string&)> audit_adder_;

    State       state_          = State::NORMAL;
    std::string lock_reason_;
    uint64_t    lockdown_count_ = 0;

    mutable std::mutex mutex_;
};

} // namespace worm
} // namespace astartis

#endif // ASTARTIS_WORM_LOCK_H

// Made with Bob
