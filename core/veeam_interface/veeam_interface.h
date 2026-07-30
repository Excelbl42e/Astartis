#ifndef ASTARTIS_VEEAM_INTERFACE_H
#define ASTARTIS_VEEAM_INTERFACE_H

// Step 19 -- Veeam / IBM Storage integration interface (stubbed for demo)
//
// This header defines the API surface designed for direct compatibility with:
//
//   Veeam Backup & Replication — Immutability API
//     lock_backups()   → POST /api/v1/repositories/{id}/setImmutability
//                         body: {"immutabilityEnabled":true, "immutabilityPeriod":N}
//     unlock_backups() → DELETE /api/v1/repositories/{id}/immutabilityLock
//                         (requires operator + security-officer approval in production)
//     integrity_check()→ POST /api/v1/backupJobs/{id}/startHealthCheck
//     status()         → GET  /api/v1/repositories/{id}
//
//   IBM Storage (FlashSystem / Spectrum Scale WORM)
//     IMMUTABLE state  → IBM Object Storage immutable bucket (S3 Object Lock, Governance mode)
//     COMPLIANCE_LOCK  → IBM FlashSystem compliance-mode WORM; cannot be removed
//                         before retention period even by administrator.
//                         The stub transitions the state label only — it does NOT
//                         enforce a 30-day minimum retention period, as that
//                         constraint requires a live IBM Storage instance.
//                         Production swap: replace the stub body with IBM Storage
//                         REST calls to PUT /mgmt/v1/storage/volumes/{id}/wormlock
//
// DEMO NOTE:
//   The VeeamInterface class is the real, production-shaped API surface.
//   The implementation in veeam_interface.cpp uses StubBackupRepo — an in-memory
//   mock backup repository — as the demo target. To swap in a live Veeam or IBM
//   Storage instance, replace the stub body in veeam_interface.cpp with real HTTP
//   calls; the header and all callers remain unchanged.

#include <string>
#include <functional>
#include <cstdint>
#include <mutex>

namespace astartis {
namespace backup {

// ---------------------------------------------------------------------------
// Lock state — maps to Veeam immutability states and IBM Storage WORM modes
// ---------------------------------------------------------------------------

enum class BackupLockState {
    UNLOCKED,        ///< Backups writable; no immutability lock in force.
    IMMUTABLE,       ///< Veeam Governance-mode immutability active; admin can override.
                     ///< IBM Storage: S3 Object Lock governance mode.
    COMPLIANCE_LOCK  ///< IBM FlashSystem compliance-mode WORM; cannot be overridden
                     ///< before retention period. Veeam equivalent: Compliance mode
                     ///< (requires security officer co-authorisation to lift).
                     ///< In the stub this is a state label only — set manually via
                     ///< set_compliance_lock(); not triggered by automatic WORM events.
};

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

/**
 * @brief Result returned by lock_backups() and unlock_backups().
 *
 * Maps to the Veeam REST response body for immutability endpoints.
 */
struct BackupLockResult {
    bool             success;         ///< true if state transition occurred.
    BackupLockState  lock_state;      ///< State after this call.
    std::string      repo_id;         ///< Stub repo ID (e.g. "astartis-demo-repo-01").
    int              backup_count;    ///< Number of backup points currently protected.
    int64_t          locked_at_ms;    ///< Unix-ms timestamp of lock; 0 if unlocked.
    std::string      locked_by_reason;///< Reason string from trigger_lockdown().
    std::string      error_message;   ///< Non-empty only on failure.
    std::string      audit_entry_id;  ///< Audit chain entry ID written by this call.
};

/**
 * @brief Result returned by integrity_check().
 *
 * Maps to Veeam health-check job completion event and IBM Storage
 * data integrity verification result.
 */
struct IntegrityCheckResult {
    bool     passed;          ///< true if all checked items are intact (stub: always true).
    int      checked_count;   ///< Number of backup points / objects checked.
    int      violations_found;///< Should be 0 in stub.
    int64_t  checked_at_ms;   ///< Unix-ms timestamp of check.
    std::string audit_entry_id;
};

/**
 * @brief Full backup repository status snapshot.
 *
 * Returned by status() and serialised into the bridge tick snapshot.
 */
struct BackupRepoStatus {
    std::string      repo_id;
    BackupLockState  lock_state;
    int              backup_count;
    int64_t          locked_at_ms;        ///< 0 if currently unlocked.
    std::string      locked_by_reason;    ///< Empty if currently unlocked.
    int              integrity_check_count;
    int64_t          last_integrity_check_ms; ///< 0 if never checked.
};

// ---------------------------------------------------------------------------
// VeeamInterface
// ---------------------------------------------------------------------------

/**
 * @brief Veeam / IBM Storage immutability interface.
 *
 * Production API surface shaped to match:
 *   - Veeam Backup & Replication REST API v1 (immutability endpoints).
 *   - IBM Storage WORM compliance-lock model.
 *
 * For the demo, the implementation target is StubBackupRepo — an in-memory
 * mock. To target a live Veeam or IBM Storage instance, replace the stub
 * bodies in veeam_interface.cpp; this header and all callers are unchanged.
 *
 * Thread-safe. All state transitions write to the audit chain.
 */
class VeeamInterface {
public:
    /// Stub repo identifier, used as the repo_id in all results.
    static constexpr const char* STUB_REPO_ID = "astartis-demo-repo-01";

    /// Seed value for backup_count in the stub — realistic-looking demo number.
    static constexpr int STUB_BACKUP_COUNT = 47;

    /**
     * @param audit_adder  Callable (event_type, payload) -> entry_id.
     *                     Same signature used by all other Astartis modules.
     */
    explicit VeeamInterface(
        std::function<std::string(const std::string&, const std::string&)> audit_adder
    );

    ~VeeamInterface() = default;
    VeeamInterface(const VeeamInterface&)            = delete;
    VeeamInterface& operator=(const VeeamInterface&) = delete;

    /**
     * @brief Lock all backup points in the repository.
     *
     * Transitions: UNLOCKED → IMMUTABLE.
     * If already locked (IMMUTABLE or COMPLIANCE_LOCK), returns success=false.
     *
     * Veeam API mapping:
     *   POST /api/v1/repositories/{id}/setImmutability
     *   { "immutabilityEnabled": true }
     *
     * IBM Storage mapping:
     *   PUT /mgmt/v1/storage/volumes/{id}/wormlock { "mode": "governance" }
     *
     * @param reason  Reason string from WormLock::trigger_lockdown() — forwarded
     *                verbatim into the audit entry and BackupLockResult.
     */
    BackupLockResult lock_backups(const std::string& reason);

    /**
     * @brief Unlock the repository from immutability.
     *
     * Transitions: IMMUTABLE → UNLOCKED.
     * COMPLIANCE_LOCK cannot be lifted via this call (returns success=false).
     * If already UNLOCKED, returns success=false.
     *
     * Veeam API mapping:
     *   DELETE /api/v1/repositories/{id}/immutabilityLock
     *
     * IBM Storage mapping:
     *   DELETE /mgmt/v1/storage/volumes/{id}/wormlock  (governance mode only)
     *
     * @param authority  Authority string from WormLock::unlock() — e.g. approver name.
     */
    BackupLockResult unlock_backups(const std::string& authority);

    /**
     * @brief Run an integrity check over all backup points.
     *
     * Stub: always passes. Increments internal counter. Writes audit entry.
     *
     * Veeam API mapping:
     *   POST /api/v1/backupJobs/{id}/startHealthCheck
     *
     * IBM Storage mapping:
     *   POST /mgmt/v1/storage/volumes/{id}/integrityCheck
     */
    IntegrityCheckResult integrity_check();

    /**
     * @brief Get the current status snapshot of the backup repository.
     *
     * Veeam API mapping:
     *   GET /api/v1/repositories/{id}
     *
     * IBM Storage mapping:
     *   GET /mgmt/v1/storage/volumes/{id}
     */
    BackupRepoStatus status() const;

    /**
     * @brief Helper: convert BackupLockState to a display string.
     */
    static std::string lock_state_str(BackupLockState s);

private:
    // Stub repository state — all in-memory.
    struct StubBackupRepo {
        BackupLockState  lock_state          = BackupLockState::UNLOCKED;
        int              backup_count        = STUB_BACKUP_COUNT;
        int64_t          locked_at_ms        = 0;
        std::string      locked_by_reason;
        int              integrity_check_count       = 0;
        int64_t          last_integrity_check_ms     = 0;
    };

    int64_t now_ms() const;

    std::function<std::string(const std::string&, const std::string&)> audit_adder_;
    StubBackupRepo repo_;
    mutable std::mutex mutex_;
};

} // namespace backup
} // namespace astartis

#endif // ASTARTIS_VEEAM_INTERFACE_H

// Made with Bob
