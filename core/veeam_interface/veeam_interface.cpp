// Step 19 -- VeeamInterface stub implementation
// See veeam_interface.h for full API documentation and production-mapping notes.

#include "veeam_interface/veeam_interface.h"

#include <chrono>
#include <sstream>

namespace astartis {
namespace backup {

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

VeeamInterface::VeeamInterface(
    std::function<std::string(const std::string&, const std::string&)> audit_adder)
    : audit_adder_(std::move(audit_adder))
{}

// ---------------------------------------------------------------------------
// lock_backups
// ---------------------------------------------------------------------------

BackupLockResult VeeamInterface::lock_backups(const std::string& reason)
{
    std::lock_guard<std::mutex> lk(mutex_);

    BackupLockResult result;
    result.repo_id = STUB_REPO_ID;

    if (repo_.lock_state != BackupLockState::UNLOCKED) {
        // Already locked — idempotent guard
        result.success          = false;
        result.lock_state       = repo_.lock_state;
        result.backup_count     = repo_.backup_count;
        result.locked_at_ms     = repo_.locked_at_ms;
        result.locked_by_reason = repo_.locked_by_reason;
        result.error_message    = "already_locked";
        return result;
    }

    repo_.lock_state       = BackupLockState::IMMUTABLE;
    repo_.locked_at_ms     = now_ms();
    repo_.locked_by_reason = reason;

    std::ostringstream payload;
    payload << "repo_id=\"" << STUB_REPO_ID << "\""
            << " backup_count=" << repo_.backup_count
            << " reason=\"" << reason << "\""
            << " locked_at_ms=" << repo_.locked_at_ms;
    result.audit_entry_id = audit_adder_("veeam_backup_locked", payload.str());

    result.success          = true;
    result.lock_state       = repo_.lock_state;
    result.backup_count     = repo_.backup_count;
    result.locked_at_ms     = repo_.locked_at_ms;
    result.locked_by_reason = repo_.locked_by_reason;
    return result;
}

// ---------------------------------------------------------------------------
// unlock_backups
// ---------------------------------------------------------------------------

BackupLockResult VeeamInterface::unlock_backups(const std::string& authority)
{
    std::lock_guard<std::mutex> lk(mutex_);

    BackupLockResult result;
    result.repo_id = STUB_REPO_ID;

    if (repo_.lock_state == BackupLockState::UNLOCKED) {
        result.success      = false;
        result.lock_state   = BackupLockState::UNLOCKED;
        result.backup_count = repo_.backup_count;
        result.error_message = "already_unlocked";
        return result;
    }

    if (repo_.lock_state == BackupLockState::COMPLIANCE_LOCK) {
        // COMPLIANCE_LOCK cannot be lifted programmatically — requires
        // retention-period expiry on a real IBM FlashSystem instance.
        result.success      = false;
        result.lock_state   = BackupLockState::COMPLIANCE_LOCK;
        result.backup_count = repo_.backup_count;
        result.error_message = "compliance_lock_requires_retention_expiry";
        return result;
    }

    // IMMUTABLE → UNLOCKED
    repo_.lock_state       = BackupLockState::UNLOCKED;
    repo_.locked_at_ms     = 0;
    repo_.locked_by_reason.clear();

    std::ostringstream payload;
    payload << "repo_id=\"" << STUB_REPO_ID << "\""
            << " authority=\"" << authority << "\"";
    result.audit_entry_id = audit_adder_("veeam_backup_unlocked", payload.str());

    result.success      = true;
    result.lock_state   = BackupLockState::UNLOCKED;
    result.backup_count = repo_.backup_count;
    return result;
}

// ---------------------------------------------------------------------------
// integrity_check
// ---------------------------------------------------------------------------

IntegrityCheckResult VeeamInterface::integrity_check()
{
    std::lock_guard<std::mutex> lk(mutex_);

    ++repo_.integrity_check_count;
    repo_.last_integrity_check_ms = now_ms();

    std::ostringstream payload;
    payload << "repo_id=\"" << STUB_REPO_ID << "\""
            << " checked=" << repo_.backup_count
            << " violations=0"
            << " check_num=" << repo_.integrity_check_count;
    auto entry_id = audit_adder_("veeam_integrity_check", payload.str());

    IntegrityCheckResult r;
    r.passed          = true;
    r.checked_count   = repo_.backup_count;
    r.violations_found = 0;
    r.checked_at_ms   = repo_.last_integrity_check_ms;
    r.audit_entry_id  = entry_id;
    return r;
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

BackupRepoStatus VeeamInterface::status() const
{
    std::lock_guard<std::mutex> lk(mutex_);

    BackupRepoStatus s;
    s.repo_id                  = STUB_REPO_ID;
    s.lock_state               = repo_.lock_state;
    s.backup_count             = repo_.backup_count;
    s.locked_at_ms             = repo_.locked_at_ms;
    s.locked_by_reason         = repo_.locked_by_reason;
    s.integrity_check_count    = repo_.integrity_check_count;
    s.last_integrity_check_ms  = repo_.last_integrity_check_ms;
    return s;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

std::string VeeamInterface::lock_state_str(BackupLockState s)
{
    switch (s) {
        case BackupLockState::UNLOCKED:        return "UNLOCKED";
        case BackupLockState::IMMUTABLE:       return "IMMUTABLE";
        case BackupLockState::COMPLIANCE_LOCK: return "COMPLIANCE_LOCK";
        default:                               return "UNKNOWN";
    }
}

int64_t VeeamInterface::now_ms() const
{
    using namespace std::chrono;
    return duration_cast<milliseconds>(
        system_clock::now().time_since_epoch()).count();
}

} // namespace backup
} // namespace astartis

// Made with Bob
