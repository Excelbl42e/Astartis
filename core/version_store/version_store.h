#ifndef ASTARTIS_VERSION_STORE_H
#define ASTARTIS_VERSION_STORE_H

#include <string>
#include <vector>
#include <map>
#include <cstdint>
#include <mutex>
#include <functional>

namespace astartis {
namespace versioning {

/**
 * @brief A single immutable snapshot of a record at a point in time.
 *
 * Once written, a RecordVersion is never modified. New writes produce
 * new versions with monotonically increasing version_number.
 */
struct RecordVersion {
    std::string  record_id;       // The record this version belongs to
    uint64_t     version_number;  // 1-based, monotonically increasing per record
    int64_t      timestamp;       // Unix timestamp in milliseconds
    std::string  data;            // The record payload at this version
    std::string  author;          // Who wrote this version
    std::string  version_hash;    // SHA-256(record_id + version_number + timestamp + data + author)
};

/**
 * @brief Result type for write/read operations.
 */
struct VersionResult {
    bool        ok;             // True on success
    std::string error;          // Non-empty on failure
    uint64_t    version_number; // Set on successful write; 0 otherwise
};

/**
 * @brief Append-only versioned store for protected records.
 *
 * Every call to write() appends a new RecordVersion — old versions are
 * never touched. This is the rollback layer: a known-good prior state
 * always exists, independent of breach detection.
 *
 * Audit chain integration: each write also appends a "version_write"
 * entry to the AuditChain supplied at construction, so the tamper-evident
 * chain proves which version was written when.
 *
 * WORM hook: an optional lock_check callback can be wired in. When it
 * returns true, write() is blocked immediately and returns an error.
 * Step 3 wires this up; until then the default no-op always returns false.
 */
class VersionStore {
public:
    /**
     * @param audit_adder  Callable with signature
     *   (event_type, payload) -> entry_id
     *   forwarded directly to AuditChain::add_entry.
     *   Pass a lambda wrapping your AuditChain instance.
     *
     * @param lock_check  Returns true when the WORM lockdown is active.
     *   Defaults to a no-op that always returns false (unlocked).
     */
    explicit VersionStore(
        std::function<std::string(const std::string&, const std::string&)> audit_adder,
        std::function<bool()> lock_check = []() { return false; }
    );

    ~VersionStore() = default;

    /**
     * @brief Write a new version of a record.
     *
     * Blocked (returns error) if lock_check() returns true.
     * Always appends — the previous version is never modified.
     * Appends a "version_write" entry to the audit chain.
     *
     * @param record_id  Stable key for the record (any non-empty string).
     * @param data       The new payload value.
     * @param author     Identity of the writer (logged in audit chain).
     * @return VersionResult with ok=true and version_number set on success.
     */
    VersionResult write(const std::string& record_id,
                        const std::string& data,
                        const std::string& author);

    /**
     * @brief Read the latest version of a record.
     *
     * @param record_id  The record to read.
     * @param out        Populated on success.
     * @return VersionResult with ok=true on success.
     */
    VersionResult read_current(const std::string& record_id,
                               RecordVersion&     out) const;

    /**
     * @brief Read a specific historical version of a record.
     *
     * @param record_id      The record to read.
     * @param version_number 1-based version index.
     * @param out            Populated on success.
     * @return VersionResult with ok=true on success.
     */
    VersionResult read_version(const std::string& record_id,
                               uint64_t           version_number,
                               RecordVersion&     out) const;

    /**
     * @brief Get the full version history for a record, oldest first.
     *
     * @param record_id  The record to retrieve history for.
     * @return All versions in order; empty vector if record not found.
     */
    std::vector<RecordVersion> get_history(const std::string& record_id) const;

    /**
     * @brief Total number of distinct records known to the store.
     */
    size_t record_count() const;

    /**
     * @brief Total number of versions across all records.
     */
    size_t total_version_count() const;

private:
    std::string calculate_version_hash(const RecordVersion& v) const;
    int64_t     get_current_timestamp() const;

    std::function<std::string(const std::string&, const std::string&)> audit_adder_;
    std::function<bool()>                                               lock_check_;

    // record_id -> ordered list of versions (index 0 = version 1)
    std::map<std::string, std::vector<RecordVersion>> store_;
    mutable std::mutex mutex_;
};

} // namespace versioning
} // namespace astartis

#endif // ASTARTIS_VERSION_STORE_H

// Made with Bob
