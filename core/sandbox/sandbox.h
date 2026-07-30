#ifndef ASTARTIS_SANDBOX_H
#define ASTARTIS_SANDBOX_H

/*
 * Step 9 — Sandboxed Mirror Environment
 *
 * A self-contained synthetic file system surface that Astartis treats as the
 * "protected enterprise server" for all demo purposes.  Every destructive-
 * looking action (WORM lock, decoy redirect, poisoning) operates on entries
 * inside this sandbox and NEVER on real paths outside it.
 *
 * Key invariant (architecture §Step 9 constraint):
 *   Any operation targeting a path outside sandbox_root_ is rejected with an
 *   error — enforced in code, not assumed by convention.
 *
 * Design:
 *   - SandboxEntry  : metadata for one synthetic file inside the sandbox.
 *     Carries version_number, lock status, size, type, and content.
 *   - Sandbox       : manages the full set of entries.
 *     - populate()  : create a realistic synthetic directory hierarchy.
 *     - write()     : create/update an entry — blocked if entry is locked or
 *                     WORM is active.
 *     - lock_entry(): mark a single entry as immutable (write-blocked).
 *     - lock_all()  : WORM-style — lock every entry in the sandbox.
 *     - read()      : read current content (any path inside sandbox root).
 *     - get_tree()  : return all entries for the dashboard file-manager view.
 *     - is_inside() : the path guard — static, called before every operation.
 *
 * Audit chain integration: every write, lock, and unlock writes an entry.
 * WORM hook: an optional lock_check callback blocks writes when active.
 */

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <mutex>
#include <cstdint>

namespace astartis {
namespace sandbox {

// ---------------------------------------------------------------------------
// Entry descriptor
// ---------------------------------------------------------------------------

enum class EntryType { FILE, DIRECTORY };

/**
 * @brief A single synthetic entry inside the sandbox.
 */
struct SandboxEntry {
    std::string rel_path;       ///< Path relative to sandbox root (always forward slashes)
    EntryType   type;
    std::string content;        ///< Synthetic content (populated by populate() or write())
    uint64_t    version;        ///< Monotonically increasing; starts at 1
    bool        locked;         ///< True → writes blocked for this specific entry
    int64_t     size_bytes;     ///< Reported synthetic file size
    int64_t     last_modified;  ///< Unix timestamp ms of last write
};

/**
 * @brief Result of a sandbox operation.
 */
struct SandboxResult {
    bool        ok;
    std::string error;   // Non-empty on failure
};

// ---------------------------------------------------------------------------
// Sandbox
// ---------------------------------------------------------------------------

/**
 * @brief The sandboxed mirror environment.
 *
 * Constructed with an absolute path to the sandbox root directory on disk.
 * The root directory is created on disk when populate() is called.
 * All in-memory state mirrors the on-disk structure.
 *
 * Thread-safe.
 */
class Sandbox {
public:
    /**
     * @param root_path    Absolute path to the sandbox root on disk.
     *                     Must be inside a temp/demo area — never the real project tree.
     * @param audit_adder  Callable (event_type, payload) -> entry_id.
     * @param lock_check   Returns true when WORM lockdown is active globally.
     *                     Defaults to no-op (always false).
     */
    explicit Sandbox(
        const std::string& root_path,
        std::function<std::string(const std::string&, const std::string&)> audit_adder,
        std::function<bool()> lock_check = []() { return false; }
    );

    ~Sandbox() = default;

    // Non-copyable.
    Sandbox(const Sandbox&)            = delete;
    Sandbox& operator=(const Sandbox&) = delete;

    // -----------------------------------------------------------------------
    // Path guard (static — safe to call before constructing a Sandbox)
    // -----------------------------------------------------------------------

    /**
     * @brief Return true if and only if abs_path is inside root_path.
     *
     * This is the enforcement point for the architecture constraint:
     *   "No lock, decoy, poisoning, or destructive-looking operation may ever
     *    target a path outside the Step 9 sandbox root."
     *
     * Uses lexicographic prefix matching after normalising separators.
     * A path equal to root_path itself is considered inside.
     *
     * @param abs_path   Absolute path to check.
     * @param root_path  The sandbox root.
     */
    static bool is_inside(const std::string& abs_path, const std::string& root_path);

    /**
     * @brief Return true if the normalised path contains any ".." component.
     *
     * Called by is_inside() and to_rel() before the prefix check.
     * Prevents directory-traversal attacks of the form
     *   <sandbox_root>/../../Windows/System32/evil
     * which pass a plain prefix check but resolve outside the sandbox.
     * Deterministic — no filesystem access, no symlink resolution.
     */
    static bool has_dotdot(const std::string& normalised_path);

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    /**
     * @brief Populate the sandbox with a realistic synthetic file hierarchy.
     *
     * Creates the root directory on disk and writes every synthetic file.
     * The hierarchy mimics a small enterprise server:
     *
     *   /etc/         — config files (nginx.conf, sshd_config, hosts, cron.d/)
     *   /var/log/     — log files (auth.log, syslog, app.log, access.log)
     *   /home/admin/  — user files (documents, keys, scripts)
     *   /opt/app/     — application (binary stubs, config.json, data/)
     *   /backup/      — backup archives (db-2024-*.tar.gz stubs)
     *
     * Existing entries are not re-created (idempotent).
     * Writes a "sandbox_populated" audit entry.
     *
     * @return Number of new entries created.
     */
    size_t populate();

    // -----------------------------------------------------------------------
    // Write / read
    // -----------------------------------------------------------------------

    /**
     * @brief Write (create or update) a synthetic file inside the sandbox.
     *
     * Blocked if:
     *   - abs_path is outside the sandbox root (path guard)
     *   - The global WORM lockdown is active (lock_check returns true)
     *   - The specific entry is individually locked
     *
     * On success: increments version, updates last_modified, writes audit entry.
     *
     * @param abs_path   Absolute path of the file (must be inside root).
     * @param content    New synthetic content.
     * @param author     Identity string (logged).
     */
    SandboxResult write(const std::string& abs_path,
                        const std::string& content,
                        const std::string& author = "system");

    /**
     * @brief Read the current content of a sandbox file.
     *
     * @param abs_path  Absolute path of the file (must be inside root).
     * @param out       Populated with the SandboxEntry on success.
     */
    SandboxResult read(const std::string& abs_path, SandboxEntry& out) const;

    // -----------------------------------------------------------------------
    // Lock operations
    // -----------------------------------------------------------------------

    /**
     * @brief Lock a single entry — subsequent writes to it are blocked.
     *
     * Writes a "sandbox_entry_locked" audit entry.
     * No-op if already locked (returns ok=true).
     *
     * @param abs_path  Absolute path of the entry.
     * @param reason    Why it is being locked (logged).
     */
    SandboxResult lock_entry(const std::string& abs_path, const std::string& reason = "");

    /**
     * @brief Lock ALL entries in the sandbox (WORM-style batch lock).
     *
     * Writes a single "sandbox_worm_lock_all" audit entry.
     * Safe to call when some entries are already locked.
     *
     * @param reason  Why the full lock is being triggered (logged).
     * @return Number of entries newly locked (previously unlocked ones).
     */
    size_t lock_all(const std::string& reason = "");

    /**
     * @brief Unlock a previously locked entry.
     *
     * Writes a "sandbox_entry_unlocked" audit entry.
     *
     * @param abs_path  Absolute path of the entry.
     * @param reason    Why it is being unlocked (logged).
     */
    SandboxResult unlock_entry(const std::string& abs_path, const std::string& reason = "");

    // -----------------------------------------------------------------------
    // Query / dashboard view
    // -----------------------------------------------------------------------

    /**
     * @brief Return all entries sorted by rel_path (for the dashboard file-manager).
     */
    std::vector<SandboxEntry> get_tree() const;

    /**
     * @brief Total number of entries in the sandbox.
     */
    size_t entry_count() const;

    /**
     * @brief The absolute path to the sandbox root.
     */
    const std::string& root_path() const { return root_path_; }

private:
    // Normalise a path: replace backslashes with forward slashes,
    // resolve "." and collapse duplicate slashes.
    static std::string normalise(const std::string& p);

    // Convert an absolute path to the rel_path key used in entries_.
    // Returns empty string if the path is not inside root_.
    std::string to_rel(const std::string& abs_path) const;

    // Write a file to disk at abs_path with the given content.
    // Creates parent directories as needed.
    static void write_to_disk(const std::string& abs_path, const std::string& content);

    int64_t now_ms() const;

    std::string root_path_;   // normalised absolute sandbox root
    std::function<std::string(const std::string&, const std::string&)> audit_adder_;
    std::function<bool()> lock_check_;

    std::map<std::string, SandboxEntry> entries_;  // key = rel_path
    mutable std::mutex mutex_;
};

} // namespace sandbox
} // namespace astartis

#endif // ASTARTIS_SANDBOX_H

// Made with Bob
