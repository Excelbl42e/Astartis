#ifndef ASTARTIS_QUARANTINE_H
#define ASTARTIS_QUARANTINE_H

// Step 16 ST-3 -- Real ClamAV quarantine
//
// Moves an infected file to a dedicated quarantine directory, preserving
// original-path and timestamp metadata in a sidecar .meta file for
// restoration.  Never deletes — quarantine is reversible, deletion is not.
//
// Every quarantine and restore action writes to the shared audit chain.
//
// Quarantine directory default: C:\ProgramData\Astartis\Quarantine\
// (requires an elevated process to create on first use)
// For tests the caller may pass any writable temp path.

#include <string>
#include <vector>
#include <functional>
#include <mutex>
#include <cstdint>

namespace astartis {
namespace quarantine {

// ---------------------------------------------------------------------------
// QuarantineEntry — one quarantined file record
// ---------------------------------------------------------------------------

struct QuarantineEntry {
    std::string entry_id;           ///< UUID-style unique ID (used as filename stem)
    std::string original_path;      ///< Absolute path the file came from
    std::string quarantine_path;    ///< Absolute path of the .bin in quarantine dir
    std::string virus_name;         ///< Signature reported by clamd
    std::string sha256_hash;        ///< SHA-256 hex of the file content
    int64_t     quarantined_at_ms;  ///< Wall-clock ms when quarantine happened
};

// ---------------------------------------------------------------------------
// Quarantine
// ---------------------------------------------------------------------------

class Quarantine {
public:
    static constexpr const char* DEFAULT_DIR =
        "C:\\ProgramData\\Astartis\\Quarantine";

    /**
     * @param quarantine_dir  Directory to store quarantined files.
     *                        Created if it doesn't exist (requires elevation
     *                        when using DEFAULT_DIR).
     * @param audit_adder     Callable (event_type, payload) -> entry_id.
     */
    explicit Quarantine(
        const std::string& quarantine_dir,
        std::function<std::string(const std::string&, const std::string&)> audit_adder
    );

    ~Quarantine() = default;
    Quarantine(const Quarantine&)            = delete;
    Quarantine& operator=(const Quarantine&) = delete;

    /**
     * @brief Move src_path to the quarantine directory.
     *
     * Steps:
     *  1. Read file content, compute SHA-256.
     *  2. Generate a unique entry_id.
     *  3. Move file to <quarantine_dir>/<entry_id>.bin
     *     (copy+delete if cross-volume, rename if same volume).
     *  4. Write <quarantine_dir>/<entry_id>.meta JSON sidecar:
     *     {original_path, sha256_hash, virus_name, quarantined_at_ms}.
     *  5. Write "quarantine" audit entry with original_path, sha256_hash,
     *     virus_name.
     *  6. Add to in-memory list.
     *
     * @param src_path   Absolute path of the infected file.
     * @param virus_name Signature name from the scanner.
     * @return The QuarantineEntry created, or an entry with entry_id==""
     *         on failure (e.g. file not found).
     */
    QuarantineEntry quarantine_file(const std::string& src_path,
                                    const std::string& virus_name);

    /**
     * @brief Restore a quarantined file to its original location.
     *
     * Moves the .bin back to original_path, removes the .meta sidecar,
     * writes a "quarantine_restore" audit entry, and removes the entry
     * from the in-memory list.
     *
     * @return true on success, false if entry_id not found or file missing.
     */
    bool restore(const std::string& entry_id);

    /** All currently quarantined entries (oldest first). */
    std::vector<QuarantineEntry> list() const;

    /** Quarantine directory in use. */
    const std::string& quarantine_dir() const { return quarantine_dir_; }

private:
    static std::string sha256_hex(const std::string& data);
    static std::string generate_entry_id();

    std::string quarantine_dir_;
    std::function<std::string(const std::string&, const std::string&)> audit_adder_;
    std::vector<QuarantineEntry> entries_;
    mutable std::mutex mutex_;
};

} // namespace quarantine
} // namespace astartis

#endif // ASTARTIS_QUARANTINE_H

// Made with Bob
