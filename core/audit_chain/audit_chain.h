#ifndef ASTARTIS_AUDIT_CHAIN_H
#define ASTARTIS_AUDIT_CHAIN_H

#include <string>
#include <vector>
#include <cstdint>
#include <mutex>

namespace astartis {
namespace audit {

/**
 * @brief Single entry in the audit chain
 * 
 * Each entry contains its own hash and links to the previous entry's hash,
 * forming a tamper-evident Merkle chain.
 */
struct AuditEntry {
    std::string entry_id;           // Unique identifier for this entry
    int64_t timestamp;              // Unix timestamp in milliseconds
    std::string event_type;         // Type of event (e.g., "login", "access_denied")
    std::string payload;            // Event data/details
    std::string previous_hash;      // SHA-256 hash of previous entry
    std::string current_hash;       // SHA-256 hash of this entry
};

/**
 * @brief Result of chain verification
 */
struct VerificationResult {
    bool is_valid;                  // Overall chain validity
    std::string error_message;      // Details if invalid
    int tampered_entry_index;       // Index of tampered entry (-1 if none)
    std::string expected_hash;      // What the hash should be
    std::string actual_hash;        // What the hash actually is
};

/**
 * @brief Tamper-evident audit chain using SHA-256 Merkle hashing
 * 
 * Each entry's hash is calculated as:
 * SHA256(entry_id + timestamp + event_type + payload + previous_hash)
 * 
 * This creates a chain where any modification to historical data
 * breaks the hash chain and is immediately detectable.
 */
class AuditChain {
public:
    AuditChain();
    ~AuditChain() = default;

    /**
     * @brief Add a new entry to the audit chain
     * 
     * @param event_type Type of event being logged
     * @param payload Event data/details
     * @return entry_id of the newly added entry
     */
    std::string add_entry(const std::string& event_type, const std::string& payload);

    /**
     * @brief Verify the integrity of the entire chain
     * 
     * Walks through all entries and verifies:
     * 1. Each entry's current_hash matches recalculated hash
     * 2. Each entry's previous_hash matches previous entry's current_hash
     * 
     * @return VerificationResult with details
     */
    VerificationResult verify_chain() const;

    /**
     * @brief Get a specific entry by ID
     * 
     * @param entry_id The entry identifier
     * @return Pointer to entry if found, nullptr otherwise
     */
    const AuditEntry* get_entry(const std::string& entry_id) const;

    /**
     * @brief Get all entries in the chain
     * 
     * @return Vector of all entries
     */
    std::vector<AuditEntry> get_all_entries() const;

    /**
     * @brief Get the number of entries in the chain
     * 
     * @return Chain length
     */
    size_t get_chain_length() const;

    /**
     * @brief Get the hash of the last entry (chain head)
     *
     * @return Hash of most recent entry, or genesis hash if empty
     */
    std::string get_chain_head_hash() const;

    /**
     * @brief Directly corrupt a stored entry — FOR TESTING ONLY.
     *
     * Simulates an attacker editing the underlying storage directly,
     * bypassing the append-only API. Sets the payload of entry at
     * `index` to `new_payload` WITHOUT recalculating the stored hash,
     * so verify_chain() will detect the mismatch.
     *
     * @param index       Zero-based index of the entry to corrupt.
     * @param new_payload The forged payload value to inject.
     * @return false if index is out of range.
     */
    bool tamper_entry_for_testing(size_t index, const std::string& new_payload);

private:
    /**
     * @brief Calculate SHA-256 hash for an entry
     * 
     * @param entry The entry to hash
     * @return Hex-encoded SHA-256 hash
     */
    std::string calculate_entry_hash(const AuditEntry& entry) const;

    /**
     * @brief Generate a unique entry ID
     * 
     * @return Unique identifier string
     */
    std::string generate_entry_id() const;

    /**
     * @brief Get current timestamp in milliseconds
     * 
     * @return Unix timestamp in milliseconds
     */
    int64_t get_current_timestamp() const;

    /**
     * @brief Genesis hash (all zeros) for the first entry
     */
    static constexpr const char* GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

    std::vector<AuditEntry> chain_;
    mutable std::mutex mutex_;
};

} // namespace audit
} // namespace astartis

#endif // ASTARTIS_AUDIT_CHAIN_H

// Made with Bob
