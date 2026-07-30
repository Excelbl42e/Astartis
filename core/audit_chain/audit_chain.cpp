#include "audit_chain.h"
#include <openssl/sha.h>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <random>

namespace astartis {
namespace audit {

AuditChain::AuditChain() {
    // Chain starts empty - first entry will use GENESIS_HASH
}

std::string AuditChain::add_entry(const std::string& event_type, const std::string& payload) {
    std::lock_guard<std::mutex> lock(mutex_);

    AuditEntry entry;
    entry.entry_id = generate_entry_id();
    entry.timestamp = get_current_timestamp();
    entry.event_type = event_type;
    entry.payload = payload;

    // Link to previous entry or genesis
    if (chain_.empty()) {
        entry.previous_hash = GENESIS_HASH;
    } else {
        entry.previous_hash = chain_.back().current_hash;
    }

    // Calculate hash for this entry
    entry.current_hash = calculate_entry_hash(entry);

    // Add to chain
    chain_.push_back(entry);

    return entry.entry_id;
}

VerificationResult AuditChain::verify_chain() const {
    std::lock_guard<std::mutex> lock(mutex_);

    VerificationResult result;
    result.is_valid = true;
    result.tampered_entry_index = -1;

    if (chain_.empty()) {
        result.error_message = "Chain is empty";
        return result;
    }

    // Verify first entry links to genesis
    if (chain_[0].previous_hash != GENESIS_HASH) {
        result.is_valid = false;
        result.error_message = "First entry does not link to genesis hash";
        result.tampered_entry_index = 0;
        result.expected_hash = GENESIS_HASH;
        result.actual_hash = chain_[0].previous_hash;
        return result;
    }

    // Verify each entry
    for (size_t i = 0; i < chain_.size(); i++) {
        const AuditEntry& entry = chain_[i];

        // Recalculate hash
        std::string calculated_hash = calculate_entry_hash(entry);

        // Check if stored hash matches calculated hash
        if (entry.current_hash != calculated_hash) {
            result.is_valid = false;
            result.error_message = "Entry hash mismatch - entry has been tampered with";
            result.tampered_entry_index = static_cast<int>(i);
            result.expected_hash = calculated_hash;
            result.actual_hash = entry.current_hash;
            return result;
        }

        // Check if previous_hash links correctly (except for first entry)
        if (i > 0) {
            const AuditEntry& prev_entry = chain_[i - 1];
            if (entry.previous_hash != prev_entry.current_hash) {
                result.is_valid = false;
                result.error_message = "Chain link broken - previous_hash does not match";
                result.tampered_entry_index = static_cast<int>(i);
                result.expected_hash = prev_entry.current_hash;
                result.actual_hash = entry.previous_hash;
                return result;
            }
        }
    }

    result.error_message = "Chain verification passed";
    return result;
}

const AuditEntry* AuditChain::get_entry(const std::string& entry_id) const {
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto& entry : chain_) {
        if (entry.entry_id == entry_id) {
            return &entry;
        }
    }

    return nullptr;
}

std::vector<AuditEntry> AuditChain::get_all_entries() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return chain_;
}

size_t AuditChain::get_chain_length() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return chain_.size();
}

std::string AuditChain::get_chain_head_hash() const {
    std::lock_guard<std::mutex> lock(mutex_);

    if (chain_.empty()) {
        return GENESIS_HASH;
    }

    return chain_.back().current_hash;
}

std::string AuditChain::calculate_entry_hash(const AuditEntry& entry) const {
    // Concatenate all fields
    std::ostringstream oss;
    oss << entry.entry_id
        << entry.timestamp
        << entry.event_type
        << entry.payload
        << entry.previous_hash;

    std::string data = oss.str();

    // Calculate SHA-256
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), hash);

    // Convert to hex string
    std::ostringstream hex_stream;
    hex_stream << std::hex << std::setfill('0');
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        hex_stream << std::setw(2) << static_cast<int>(hash[i]);
    }

    return hex_stream.str();
}

std::string AuditChain::generate_entry_id() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<uint64_t> dis;

    std::ostringstream oss;
    oss << "entry_" << std::hex << dis(gen);
    return oss.str();
}

bool AuditChain::tamper_entry_for_testing(size_t index, const std::string& new_payload) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index >= chain_.size()) {
        return false;
    }
    // Corrupt the payload WITHOUT updating the stored hash.
    // This is exactly what a direct database edit looks like —
    // the hash no longer matches the content.
    chain_[index].payload = new_payload;
    return true;
}

int64_t AuditChain::get_current_timestamp() const {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

} // namespace audit
} // namespace astartis

// Made with Bob
