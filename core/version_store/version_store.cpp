#include "version_store.h"
#include <openssl/sha.h>
#include <chrono>
#include <sstream>
#include <iomanip>

namespace astartis {
namespace versioning {

VersionStore::VersionStore(
    std::function<std::string(const std::string&, const std::string&)> audit_adder,
    std::function<bool()> lock_check)
    : audit_adder_(std::move(audit_adder))
    , lock_check_(std::move(lock_check))
{}

VersionResult VersionStore::write(const std::string& record_id,
                                  const std::string& data,
                                  const std::string& author)
{
    if (record_id.empty()) {
        return {false, "record_id must not be empty", 0};
    }

    // WORM hook — blocked if lockdown is active (wired up in Step 3)
    if (lock_check_()) {
        return {false, "write blocked: WORM lockdown is active", 0};
    }

    std::lock_guard<std::mutex> lock(mutex_);

    auto& history = store_[record_id];
    uint64_t next_version = static_cast<uint64_t>(history.size()) + 1;

    RecordVersion v;
    v.record_id      = record_id;
    v.version_number = next_version;
    v.timestamp      = get_current_timestamp();
    v.data           = data;
    v.author         = author;
    v.version_hash   = calculate_version_hash(v);

    history.push_back(v);

    // Write audit chain entry — proves this version was created at this time
    std::ostringstream audit_payload;
    audit_payload << "record_id=" << record_id
                  << " version="  << next_version
                  << " author="   << author
                  << " hash="     << v.version_hash;
    audit_adder_("version_write", audit_payload.str());

    return {true, "", next_version};
}

VersionResult VersionStore::read_current(const std::string& record_id,
                                         RecordVersion&     out) const
{
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = store_.find(record_id);
    if (it == store_.end() || it->second.empty()) {
        return {false, "record not found: " + record_id, 0};
    }

    out = it->second.back();
    return {true, "", out.version_number};
}

VersionResult VersionStore::read_version(const std::string& record_id,
                                         uint64_t           version_number,
                                         RecordVersion&     out) const
{
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = store_.find(record_id);
    if (it == store_.end() || it->second.empty()) {
        return {false, "record not found: " + record_id, 0};
    }

    const auto& history = it->second;
    if (version_number == 0 || version_number > history.size()) {
        return {false, "version_number out of range", 0};
    }

    // version_number is 1-based
    out = history[version_number - 1];
    return {true, "", out.version_number};
}

std::vector<RecordVersion> VersionStore::get_history(const std::string& record_id) const
{
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = store_.find(record_id);
    if (it == store_.end()) {
        return {};
    }
    return it->second;
}

size_t VersionStore::record_count() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return store_.size();
}

size_t VersionStore::total_version_count() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    size_t total = 0;
    for (const auto& kv : store_) {
        total += kv.second.size();
    }
    return total;
}

std::string VersionStore::calculate_version_hash(const RecordVersion& v) const
{
    std::ostringstream oss;
    oss << v.record_id
        << v.version_number
        << v.timestamp
        << v.data
        << v.author;

    std::string data = oss.str();

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()),
           data.length(), hash);

    std::ostringstream hex;
    hex << std::hex << std::setfill('0');
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        hex << std::setw(2) << static_cast<int>(hash[i]);
    }
    return hex.str();
}

int64_t VersionStore::get_current_timestamp() const
{
    auto now      = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

} // namespace versioning
} // namespace astartis

// Made with Bob
