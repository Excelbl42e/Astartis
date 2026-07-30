// Step 16 ST-3 -- Quarantine implementation
//
// See quarantine.h for API documentation.

// Winsock2 before windows.h (included transitively by some headers)
#include <winsock2.h>
#include <windows.h>

#pragma warning(push)
#pragma warning(disable: 4706 4127 4244)
// nlohmann/json for sidecar serialisation — path relative to bridge include
// path; the CMake include_directories covers core/ root so we reach it via
// the bridge include or use a relative path.
// We use a minimal hand-rolled JSON writer here to avoid a heavy header
// dependency in a leaf module.  The sidecar is written by us and read by us,
// so we can define the exact format.
#pragma warning(pop)

#include "quarantine/quarantine.h"

#include <openssl/sha.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <stdexcept>
#include <random>
#include <cstring>

namespace fs = std::filesystem;

namespace astartis {
namespace quarantine {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static int64_t now_ms()
{
    using namespace std::chrono;
    return duration_cast<milliseconds>(
               system_clock::now().time_since_epoch()).count();
}

std::string Quarantine::sha256_hex(const std::string& data)
{
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()),
           data.size(), digest);
    std::ostringstream oss;
    for (unsigned char b : digest)
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(b);
    return oss.str();
}

std::string Quarantine::generate_entry_id()
{
    // 16 random hex bytes — simple, collision-free for our scale
    static std::mt19937_64 rng{std::random_device{}()};
    uint64_t a = rng(), b = rng();
    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(16) << a
        << std::setw(16) << b;
    return "qtn_" + oss.str();
}

// Minimal JSON serialiser for the sidecar — only what we need.
static std::string make_meta_json(const QuarantineEntry& e)
{
    // Escape backslashes and double-quotes in path strings
    auto escape = [](const std::string& s) {
        std::string out;
        out.reserve(s.size() + 8);
        for (char c : s) {
            if (c == '\\') out += "\\\\";
            else if (c == '"') out += "\\\"";
            else out += c;
        }
        return out;
    };
    std::ostringstream j;
    j << "{\n"
      << "  \"entry_id\": \""          << escape(e.entry_id)        << "\",\n"
      << "  \"original_path\": \""     << escape(e.original_path)   << "\",\n"
      << "  \"quarantine_path\": \""   << escape(e.quarantine_path) << "\",\n"
      << "  \"virus_name\": \""        << escape(e.virus_name)      << "\",\n"
      << "  \"sha256_hash\": \""       << e.sha256_hash             << "\",\n"
      << "  \"quarantined_at_ms\": "   << e.quarantined_at_ms       << "\n"
      << "}\n";
    return j.str();
}

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

Quarantine::Quarantine(
    const std::string& quarantine_dir,
    std::function<std::string(const std::string&, const std::string&)> audit_adder
)
    : quarantine_dir_(quarantine_dir)
    , audit_adder_(std::move(audit_adder))
{
    fs::create_directories(fs::path(quarantine_dir_));
}

// ---------------------------------------------------------------------------
// quarantine_file
// ---------------------------------------------------------------------------

QuarantineEntry Quarantine::quarantine_file(const std::string& src_path,
                                             const std::string& virus_name)
{
    QuarantineEntry entry;

    // --- 0. Size gate — refuse to read files > 500 MB into memory (Bug 3 fix) --
    static constexpr uintmax_t MAX_HASH_BYTES = 500ULL * 1024 * 1024;
    std::error_code size_ec;
    uintmax_t file_size = fs::file_size(src_path, size_ec);
    if (size_ec) {
        // file_size() failed — file not found or not readable
        return entry;
    }

    // --- 1. Read file content (only for hashable-size files) -----------------
    std::string content;
    bool hashed = false;
    if (file_size <= MAX_HASH_BYTES) {
        std::ifstream ifs(src_path, std::ios::binary);
        if (!ifs) return entry;
        content.assign((std::istreambuf_iterator<char>(ifs)),
                        std::istreambuf_iterator<char>());
        hashed = true;
    }

    // --- 2. Populate entry fields ---------------------------------------------
    entry.entry_id          = generate_entry_id();
    entry.original_path     = fs::absolute(fs::path(src_path)).string();
    entry.virus_name        = virus_name;
    entry.sha256_hash       = hashed ? sha256_hex(content) : "(file too large to hash)";
    entry.quarantined_at_ms = now_ms();
    entry.quarantine_path   =
        (fs::path(quarantine_dir_) / (entry.entry_id + ".bin")).string();

    // --- 3. Move file to quarantine directory ---------------------------------
    std::error_code ec;
    fs::rename(src_path, entry.quarantine_path, ec);
    if (ec) {
        // Cross-volume: copy then delete original
        fs::copy_file(src_path, entry.quarantine_path,
                      fs::copy_options::overwrite_existing, ec);
        if (ec) return QuarantineEntry{}; // copy failed
        fs::remove(src_path, ec);        // best-effort delete original
    }

    // --- 4. Write .meta sidecar -----------------------------------------------
    std::string meta_path =
        (fs::path(quarantine_dir_) / (entry.entry_id + ".meta")).string();
    {
        std::ofstream mf(meta_path);
        if (mf) mf << make_meta_json(entry);
    }

    // --- 5. Audit entry -------------------------------------------------------
    std::ostringstream payload;
    payload << "original_path=" << entry.original_path
            << " sha256=" << entry.sha256_hash
            << " virus=" << entry.virus_name;
    audit_adder_("quarantine", payload.str());

    // --- 6. In-memory record --------------------------------------------------
    {
        std::lock_guard<std::mutex> lk(mutex_);
        entries_.push_back(entry);
    }

    return entry;
}

// ---------------------------------------------------------------------------
// restore
// ---------------------------------------------------------------------------

bool Quarantine::restore(const std::string& entry_id)
{
    std::lock_guard<std::mutex> lk(mutex_);

    auto it = std::find_if(entries_.begin(), entries_.end(),
        [&](const QuarantineEntry& e){ return e.entry_id == entry_id; });
    if (it == entries_.end()) return false;

    QuarantineEntry e = *it;

    // Move .bin back to original path
    std::error_code ec;
    fs::path orig(e.original_path);
    fs::create_directories(orig.parent_path(), ec);
    fs::rename(e.quarantine_path, orig, ec);
    if (ec) {
        // Cross-volume fallback
        fs::copy_file(e.quarantine_path, orig,
                      fs::copy_options::overwrite_existing, ec);
        if (ec) return false;
        fs::remove(e.quarantine_path, ec);
    }

    // Remove sidecar
    std::string meta_path =
        (fs::path(quarantine_dir_) / (e.entry_id + ".meta")).string();
    fs::remove(meta_path, ec); // best-effort

    // Audit
    audit_adder_("quarantine_restore",
                 "entry_id=" + e.entry_id +
                 " original_path=" + e.original_path);

    // Remove from in-memory list
    entries_.erase(it);
    return true;
}

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

std::vector<QuarantineEntry> Quarantine::list() const
{
    std::lock_guard<std::mutex> lk(mutex_);
    return entries_;
}

} // namespace quarantine
} // namespace astartis

// Made with Bob
