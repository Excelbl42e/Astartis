#include "sandbox.h"

#include <chrono>
#include <sstream>
#include <algorithm>
#include <stdexcept>
#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;

namespace astartis {
namespace sandbox {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

Sandbox::Sandbox(
    const std::string& root_path,
    std::function<std::string(const std::string&, const std::string&)> audit_adder,
    std::function<bool()> lock_check)
    : root_path_(normalise(root_path))
    , audit_adder_(std::move(audit_adder))
    , lock_check_(std::move(lock_check))
{}

// ---------------------------------------------------------------------------
// Static helpers
// ---------------------------------------------------------------------------

std::string Sandbox::normalise(const std::string& p)
{
    std::string s = p;
    // Replace backslashes with forward slashes
    std::replace(s.begin(), s.end(), '\\', '/');
    // Remove trailing slash (unless it's just "/")
    while (s.size() > 1 && s.back() == '/') s.pop_back();
    return s;
}

bool Sandbox::has_dotdot(const std::string& normalised_path)
{
    // Reject any path that contains a ".." component.
    // Covers all four positions a ".." segment can appear in a
    // forward-slash-normalised path without any filesystem round-trip:
    //   whole path:  ".."
    //   start:       "../rest"
    //   end:         "rest/.."
    //   middle:      "rest/../../more"
    const std::string& s = normalised_path;
    if (s == "..")                                             return true;
    if (s.size() >= 3 && s.substr(0, 3) == "../")             return true;
    if (s.size() >= 3 && s.substr(s.size() - 3) == "/..")     return true;
    if (s.find("/../") != std::string::npos)                  return true;
    return false;
}

bool Sandbox::is_inside(const std::string& abs_path, const std::string& root_path)
{
    std::string norm_path = normalise(abs_path);
    std::string norm_root = normalise(root_path);

    // Hard-reject any path containing a ".." component.  A traversal like
    // <root>/../../Windows/System32/evil passes the prefix check below
    // because it still starts with the root string, but resolves outside
    // the sandbox.  Rejecting ".." outright is deterministic and requires
    // no filesystem call or symlink resolution.
    if (has_dotdot(norm_path)) return false;

    // Path must start with root followed by '/' or be exactly the root
    if (norm_path == norm_root) return true;
    if (norm_path.size() > norm_root.size() &&
        norm_path.substr(0, norm_root.size()) == norm_root &&
        norm_path[norm_root.size()] == '/')
    {
        return true;
    }
    return false;
}

std::string Sandbox::to_rel(const std::string& abs_path) const
{
    std::string norm = normalise(abs_path);
    // Same guard as is_inside: reject traversal before the prefix check
    if (has_dotdot(norm)) return "";
    if (!is_inside(norm, root_path_)) return "";
    if (norm == root_path_) return ".";
    // Strip root prefix + leading slash
    return norm.substr(root_path_.size() + 1);
}

int64_t Sandbox::now_ms() const
{
    auto tp = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(tp).count();
}

void Sandbox::write_to_disk(const std::string& abs_path, const std::string& content)
{
    fs::path p(abs_path);
    fs::create_directories(p.parent_path());
    std::ofstream f(p, std::ios::out | std::ios::trunc);
    if (!f) throw std::runtime_error("Cannot open for write: " + abs_path);
    f << content;
}

// ---------------------------------------------------------------------------
// populate — synthetic enterprise hierarchy
// ---------------------------------------------------------------------------

namespace {

struct SynthFile {
    const char* rel_path;
    const char* content;
};

// Realistic-looking but entirely synthetic content
static const SynthFile kSyntheticFiles[] = {
    // /etc/
    {"etc/nginx.conf",
     "worker_processes auto;\nevents { worker_connections 1024; }\n"
     "http {\n  server {\n    listen 443 ssl;\n    server_name corp.internal;\n  }\n}\n"},
    {"etc/sshd_config",
     "Port 22\nPermitRootLogin no\nPasswordAuthentication no\n"
     "PubkeyAuthentication yes\nAllowUsers admin deploy\n"},
    {"etc/hosts",
     "127.0.0.1 localhost\n192.168.10.5 db-primary.corp.internal\n"
     "192.168.10.6 db-replica.corp.internal\n192.168.10.20 app-server.corp.internal\n"},
    {"etc/cron.d/backup-job",
     "0 2 * * * root /opt/app/scripts/backup.sh >> /var/log/backup.log 2>&1\n"},
    {"etc/ssl/server.crt",
     "-----BEGIN CERTIFICATE-----\n[SYNTHETIC CERTIFICATE PLACEHOLDER]\n-----END CERTIFICATE-----\n"},

    // /var/log/
    {"var/log/auth.log",
     "Jun 26 01:12:03 sshd[1042]: Accepted publickey for admin from 192.168.1.100\n"
     "Jun 26 01:13:44 sshd[1052]: Failed password for invalid user guest from 10.0.0.55\n"
     "Jun 26 02:00:01 sudo: admin : TTY=pts/0 ; USER=root ; COMMAND=/bin/systemctl restart nginx\n"},
    {"var/log/syslog",
     "Jun 26 00:00:01 kernel: [0.000000] Linux version 5.15.0 (gcc 11.3.0)\n"
     "Jun 26 01:00:00 cron[812]: (root) CMD (/opt/app/scripts/health_check.sh)\n"
     "Jun 26 01:12:03 systemd[1]: Started OpenSSH server daemon.\n"},
    {"var/log/app.log",
     "[2024-06-26T01:10:00Z] INFO  app started, pid=4421\n"
     "[2024-06-26T01:12:05Z] INFO  request GET /api/v2/status 200 12ms\n"
     "[2024-06-26T01:14:22Z] WARN  rate limit threshold reached for 10.0.0.200\n"},
    {"var/log/access.log",
     "192.168.1.100 - admin [26/Jun/2024:01:12:05 +0000] \"GET /api/v2/status HTTP/1.1\" 200 512\n"
     "10.0.0.200 - - [26/Jun/2024:01:14:22 +0000] \"POST /api/v1/auth HTTP/1.1\" 429 88\n"},

    // /home/admin/
    {"home/admin/.ssh/authorized_keys",
     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB... admin@workstation\n"
     "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG... deploy@ci-server\n"},
    {"home/admin/documents/q2-report.txt",
     "Q2 Infrastructure Report\n========================\nUptime: 99.97%\nIncidents: 1 (P3)\n"},
    {"home/admin/scripts/deploy.sh",
     "#!/bin/bash\nset -euo pipefail\ncd /opt/app\ngit pull origin main\nsystemctl restart app\n"},
    {"home/admin/.bashrc",
     "export PATH=\"/opt/app/bin:$PATH\"\nexport EDITOR=vim\nalias ll='ls -la'\n"},

    // /opt/app/
    {"opt/app/config.json",
     "{\n  \"db_host\": \"db-primary.corp.internal\",\n  \"db_port\": 5432,\n"
     "  \"db_name\": \"proddb\",\n  \"max_connections\": 100,\n"
     "  \"log_level\": \"info\"\n}\n"},
    {"opt/app/data/users.db",
     "[SYNTHETIC SQLITE BINARY — 48KB]\n[user records omitted for safety]\n"},
    {"opt/app/data/sessions.cache",
     "[SYNTHETIC SESSION CACHE — 12KB]\n[session tokens not real]\n"},
    {"opt/app/bin/app-server",
     "[SYNTHETIC ELF BINARY — 2.1MB]\n"},
    {"opt/app/scripts/backup.sh",
     "#!/bin/bash\nDATE=$(date +%F)\ntar czf /backup/db-${DATE}.tar.gz /opt/app/data/\n"
     "echo \"Backup complete: db-${DATE}.tar.gz\"\n"},
    {"opt/app/scripts/health_check.sh",
     "#!/bin/bash\ncurl -sf http://localhost:8080/health || systemctl restart app\n"},

    // /backup/
    {"backup/db-2024-06-24.tar.gz",
     "[SYNTHETIC TAR.GZ — 14.2MB]\n"},
    {"backup/db-2024-06-25.tar.gz",
     "[SYNTHETIC TAR.GZ — 14.3MB]\n"},
    {"backup/db-2024-06-26.tar.gz",
     "[SYNTHETIC TAR.GZ — 14.5MB]\n"},
    {"backup/manifest.txt",
     "db-2024-06-24.tar.gz SHA256=abc123...\n"
     "db-2024-06-25.tar.gz SHA256=def456...\n"
     "db-2024-06-26.tar.gz SHA256=789abc...\n"},
};

static int64_t synthetic_size(const std::string& content)
{
    // For display: if content contains a "[SYNTHETIC ... MB]" marker, parse it
    auto mb_pos = content.find("MB]");
    if (mb_pos != std::string::npos) {
        auto dash = content.rfind("—", mb_pos);
        if (dash != std::string::npos) {
            std::string num = content.substr(dash + 3, mb_pos - dash - 3);
            // strip whitespace
            while (!num.empty() && (num.front() == ' ' || num.front() == '\n')) num.erase(0,1);
            try {
                return static_cast<int64_t>(std::stod(num) * 1024 * 1024);
            } catch (...) {}
        }
    }
    auto kb_pos = content.find("KB]");
    if (kb_pos != std::string::npos) {
        auto dash = content.rfind("—", kb_pos);
        if (dash != std::string::npos) {
            std::string num = content.substr(dash + 3, kb_pos - dash - 3);
            while (!num.empty() && (num.front() == ' ' || num.front() == '\n')) num.erase(0,1);
            try {
                return static_cast<int64_t>(std::stod(num) * 1024);
            } catch (...) {}
        }
    }
    return static_cast<int64_t>(content.size());
}

} // anonymous namespace

size_t Sandbox::populate()
{
    std::lock_guard<std::mutex> lk(mutex_);

    size_t created = 0;
    int64_t ts = now_ms();

    for (const auto& sf : kSyntheticFiles) {
        std::string rel = sf.rel_path;
        if (entries_.count(rel)) continue;   // idempotent

        std::string abs = root_path_ + "/" + rel;

        // Write to disk
        try {
            write_to_disk(abs, sf.content);
        } catch (const std::exception& e) {
            // Non-fatal: log but continue — in-memory state is still valid
            (void)e;
        }

        SandboxEntry entry;
        entry.rel_path      = rel;
        entry.type          = EntryType::FILE;
        entry.content       = sf.content;
        entry.version       = 1;
        entry.locked        = false;
        entry.size_bytes    = synthetic_size(sf.content);
        entry.last_modified = ts;

        entries_[rel] = entry;
        ++created;
    }

    if (created > 0) {
        std::ostringstream p;
        p << "root=" << root_path_
          << " entries_created=" << created;
        audit_adder_("sandbox_populated", p.str());
    }

    return created;
}

// ---------------------------------------------------------------------------
// write
// ---------------------------------------------------------------------------

SandboxResult Sandbox::write(const std::string& abs_path,
                              const std::string& content,
                              const std::string& author)
{
    // Path guard — enforced in code
    if (!is_inside(abs_path, root_path_)) {
        return {false, "path outside sandbox root: " + abs_path};
    }

    std::string rel = to_rel(abs_path);
    if (rel.empty()) {
        return {false, "could not compute rel_path for: " + abs_path};
    }

    // Global WORM check
    if (lock_check_()) {
        return {false, "write blocked: global WORM lockdown active"};
    }

    std::lock_guard<std::mutex> lk(mutex_);

    // Per-entry lock check
    auto it = entries_.find(rel);
    if (it != entries_.end() && it->second.locked) {
        return {false, "write blocked: entry is individually locked: " + rel};
    }

    int64_t ts = now_ms();

    if (it == entries_.end()) {
        // New entry
        SandboxEntry entry;
        entry.rel_path      = rel;
        entry.type          = EntryType::FILE;
        entry.content       = content;
        entry.version       = 1;
        entry.locked        = false;
        entry.size_bytes    = static_cast<int64_t>(content.size());
        entry.last_modified = ts;
        entries_[rel] = entry;
    } else {
        it->second.content       = content;
        it->second.version      += 1;
        it->second.size_bytes    = static_cast<int64_t>(content.size());
        it->second.last_modified = ts;
    }

    // Write to disk
    try {
        write_to_disk(abs_path, content);
    } catch (...) {}

    std::ostringstream p;
    p << "rel=" << rel
      << " version=" << entries_[rel].version
      << " author=" << author
      << " size=" << entries_[rel].size_bytes;
    audit_adder_("sandbox_write", p.str());

    return {true, ""};
}

// ---------------------------------------------------------------------------
// read
// ---------------------------------------------------------------------------

SandboxResult Sandbox::read(const std::string& abs_path, SandboxEntry& out) const
{
    if (!is_inside(abs_path, root_path_)) {
        return {false, "path outside sandbox root: " + abs_path};
    }

    std::string rel = to_rel(abs_path);
    std::lock_guard<std::mutex> lk(mutex_);

    auto it = entries_.find(rel);
    if (it == entries_.end()) {
        return {false, "entry not found: " + rel};
    }

    out = it->second;
    return {true, ""};
}

// ---------------------------------------------------------------------------
// lock_entry / lock_all / unlock_entry
// ---------------------------------------------------------------------------

SandboxResult Sandbox::lock_entry(const std::string& abs_path, const std::string& reason)
{
    if (!is_inside(abs_path, root_path_)) {
        return {false, "path outside sandbox root: " + abs_path};
    }

    std::string rel = to_rel(abs_path);
    std::lock_guard<std::mutex> lk(mutex_);

    auto it = entries_.find(rel);
    if (it == entries_.end()) {
        return {false, "entry not found: " + rel};
    }

    it->second.locked = true;

    std::ostringstream p;
    p << "rel=" << rel << " reason=\"" << reason << "\"";
    audit_adder_("sandbox_entry_locked", p.str());

    return {true, ""};
}

size_t Sandbox::lock_all(const std::string& reason)
{
    std::lock_guard<std::mutex> lk(mutex_);

    size_t newly_locked = 0;
    for (auto& kv : entries_) {
        if (!kv.second.locked) {
            kv.second.locked = true;
            ++newly_locked;
        }
    }

    std::ostringstream p;
    p << "newly_locked=" << newly_locked
      << " total=" << entries_.size()
      << " reason=\"" << reason << "\"";
    audit_adder_("sandbox_worm_lock_all", p.str());

    return newly_locked;
}

SandboxResult Sandbox::unlock_entry(const std::string& abs_path, const std::string& reason)
{
    if (!is_inside(abs_path, root_path_)) {
        return {false, "path outside sandbox root: " + abs_path};
    }

    std::string rel = to_rel(abs_path);
    std::lock_guard<std::mutex> lk(mutex_);

    auto it = entries_.find(rel);
    if (it == entries_.end()) {
        return {false, "entry not found: " + rel};
    }

    it->second.locked = false;

    std::ostringstream p;
    p << "rel=" << rel << " reason=\"" << reason << "\"";
    audit_adder_("sandbox_entry_unlocked", p.str());

    return {true, ""};
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

std::vector<SandboxEntry> Sandbox::get_tree() const
{
    std::lock_guard<std::mutex> lk(mutex_);
    std::vector<SandboxEntry> result;
    result.reserve(entries_.size());
    for (const auto& kv : entries_) {
        result.push_back(kv.second);
    }
    return result;
}

size_t Sandbox::entry_count() const
{
    std::lock_guard<std::mutex> lk(mutex_);
    return entries_.size();
}

} // namespace sandbox
} // namespace astartis

// Made with Bob
