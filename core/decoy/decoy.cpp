#include "decoy.h"

#include <chrono>
#include <sstream>
#include <stdexcept>
#include <map>

namespace astartis {
namespace decoy {

// ---------------------------------------------------------------------------
// Constant
// ---------------------------------------------------------------------------

const char* DecoyEnvironment::LATERAL_MOVEMENT_ROOT = "decoy/server-02";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const char* poison_type_name(PoisonType t)
{
    switch (t) {
        case PoisonType::DATA_VALUATION:   return "DATA_VALUATION";
        case PoisonType::LATERAL_MOVEMENT: return "LATERAL_MOVEMENT";
        case PoisonType::CREDENTIAL:       return "CREDENTIAL";
    }
    return "UNKNOWN";
}

static int64_t now_ms_decoy()
{
    auto tp = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(tp).count();
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

DecoyEnvironment::DecoyEnvironment(
    sandbox::Sandbox& sb,
    std::function<std::string(const std::string&, const std::string&)> audit_adder)
    : sb_(sb)
    , audit_adder_(std::move(audit_adder))
{}

// ---------------------------------------------------------------------------
// plant
// ---------------------------------------------------------------------------

namespace {

struct PoisonSpec {
    const char* rel_path;
    PoisonType  type;
    const char* content;
};

static const PoisonSpec kPoisonedFiles[] = {

    // --- DATA VALUATION POISONING -------------------------------------------
    {
        "decoy/assets/financial-projections-2024.xlsx",
        PoisonType::DATA_VALUATION,
        "[SYNTHETIC XLSX — 842KB]\n"
        "Sheet1: Revenue Projections\n"
        "Q1: $4,200,000  Q2: $5,100,000  Q3: $6,300,000  Q4: $7,800,000\n"
        "EBITDA margin target: 34.2%\n"
        "Acquisition target: TechCorp Holdings (NDA pending)\n"
        "NOTE: All figures are synthetic and not real.\n"
    },
    {
        "decoy/assets/customer-pii-export.csv",
        PoisonType::DATA_VALUATION,
        "id,name,email,ssn,dob,account_balance\n"
        "1,John Doe,jdoe@example.com,XXX-XX-0001,1980-03-14,$142000\n"
        "2,Jane Smith,jsmith@example.com,XXX-XX-0002,1975-07-22,$89500\n"
        "3,Bob Jones,bjones@example.com,XXX-XX-0003,1990-11-05,$215000\n"
        "NOTE: Entirely synthetic data — not real PII.\n"
    },
    {
        "decoy/assets/ip-source-code-archive.tar.gz",
        PoisonType::DATA_VALUATION,
        "[SYNTHETIC TAR.GZ — 38.4MB]\n"
        "Alleged contents: proprietary ML training pipeline source code\n"
        "NOTE: This is synthetic bait — no real source code.\n"
    },
    {
        "decoy/assets/strategic-roadmap-confidential.pdf",
        PoisonType::DATA_VALUATION,
        "[SYNTHETIC PDF — 2.1MB]\n"
        "CONFIDENTIAL — FOR BOARD DISTRIBUTION ONLY\n"
        "FY2025 Strategic Roadmap\n"
        "Key initiatives: Project Atlas, M&A Pipeline, APAC Expansion\n"
        "NOTE: Entirely synthetic content.\n"
    },

    // --- LATERAL MOVEMENT POISONING -----------------------------------------
    {
        "decoy/server-02/etc/hostname",
        PoisonType::LATERAL_MOVEMENT,
        "app-server-02.corp.internal\n"
    },
    {
        "decoy/server-02/etc/nginx.conf",
        PoisonType::LATERAL_MOVEMENT,
        "# Decoy server-02 nginx config\n"
        "worker_processes auto;\nhttp {\n"
        "  server {\n    listen 443 ssl;\n    server_name app-server-02.corp.internal;\n  }\n}\n"
    },
    {
        "decoy/server-02/var/log/auth.log",
        PoisonType::LATERAL_MOVEMENT,
        "Jun 26 03:00:01 sshd[2201]: Accepted publickey for deploy from 192.168.10.20\n"
        "Jun 26 03:14:55 sshd[2211]: Accepted publickey for admin from 192.168.10.20\n"
    },
    {
        "decoy/server-02/home/admin/.ssh/authorized_keys",
        PoisonType::LATERAL_MOVEMENT,
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN... admin@app-server-01\n"
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIR... deploy@ci-server\n"
    },
    {
        "decoy/server-02/opt/app/config.json",
        PoisonType::LATERAL_MOVEMENT,
        "{\n  \"db_host\": \"db-replica.corp.internal\",\n"
        "  \"db_port\": 5432,\n  \"db_name\": \"proddb_replica\",\n"
        "  \"api_key\": \"sk_live_DECOY_NOT_REAL_KEY_abc123xyz\"\n}\n"
    },

    // --- CREDENTIAL POISONING -----------------------------------------------
    {
        "decoy/credentials/.aws/credentials",
        PoisonType::CREDENTIAL,
        "[default]\n"
        "aws_access_key_id     = AKIAIOSFODNN7DECOY01\n"
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYDECOYKEY\n"
        "region = us-east-1\n"
        "NOTE: These are synthetic honeypot credentials — not real.\n"
    },
    {
        "decoy/credentials/.ssh/id_rsa",
        PoisonType::CREDENTIAL,
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz\n"
        "[SYNTHETIC KEY MATERIAL — NOT A REAL PRIVATE KEY]\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    },
    {
        "decoy/credentials/etc/shadow",
        PoisonType::CREDENTIAL,
        "root:$6$DECOY$abc123xyz456:19900:0:99999:7:::\n"
        "admin:$6$DECOY$def456uvw789:19900:0:99999:7:::\n"
        "deploy:$6$DECOY$ghi789rst012:19900:0:99999:7:::\n"
        "NOTE: Synthetic password hashes — not real.\n"
    },
    {
        "decoy/credentials/opt/app/.env",
        PoisonType::CREDENTIAL,
        "DATABASE_URL=postgresql://app_user:D3c0yP@ssw0rd!@db-primary.corp.internal:5432/proddb\n"
        "REDIS_URL=redis://:D3c0yR3dis!@cache.corp.internal:6379/0\n"
        "SECRET_KEY=decoy-django-secret-key-not-real-abc123xyz\n"
        "STRIPE_SECRET_KEY=sk_live_DECOY_STRIPE_NOT_REAL\n"
        "NOTE: All credentials are synthetic honeypot bait.\n"
    },
};

} // anonymous namespace

size_t DecoyEnvironment::plant()
{
    std::lock_guard<std::mutex> lk(mutex_);

    size_t planted = 0;
    for (const auto& spec : kPoisonedFiles) {
        std::string rel = spec.rel_path;
        std::string abs = sb_.root_path() + "/" + rel;

        auto r = sb_.write(abs, spec.content, "decoy_system");
        if (!r.ok) continue;   // already exists or blocked — skip

        poisoned_[rel] = spec.type;
        ++planted;
    }

    std::ostringstream p;
    p << "planted=" << planted
      << " data_valuation=4 lateral_movement=5 credential=4";
    audit_adder_("decoy_planted", p.str());

    return planted;
}

// ---------------------------------------------------------------------------
// touch
// ---------------------------------------------------------------------------

void DecoyEnvironment::log_event(const DecoyEvent& ev)
{
    forensic_log_.push_back(ev);

    std::ostringstream p;
    p << "rel=" << ev.rel_path
      << " poison_type=" << poison_type_name(ev.poison_type)
      << " action=" << ev.action
      << " attacker=" << ev.attacker_tag
      << " detail=\"" << ev.detail << "\"";
    audit_adder_("decoy_event", p.str());
}

bool DecoyEnvironment::touch(const std::string& rel_path,
                              const std::string& action,
                              const std::string& attacker_tag,
                              const std::string& detail)
{
    std::lock_guard<std::mutex> lk(mutex_);

    auto it = poisoned_.find(rel_path);
    if (it == poisoned_.end()) return false;

    DecoyEvent ev;
    ev.timestamp_ms = now_ms_decoy();
    ev.rel_path     = rel_path;
    ev.poison_type  = it->second;
    ev.action       = action;
    ev.attacker_tag = attacker_tag;
    ev.detail       = detail;
    log_event(ev);

    return true;
}

// ---------------------------------------------------------------------------
// redirect
// ---------------------------------------------------------------------------

std::string DecoyEnvironment::redirect(const std::string& attacker_tag,
                                        const std::string& trigger_path)
{
    std::lock_guard<std::mutex> lk(mutex_);

    std::string dest = LATERAL_MOVEMENT_ROOT;

    DecoyEvent ev;
    ev.timestamp_ms = now_ms_decoy();
    ev.rel_path     = dest;
    ev.poison_type  = PoisonType::LATERAL_MOVEMENT;
    ev.action       = "redirect";
    ev.attacker_tag = attacker_tag;
    ev.detail       = "triggered_by=" + trigger_path;
    log_event(ev);

    return dest;
}

// ---------------------------------------------------------------------------
// Forensic log queries
// ---------------------------------------------------------------------------

std::vector<DecoyEvent> DecoyEnvironment::forensic_log() const
{
    std::lock_guard<std::mutex> lk(mutex_);
    return forensic_log_;
}

size_t DecoyEnvironment::event_count() const
{
    std::lock_guard<std::mutex> lk(mutex_);
    return forensic_log_.size();
}

bool DecoyEnvironment::is_poisoned(const std::string& rel_path) const
{
    std::lock_guard<std::mutex> lk(mutex_);
    return poisoned_.count(rel_path) > 0;
}

PoisonType DecoyEnvironment::poison_type_of(const std::string& rel_path) const
{
    std::lock_guard<std::mutex> lk(mutex_);
    auto it = poisoned_.find(rel_path);
    if (it == poisoned_.end())
        throw std::invalid_argument("not a poisoned path: " + rel_path);
    return it->second;
}

} // namespace decoy
} // namespace astartis

// Made with Bob
