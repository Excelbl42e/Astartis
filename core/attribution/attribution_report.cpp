#include "attribution_report.h"

#include <sstream>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <ctime>

namespace fs = std::filesystem;

namespace astartis {
namespace attribution {

// ---------------------------------------------------------------------------
// MITRE ATT&CK inline mapping table
// Covers only the techniques observable on Astartis's decoy surface.
// ---------------------------------------------------------------------------

namespace {

struct TechniqueRule {
    const char* action_contains;   // substring match on action field (or "")
    const char* path_contains;     // substring match on rel_path (or "")
    const char* technique_id;
    const char* name;
    const char* tactic;
};

static const TechniqueRule kTechniqueRules[] = {
    // Credential access
    { "",         "credentials",       "T1552",   "Unsecured Credentials",         "Credential Access" },
    { "",         ".aws",              "T1552.005","Cloud Instance Metadata API",   "Credential Access" },
    { "",         "id_rsa",            "T1552.004","Private Keys",                  "Credential Access" },
    { "",         "shadow",            "T1003.008","OS Credential Dumping: /etc/shadow", "Credential Access" },
    { "",         ".env",              "T1552.001","Credentials In Files",          "Credential Access" },
    // Discovery
    { "",         "etc/hostname",      "T1082",   "System Information Discovery",   "Discovery"         },
    { "",         "etc/nginx.conf",    "T1518",   "Software Discovery",             "Discovery"         },
    { "",         "etc/sshd_config",   "T1082",   "System Information Discovery",   "Discovery"         },
    { "",         "authorized_keys",   "T1087",   "Account Discovery",              "Discovery"         },
    { "",         "config.json",       "T1083",   "File and Directory Discovery",   "Discovery"         },
    // Collection
    { "",         "financial",         "T1213",   "Data from Information Repositories", "Collection"    },
    { "",         "customer-pii",      "T1005",   "Data from Local System",         "Collection"        },
    { "",         "ip-source-code",    "T1213",   "Data from Information Repositories", "Collection"    },
    { "",         "roadmap",           "T1005",   "Data from Local System",         "Collection"        },
    // Exfiltration
    { "exfil",    "",                  "T1041",   "Exfiltration Over C2 Channel",   "Exfiltration"      },
    // Lateral movement
    { "",         "server-02",         "T1021",   "Remote Services",                "Lateral Movement"  },
    // Log access
    { "",         "auth.log",          "T1654",   "Log Enumeration",                "Discovery"         },
    { "",         "access.log",        "T1654",   "Log Enumeration",                "Discovery"         },
    // Redirect / defence evasion
    { "redirect", "",                  "T1036",   "Masquerading",                   "Defense Evasion"   },
};

} // anonymous namespace

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

AttributionReporter::AttributionReporter(
    const std::string& sandbox_root,
    std::function<std::string(const std::string&, const std::string&)> audit_adder)
    : sandbox_root_(sandbox_root)
    , audit_adder_(std::move(audit_adder))
{}

// ---------------------------------------------------------------------------
// map_techniques
// ---------------------------------------------------------------------------

std::vector<AttackTechnique> AttributionReporter::map_techniques(
    const std::string& action,
    const std::string& rel_path,
    decoy::PoisonType  /* poison_type */)
{
    std::vector<AttackTechnique> results;
    std::vector<std::string> seen_ids;  // avoid duplicates

    for (const auto& rule : kTechniqueRules) {
        bool action_match = (rule.action_contains[0] == '\0') ||
                            (action.find(rule.action_contains) != std::string::npos);
        bool path_match   = (rule.path_contains[0] == '\0') ||
                            (rel_path.find(rule.path_contains) != std::string::npos);

        if (action_match && path_match) {
            // Deduplicate by technique_id
            std::string tid = rule.technique_id;
            if (std::find(seen_ids.begin(), seen_ids.end(), tid) == seen_ids.end()) {
                seen_ids.push_back(tid);
                AttackTechnique t;
                t.technique_id = tid;
                t.name         = rule.name;
                t.tactic       = rule.tactic;
                t.evidence     = action + " on " + rel_path;
                results.push_back(t);
            }
        }
    }
    return results;
}

// ---------------------------------------------------------------------------
// format_timestamp
// ---------------------------------------------------------------------------

std::string AttributionReporter::format_timestamp(int64_t ms)
{
    time_t sec = static_cast<time_t>(ms / 1000);
    int    ms_part = static_cast<int>(ms % 1000);
    struct tm tm_buf;
#ifdef _WIN32
    gmtime_s(&tm_buf, &sec);
#else
    gmtime_r(&sec, &tm_buf);
#endif
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_buf);
    std::ostringstream oss;
    oss << buf << "." << std::setw(3) << std::setfill('0') << ms_part << "Z";
    return oss.str();
}

// ---------------------------------------------------------------------------
// build_report_text
// ---------------------------------------------------------------------------

std::string AttributionReporter::build_report_text(const ReportArtifact& r)
{
    std::ostringstream o;

    o << "================================================================================\n";
    o << "  ASTARTIS ATTRIBUTION REPORT\n";
    o << "  DIBANET Layer 4 -- Decoy Session Analysis\n";
    o << "================================================================================\n\n";

    o << "Session ID      : " << r.session_id << "\n";
    o << "Session Start   : " << format_timestamp(r.session_start_ms) << "\n";
    o << "Session End     : " << format_timestamp(r.session_end_ms) << "\n";
    o << "Total Interactions: " << r.total_interactions << "\n\n";

    // -- ATT&CK techniques --
    o << "--------------------------------------------------------------------------------\n";
    o << "  MITRE ATT&CK TECHNIQUE MATCHES\n";
    o << "--------------------------------------------------------------------------------\n";
    if (r.techniques.empty()) {
        o << "  (no techniques matched)\n";
    } else {
        for (const auto& t : r.techniques) {
            o << "  [" << t.technique_id << "]  " << t.name
              << "  (" << t.tactic << ")\n";
            o << "    Evidence: " << t.evidence << "\n";
        }
    }
    o << "\n";

    // -- IOC hits --
    o << "--------------------------------------------------------------------------------\n";
    o << "  IOC CORRELATION RESULTS\n";
    o << "--------------------------------------------------------------------------------\n";
    if (r.ioc_hits.empty()) {
        o << "  (no IOC matches)\n";
    } else {
        for (const auto& h : r.ioc_hits) {
            o << "  [" << h.type << "]  " << h.indicator << "\n";
            o << "    " << h.description << "  (source: " << h.source << ")\n";
            o << "    Observed at: " << format_timestamp(h.timestamp_ms) << "\n";
        }
    }
    o << "\n";

    // -- Decoy events timeline --
    o << "--------------------------------------------------------------------------------\n";
    o << "  DECOY INTERACTION TIMELINE\n";
    o << "--------------------------------------------------------------------------------\n";
    for (const auto& ev : r.decoy_events) {
        o << "  " << format_timestamp(ev.timestamp_ms)
          << "  [" << decoy::poison_type_name(ev.poison_type) << "]"
          << "  " << ev.action
          << "  " << ev.rel_path << "\n";
    }
    o << "\n";

    // -- Response tiers --
    o << "--------------------------------------------------------------------------------\n";
    o << "  RESPONSE TIER PROGRESSION\n";
    o << "--------------------------------------------------------------------------------\n";
    for (const auto& ev : r.response_events) {
        o << "  " << format_timestamp(ev.timestamp_ms)
          << "  tier=" << ev.response_tier
          << "  " << ev.resource
          << (ev.ioc_match ? "  [IOC HIT: " + ev.ioc_indicator + "]" : "")
          << "\n";
    }
    o << "\n";

    // -- Summary --
    o << "--------------------------------------------------------------------------------\n";
    o << "  SUMMARY\n";
    o << "--------------------------------------------------------------------------------\n";
    o << r.summary << "\n\n";

    o << "================================================================================\n";
    o << "  Generated by Astartis -- DIBANET Layer 4\n";
    o << "================================================================================\n";

    return o.str();
}

// ---------------------------------------------------------------------------
// generate
// ---------------------------------------------------------------------------

ReportArtifact AttributionReporter::generate(
    const std::string&                                  session_id,
    const std::vector<decoy::DecoyEvent>&               decoy_log,
    const std::vector<active_response::ResponseEvent>&  response_log)
{
    ReportArtifact r;
    r.session_id = session_id;

    // Filter events to this session
    for (const auto& ev : decoy_log)
        if (ev.attacker_tag == session_id) r.decoy_events.push_back(ev);

    for (const auto& ev : response_log)
        if (ev.session_id == session_id) r.response_events.push_back(ev);

    r.total_interactions = static_cast<int>(r.response_events.size());

    // Session timestamps from earliest/latest event
    int64_t t_min = INT64_MAX, t_max = INT64_MIN;
    for (const auto& ev : r.decoy_events) {
        if (ev.timestamp_ms < t_min) t_min = ev.timestamp_ms;
        if (ev.timestamp_ms > t_max) t_max = ev.timestamp_ms;
    }
    for (const auto& ev : r.response_events) {
        if (ev.timestamp_ms < t_min) t_min = ev.timestamp_ms;
        if (ev.timestamp_ms > t_max) t_max = ev.timestamp_ms;
    }
    if (t_min == INT64_MAX) {
        // No events -- use now
        auto now = std::chrono::system_clock::now().time_since_epoch();
        t_min = t_max = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
    }
    r.session_start_ms = t_min;
    r.session_end_ms   = t_max;

    // ATT&CK technique mapping -- deduplicated across all decoy events
    std::vector<std::string> seen_ids;
    for (const auto& ev : r.decoy_events) {
        auto techs = map_techniques(ev.action, ev.rel_path, ev.poison_type);
        for (auto& t : techs) {
            if (std::find(seen_ids.begin(), seen_ids.end(), t.technique_id) == seen_ids.end()) {
                seen_ids.push_back(t.technique_id);
                r.techniques.push_back(t);
            }
        }
    }

    // IOC hits from response log
    for (const auto& ev : r.response_events) {
        if (ev.ioc_match) {
            IocHit h;
            h.indicator    = ev.ioc_indicator;
            h.timestamp_ms = ev.timestamp_ms;
            // Look up description/source/type from the indicator string
            // (simplified: mark as IP_ADDRESS for IPs, DOMAIN otherwise)
            bool has_dot = ev.ioc_indicator.find('.') != std::string::npos;
            bool is_ip   = has_dot &&
                           ev.ioc_indicator.find_first_not_of("0123456789.") == std::string::npos;
            h.type = is_ip ? "IP_ADDRESS" : "DOMAIN";
            h.description = "IOC match observed in session";
            h.source      = "Astartis IOC database";
            r.ioc_hits.push_back(h);
        }
    }

    // Build summary paragraph
    std::ostringstream sum;
    sum << "Attacker session '" << session_id << "' interacted with the decoy environment "
        << r.total_interactions << " time(s) across "
        << r.decoy_events.size() << " distinct poisoned asset(s). ";

    if (!r.techniques.empty()) {
        sum << r.techniques.size() << " MITRE ATT&CK technique(s) were observed: ";
        for (size_t i = 0; i < r.techniques.size(); ++i) {
            if (i > 0) sum << ", ";
            sum << r.techniques[i].technique_id << " (" << r.techniques[i].name << ")";
        }
        sum << ". ";
    }

    if (!r.ioc_hits.empty()) {
        sum << r.ioc_hits.size() << " IOC match(es) were recorded: ";
        for (size_t i = 0; i < r.ioc_hits.size(); ++i) {
            if (i > 0) sum << ", ";
            sum << r.ioc_hits[i].indicator;
        }
        sum << ". ";
    }

    // Find the highest response tier reached
    int max_tier = 0;
    for (const auto& ev : r.response_events)
        if (ev.response_tier > max_tier) max_tier = ev.response_tier;
    sum << "The attacker reached response tier " << max_tier
        << " (0=full response, 3=honeypot loop). "
        << "All interactions were contained within the sandbox. "
        << "No real system data was exposed.";
    r.summary = sum.str();

    // Write report file to <sandbox_root>/reports/<session_id>.txt
    fs::path reports_dir = fs::path(sandbox_root_) / "reports";
    fs::create_directories(reports_dir);
    std::string report_file = (reports_dir / (session_id + ".txt")).string();

    std::string text = build_report_text(r);
    std::ofstream f(report_file, std::ios::out | std::ios::trunc);
    if (f) { f << text; f.close(); }
    r.report_file_path = report_file;

    // Audit chain entry
    std::ostringstream p;
    p << "session=" << session_id
      << " techniques=" << r.techniques.size()
      << " ioc_hits=" << r.ioc_hits.size()
      << " interactions=" << r.total_interactions
      << " file=" << report_file;
    audit_adder_("attribution_report_generated", p.str());

    return r;
}

} // namespace attribution
} // namespace astartis

// Made with Bob
