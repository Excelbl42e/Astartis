// dashboard_writer.h -- Writes dashboard_data.json for the Astartis v3.2 UI
//
// DashboardWriter runs a background thread that calls a user-supplied DataProvider
// every interval_seconds and writes the result as JSON to <output_dir>/dashboard_data.json.
//
// Re-added in Phase 4 rebuild. Identical to v3.2 version with no functional changes.

#ifndef DASHBOARD_WRITER_H
#define DASHBOARD_WRITER_H

#include <string>
#include <thread>
#include <atomic>
#include <functional>
#include <vector>

namespace astartis {
namespace dashboard {

struct AgentStatus {
    std::string name;
    std::string tier;
    std::string model;
    std::string status;      // "online" | "offline" | "busy"
    int         tasks_completed = 0;
    std::string last_active;  // ISO 8601 timestamp
};

struct Alert {
    std::string timestamp;
    std::string severity;    // "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    std::string agent_name;
    std::string message;
};

struct LogEntry {
    std::string timestamp;
    std::string level;       // "INFO" | "WARN" | "ERROR" | "DEBUG"
    std::string message;
};

// Dependency version info for the status panel (TERRA Part 3)
struct DepInfo {
    std::string name;
    std::string version;      // "" = unknown
    std::string status;       // "connected" | "running" | "stubbed" | "missing"
    std::string verified_at;  // ISO 8601 timestamp of last successful check
};

struct SystemHealth {
    bool ollama_online         = false;
    bool npcap_installed       = false;
    bool npcap_service_running = false;
    bool clamd_online          = false;
    bool is_admin              = false;
    // Dependency version info (populated by query_system_health)
    DepInfo dep_ollama;
    DepInfo dep_npcap;
    DepInfo dep_clamd;
    DepInfo dep_granite_fast;
    DepInfo dep_granite_heavy;
    DepInfo dep_granite_acc;
};

struct SystemMetrics {
    double cpu_percent      = 0.0;
    double memory_percent   = 0.0;
    double memory_used_gb   = 0.0;
    double memory_total_gb  = 0.0;
    double disk_percent     = 0.0;
    double disk_free_gb     = 0.0;
    double network_mbps     = 0.0;
    int    cpu_cores        = 0;
    bool   ollama_online    = false;
};

struct FirewallBlockData {
    std::string ip;
    std::string rule_name_in;
    int64_t     blocked_at_ms = 0;
    int64_t     expires_at_ms = 0;
};

struct QuarantineEntryData {
    std::string entry_id;
    std::string virus_name;
    int64_t     quarantined_at_ms = 0;
};

struct DecoyEventData {
    std::string attacker_tag;
    std::string poison_type;
    std::string action;
    int64_t     timestamp_ms = 0;
};

struct ZeroTrustDecisionData {
    std::string user_id;
    std::string decision;
    int         trust_score = 0;
    std::string resource;
    std::string timestamp;  // ISO 8601 — populated from audit entry timestamp
};

struct EntropyWindowData {
    double   mean_entropy_bits = 0.0;
    double   max_entropy_bits  = 0.0;
    bool     anomalous         = false;
    uint64_t window_index      = 0;
};

struct ChaosWindowData {
    double   K             = 0.0;
    bool     anomalous     = false;
    uint64_t window_index  = 0;
};

struct PipelineStageData {
    std::string stage;
    std::string status;  // PASSED | FAILED | SKIPPED | AUTO_FIXED
    std::string detail;
};

struct SandboxEntryData {
    std::string rel_path;
    std::string type;
    bool        locked  = false;
    uint64_t    version = 0;
};

struct AuditEntryData {
    std::string entry_id;
    std::string event_type;
    std::string timestamp;
    bool        chain_valid = true;
};

struct DashboardData {
    std::string system_mode   = "FULL";
    std::string system_status = "online";
    int active_agents   = 0;
    int queue_depth     = 0;
    std::string threat_level  = "LOW";
    int threat_score    = 0;
    int alerts_24h      = 0;
    int critical_alerts = 0;
    std::vector<AgentStatus> agents;
    std::vector<Alert>       alerts;
    std::vector<LogEntry>    new_logs;

    SystemMetrics system_metrics;
    std::vector<double> cpu_history;
    std::vector<double> mem_history;
    std::vector<double> disk_history;
    std::vector<double> net_history;
    std::vector<FirewallBlockData>      firewall_blocks;
    std::vector<QuarantineEntryData>    quarantine_entries;
    std::vector<DecoyEventData>         decoy_events;
    std::vector<ZeroTrustDecisionData>  zerotrust_decisions;
    std::vector<EntropyWindowData>      entropy_windows;
    std::vector<ChaosWindowData>        chaos_windows;
    std::vector<PipelineStageData>      pipeline_stages;
    std::vector<SandboxEntryData>       sandbox_entries;
    std::vector<AuditEntryData>         audit_entries;
    bool audit_chain_valid = true;
    bool worm_is_locked    = false;
    SystemHealth health;
};

class DashboardWriter {
public:
    using DataProvider = std::function<DashboardData()>;

    explicit DashboardWriter(const std::string& output_dir);
    ~DashboardWriter();

    DashboardWriter(const DashboardWriter&)            = delete;
    DashboardWriter& operator=(const DashboardWriter&) = delete;

    void set_data_provider(DataProvider provider);
    void start(int interval_seconds = 5);
    void stop();
    bool is_running() const { return running_.load(); }

private:
    void write_loop(int interval_seconds);
    void write_json(const DashboardData& data);

    std::string  output_dir_;
    std::string  json_path_;
    DataProvider provider_;
    std::atomic<bool> running_{false};
    std::thread  thread_;
};

SystemMetrics query_windows_metrics();
SystemHealth  query_system_health();

} // namespace dashboard
} // namespace astartis

#endif // DASHBOARD_WRITER_H
