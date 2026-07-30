// astartis_bridge.cpp -- Port target for the Elixir orchestration layer (Step 15)
//
// Communicates over stdio using newline-delimited JSON:
//   stdin  : {"cmd":"...", "args":{...}}
//   stdout : {"event":"...", "data":{...}}
//
// Stdout is always flushed immediately.
// Step 16: elevation is the Port supervisor's responsibility, not ours.
// --dashboard: launches the IBM Carbon-styled dashboard on http://127.0.0.1:9876/

// Winsock2 must precede windows.h
#include <winsock2.h>
#include <shellapi.h>

// MUST come after winsock2.h; use nlohmann BEFORE any other Windows includes
// so WIN32_LEAN_AND_MEAN doesn't strip anything nlohmann needs.
#pragma warning(push)
#pragma warning(disable: 4706 4127 4244)
#include "nlohmann/json.hpp"
#pragma warning(pop)

// Now include the core headers. The core headers use WIN32_LEAN_AND_MEAN
// themselves; nlohmann is already fully compiled above so there's no conflict.
#include "audit_chain/audit_chain.h"
#include "worm_lock/worm_lock.h"
#include "sandbox/sandbox.h"
#include "threat_level/threat_level.h"
#include "rule_engine/rule_engine.h"
#include "chaos_detector/chaos_detector.h"
#include "decoy/decoy.h"
#include "active_response/active_response.h"
#include "attribution/attribution_report.h"
#include "clamd/clamd_scanner.h"
#include "quarantine/quarantine.h"
#include "firewall/firewall_blocker.h"
#include "unlock_protocol/unlock_protocol.h"
#include "access_token/access_token.h"
#include "ai_triage/ai_triage.h"
#include "veeam_interface/veeam_interface.h"

#include <iostream>
#include <fstream>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>
#include <filesystem>
#include <sstream>
#include <vector>
#include <algorithm>
#include <cstdint>
#include <cmath>
#include <memory>

// v2.0 agent swarm
#include "agents/controller/agent_controller.h"

// Phase 4: C++ HTTP dashboard (rebuilt)
#include "dashboard_writer.h"
#include "dashboard_server.h"

// v2.1 network architecture — Zero Trust simulation
#include "network_arch/segmentation/ssid_config.h"
#include "network_arch/zerotrust/nac_workflow.h"
#include "network_arch/zerotrust/zerotrust_engine.h"

// v3.1 real protection monitors
#include "packet_sensor/packet_sensor.h"
#include "event_log_monitor/event_log_monitor.h"
#include "fs_monitor/fs_monitor.h"
#include "autonomy_loop/autonomy_loop.h"

using json = nlohmann::json;
namespace fs = std::filesystem;

// Correct namespace aliases for each module
using AuditChain   = astartis::audit::AuditChain;
using WormLock     = astartis::worm::WormLock;
using Sandbox      = astartis::sandbox::Sandbox;
using EntryType    = astartis::sandbox::EntryType;
using ThreatSM     = astartis::threat::ThreatStateMachine;
using ThreatTier   = astartis::threat::ThreatTier;
using RuleEngine   = astartis::rules::RuleEngine;
using ChaosDetect  = astartis::chaos::ChaosDetector;
using ChaosWindow  = astartis::chaos::ChaosWindow;
using DecoyEnv     = astartis::decoy::DecoyEnvironment;
using ActiveResp   = astartis::active_response::ActiveResponse;
using Attribution  = astartis::attribution::AttributionReporter;
using ClamdScan    = astartis::clamd::ClamdScanner;
using Quarantine      = astartis::quarantine::Quarantine;
using FwBlocker       = astartis::firewall::FirewallBlocker;
using TokenStore      = astartis::access::TokenStore;
using UnlockProtocol  = astartis::unlock::UnlockProtocol;
using ApproverSide    = astartis::unlock::ApproverSide;
using AiTriage        = astartis::ai::AiTriage;
using VeeamIface      = astartis::backup::VeeamInterface;
using BackupLockState = astartis::backup::BackupLockState;

// ---------------------------------------------------------------------------
// Global objects (all share a single audit chain)
// ---------------------------------------------------------------------------

static AuditChain g_audit;

// WormLock, ThreatSM, RuleEngine constructed in main (need audit_adder lambda)
// All heap objects held as unique_ptr for RAII / exception safety (P0 fix)
static std::unique_ptr<WormLock>       g_worm;
static std::unique_ptr<Sandbox>        g_sandbox;
static std::unique_ptr<ThreatSM>       g_threat;
static std::unique_ptr<RuleEngine>     g_rules;
static std::unique_ptr<ChaosDetect>    g_chaos;
static std::unique_ptr<DecoyEnv>       g_decoy;
static std::unique_ptr<ActiveResp>     g_ar;
static std::unique_ptr<ClamdScan>      g_clamd;
static std::unique_ptr<Quarantine>     g_qtn;
static std::unique_ptr<FwBlocker>      g_firewall;
static std::unique_ptr<TokenStore>     g_tokens;
static std::unique_ptr<UnlockProtocol> g_unlock;
static std::unique_ptr<AiTriage>       g_ai_triage;
static std::unique_ptr<VeeamIface>     g_veeam;
// v2.0 agent swarm controller
static std::unique_ptr<astartis::agents::AgentController> g_agents;

// Step 18: last triage snapshot (written by triage_event handler, read by build_snapshot)
static std::mutex         g_triage_snap_mutex;
static nlohmann::json     g_last_triage_snap = nullptr;

// Step 17: approver identities keyed by name (bridge holds private keys for demo)
static std::map<std::string, std::unique_ptr<astartis::crypto::Identity>> g_approver_identities;

static std::string g_sandbox_root;
// v3.1 real-time protection components
static std::unique_ptr<astartis::sensor::PacketSensor>           g_packet_sensor;
static std::unique_ptr<astartis::monitor::EventLogMonitor>       g_event_log_monitor;
static std::unique_ptr<astartis::monitor::FsMonitor>             g_fs_monitor;
static std::unique_ptr<astartis::autonomy::AutonomyLoop>         g_autonomy_loop;

// Phase 4: C++ HTTP dashboard components
static std::unique_ptr<astartis::dashboard::DashboardWriter>     g_dashboard_writer;
static std::unique_ptr<astartis::dashboard::DashboardServer>     g_dashboard_server;

// Rolling PDH metric history for sparklines (max 20 samples)
static std::mutex              g_metrics_hist_mutex;
static std::vector<double>     g_cpu_history;
static std::vector<double>     g_mem_history;
static std::vector<double>     g_disk_history;

static std::mutex        g_write_mutex;
static std::atomic<bool> g_running{true};

// Elevation status — set once in main() before any threads start
static bool g_is_elevated = false;

// ---------------------------------------------------------------------------
// Elevation check (Windows-specific)
// ---------------------------------------------------------------------------

static bool check_elevation()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    TOKEN_ELEVATION elevation{};
    DWORD size = sizeof(elevation);
    BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, size, &size);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated != 0;
}

// Chaos K rolling history (max 100 windows)
static std::mutex          g_hist_mutex;
static std::vector<double> g_chaos_history;

// Latest chaos window values for the tick snapshot
static std::atomic<double> g_latest_K{0.0};
static std::atomic<bool>   g_latest_anomalous{false};
static std::atomic<uint64_t> g_latest_chaos_windows{0};

// ---------------------------------------------------------------------------
// Audit adder
// ---------------------------------------------------------------------------

static std::function<std::string(const std::string&, const std::string&)>
make_audit_adder()
{
    return [](const std::string& evt, const std::string& payload) -> std::string {
        return g_audit.add_entry(evt, payload);
    };
}

// ---------------------------------------------------------------------------
// Serialised stdout writer
// ---------------------------------------------------------------------------

static void emit(const json& obj)
{
    std::lock_guard<std::mutex> lk(g_write_mutex);
    std::cout << obj.dump() << "\n";
    std::cout.flush();
}

// ---------------------------------------------------------------------------
// Snapshot for the 500 ms tick
// ---------------------------------------------------------------------------

static json build_snapshot()
{
    json snap;

    // Threat tier
    ThreatTier tier = g_threat->current_tier();
    snap["threat_tier"] = static_cast<int>(tier);
    switch (tier) {
        case ThreatTier::LOW:      snap["threat_tier_name"] = "LOW";      break;
        case ThreatTier::MEDIUM:   snap["threat_tier_name"] = "MEDIUM";   break;
        case ThreatTier::HIGH:     snap["threat_tier_name"] = "HIGH";     break;
        case ThreatTier::CRITICAL: snap["threat_tier_name"] = "CRITICAL"; break;
        default:                   snap["threat_tier_name"] = "LOW";      break;
    }
    snap["threat_transitions"] = g_threat->transition_count();

    // WORM
    snap["worm_locked"]     = g_worm->is_locked();
    snap["worm_reason"]     = g_worm->lock_reason();
    snap["worm_lock_count"] = g_worm->lockdown_count();

    // Audit chain
    auto vr = g_audit.verify_chain();
    snap["chain_length"] = g_audit.get_chain_length();
    snap["chain_valid"]  = vr.is_valid;
    {
        auto h = g_audit.get_chain_head_hash();
        snap["chain_head"] = h.size() >= 12 ? h.substr(0, 12) : h;
    }

    // Chaos
    snap["chaos_K"]         = g_latest_K.load();
    snap["chaos_anomalous"] = g_latest_anomalous.load();
    snap["chaos_windows"]   = g_latest_chaos_windows.load();
    {
        std::lock_guard<std::mutex> lk(g_hist_mutex);
        snap["chaos_history"] = g_chaos_history;
    }

    // Rule engine — FIX BUG-05-D: guard against null g_rules
    if (g_rules) {
        snap["rule_fires"]    = g_rules->total_fires();
        snap["worm_triggers"] = g_rules->worm_trigger_count();
    } else {
        snap["rule_fires"]    = 0;
        snap["worm_triggers"] = 0;
    }

    // Decoy — FIX BUG-05-D: guard against null g_decoy
    snap["decoy_events"] = g_decoy ? g_decoy->event_count() : 0;

    // Sandbox file tree — FIX BUG-05-C: guard against null g_sandbox
    json entries = json::array();
    for (const auto& e : (g_sandbox ? g_sandbox->get_tree() : decltype(g_sandbox->get_tree()){})) {
        entries.push_back({
            {"rel_path",      e.rel_path},
            {"type",          e.type == EntryType::FILE ? "file" : "dir"},
            {"size_bytes",    e.size_bytes},
            {"version",       e.version},
            {"locked",        e.locked},
            {"last_modified", e.last_modified}
        });
    }
    snap["sandbox_entries"] = entries;
    snap["sandbox_root"]    = g_sandbox_root;
    snap["elevated"]        = g_is_elevated;

    // Step 16 ST-5: quarantine + firewall counts
    snap["quarantine_count"] = g_qtn ? static_cast<int>(g_qtn->list().size()) : 0;
    {
        json fw_blocks = json::array();
        if (g_firewall) {
            for (const auto& ab : g_firewall->active_blocks()) {
                fw_blocks.push_back({
                    {"ip",             ab.ip},
                    {"rule_name_in",   ab.rule_name_in},
                    {"expires_at_ms",  ab.expires_at_ms}
                });
            }
        }
        snap["active_firewall_blocks"] = fw_blocks;
    }

    // Step 17: unlock protocol status
    if (g_unlock) {
        auto ust = g_unlock->status();
        snap["unlock_votes_collected"] = ust.votes_collected;
        snap["unlock_threshold"]       = ust.threshold;
        snap["unlock_state"] = [&]() -> std::string {
            switch (ust.state) {
                case astartis::unlock::ProtocolState::COLLECTING: return "COLLECTING";
                case astartis::unlock::ProtocolState::GRANTED:    return "GRANTED";
                default:                                           return "IDLE";
            }
        }();
        json approver_arr = json::array();
        for (const auto& ap : ust.approvers) {
            approver_arr.push_back({
                {"name",  ap.name},
                {"side",  ap.side == ApproverSide::ASTARTIS ? "ASTARTIS" : "CLIENT"},
                {"voted", ap.voted}
            });
        }
        snap["unlock_approvers"] = approver_arr;
    } else {
        snap["unlock_votes_collected"] = 0;
        snap["unlock_threshold"]       = UnlockProtocol::DEMO_THRESHOLD;
        snap["unlock_state"]           = "IDLE";
        snap["unlock_approvers"]       = json::array();
    }

    // Step 18: last triage result (populated after first triage_event call)
    {
        std::lock_guard<std::mutex> lk(g_triage_snap_mutex);
        snap["last_triage"] = g_last_triage_snap;
    }

    // Step 19: Veeam / IBM Storage backup repo status
    if (g_veeam) {
        auto vs = g_veeam->status();
        snap["veeam_lock_state"]       = VeeamIface::lock_state_str(vs.lock_state);
        snap["veeam_backup_count"]     = vs.backup_count;
        snap["veeam_locked_at_ms"]     = vs.locked_at_ms;
        snap["veeam_integrity_checks"] = vs.integrity_check_count;
        snap["veeam_locked_by_reason"] = vs.locked_by_reason;
    } else {
        snap["veeam_lock_state"]       = "UNLOCKED";
        snap["veeam_backup_count"]     = 0;
        snap["veeam_locked_at_ms"]     = 0;
        snap["veeam_integrity_checks"] = 0;
        snap["veeam_locked_by_reason"] = "";
    }

    // v2.0: agent swarm status — included in every tick so dashboard stays live
    if (g_agents) {
        auto statuses = g_agents->get_statuses();
        json status_arr = json::array();
        for (const auto& s : statuses) {
            std::string state_str;
            switch (s.state) {
                case astartis::agents::AgentState::IDLE:      state_str = "IDLE";      break;
                case astartis::agents::AgentState::RUNNING:   state_str = "RUNNING";   break;
                case astartis::agents::AgentState::COMPLETED: state_str = "COMPLETED"; break;
                case astartis::agents::AgentState::FAILED:    state_str = "FAILED";    break;
                default:                                       state_str = "IDLE";      break;
            }
            status_arr.push_back({
                {"name",                s.name},
                {"category",            s.category},
                {"state",               state_str},
                {"last_task_id",        s.last_task_id},
                {"last_result_snippet", s.last_result_snippet},
                {"last_run_at_ms",      s.last_run_at_ms},
                {"tasks_completed",     s.tasks_completed},
                {"tasks_failed",        s.tasks_failed}
            });
        }
        snap["agent_statuses"]    = status_arr;
        snap["agent_queue_depth"] = static_cast<int>(g_agents->queue_depth());
    } else {
        snap["agent_statuses"]    = json::array();
        snap["agent_queue_depth"] = 0;
    }

    return snap;
}

// ---------------------------------------------------------------------------
// Command dispatcher
// ---------------------------------------------------------------------------

static void dispatch(const json& msg)
{
    auto audit_adder = make_audit_adder();
    std::string cmd = msg.value("cmd", "");
    json args = msg.value("args", json::object());

    if (cmd == "ping") {
        emit({{"event", "pong"}});
        return;
    }

    if (cmd == "get_snapshot") {
        emit({{"event", "snapshot"}, {"data", build_snapshot()}});
        return;
    }

    if (cmd == "observe_signal") {
        int score = args.value("score", 0);
        std::string source = args.value("source", "elixir");
        auto result = g_threat->observe_signal(score, source);
        auto rule_r = g_rules->evaluate_threat_score(score, source);
        bool worm_fired = result.worm_triggered || rule_r.worm_triggered;
        if (worm_fired)
            g_worm->trigger_lockdown("threat_signal score=" + std::to_string(score));
        emit({{"event", "signal_result"}, {"data", {
            {"tier",           static_cast<int>(result.current_tier)},
            {"tier_changed",   result.tier_changed},
            {"worm_triggered", worm_fired},
            {"action",         result.response_description}
        }}});
        return;
    }

    if (cmd == "push_chaos") {
        double value     = args.value("value", 0.0);
        bool   synthetic = args.value("synthetic", true);
        g_chaos->push(value, synthetic);
        emit({{"event", "chaos_pushed"}, {"data", {{"value", value}}}});
        return;
    }

    if (cmd == "push_chaos_batch") {
        // Accept a JSON array of doubles, push all at once.
        // {"cmd":"push_chaos_batch","args":{"values":[0.5,0.76,...],"synthetic":true}}
        bool synthetic = args.value("synthetic", true);
        auto vals = args.value("values", json::array());
        int pushed = 0;
        for (const auto& v : vals) {
            if (v.is_number()) {
                g_chaos->push(v.get<double>(), synthetic);
                ++pushed;
            }
        }
        emit({{"event", "chaos_batch_pushed"}, {"data", {{"count", pushed}}}});
        return;
    }

    if (cmd == "worm_trigger") {
        std::string reason = args.value("reason", "manual");
        bool changed = g_worm->trigger_lockdown(reason);
        if (changed) {
            g_sandbox->lock_all("worm_lockdown");
            audit_adder("worm_trigger", "reason=" + reason);
            // Step 17: open a fresh voting session whenever lockdown is engaged
            if (g_unlock) g_unlock->begin_session();
            // Step 19: mirror lockdown to backup repo
            if (g_veeam) g_veeam->lock_backups(reason);
        }
        emit({{"event", "worm_status"}, {"data", {
            {"locked", g_worm->is_locked()},
            {"reason", g_worm->lock_reason()}
        }}});
        return;
    }

    // worm_unlock direct command is DISABLED (P0 security fix).
    // All unlock operations MUST go through the UnlockProtocol (unlock_vote).
    // This prevents a single actor bypassing the multi-party threshold check.
    if (cmd == "worm_unlock") {
        audit_adder("worm_unlock_rejected",
                    "reason=direct_unlock_disabled use_unlock_vote_instead");
        emit({{"event", "worm_status"}, {"data", {
            {"locked",  g_worm->is_locked()},
            {"reason",  g_worm->lock_reason()},
            {"error",   "Direct unlock disabled. Use unlock_vote with all required approvers."},
            {"hint",    "POST cmd=unlock_vote for each approver to reach threshold"}
        }}});
        return;
    }

    // -------------------------------------------------------------------
    // Step 19: veeam_integrity_check
    // {"cmd":"veeam_integrity_check"}
    // -------------------------------------------------------------------
    if (cmd == "veeam_integrity_check") {
        if (!g_veeam) {
            emit({{"event", "veeam_check_result"}, {"data", {
                {"error", "veeam_not_initialised"}
            }}});
            return;
        }
        auto r = g_veeam->integrity_check();
        emit({{"event", "veeam_check_result"}, {"data", {
            {"passed",          r.passed},
            {"checked_count",   r.checked_count},
            {"violations_found",r.violations_found},
            {"checked_at_ms",   r.checked_at_ms},
            {"audit_entry_id",  r.audit_entry_id}
        }}});
        return;
    }

    // -------------------------------------------------------------------
    // Step 19: veeam_status
    // {"cmd":"veeam_status"}
    // -------------------------------------------------------------------
    if (cmd == "veeam_status") {
        if (!g_veeam) {
            emit({{"event", "veeam_status"}, {"data", {
                {"error", "veeam_not_initialised"}
            }}});
            return;
        }
        auto vs = g_veeam->status();
        emit({{"event", "veeam_status"}, {"data", {
            {"lock_state",            VeeamIface::lock_state_str(vs.lock_state)},
            {"backup_count",          vs.backup_count},
            {"locked_at_ms",          vs.locked_at_ms},
            {"locked_by_reason",      vs.locked_by_reason},
            {"integrity_check_count", vs.integrity_check_count},
            {"last_check_ms",         vs.last_integrity_check_ms}
        }}});
        return;
    }

    if (cmd == "sandbox_get_tree") {
        json entries = json::array();
        for (const auto& e : g_sandbox->get_tree()) {
            entries.push_back({
                {"rel_path",      e.rel_path},
                {"type",          e.type == EntryType::FILE ? "file" : "dir"},
                {"size_bytes",    e.size_bytes},
                {"version",       e.version},
                {"locked",        e.locked},
                {"last_modified", e.last_modified}
            });
        }
        emit({{"event", "sandbox_tree"}, {"data", entries}});
        return;
    }

    if (cmd == "decoy_plant") {
        size_t count = g_decoy->plant();
        emit({{"event", "decoy_planted"}, {"data", {{"count", count}}}});
        return;
    }

    if (cmd == "decoy_touch") {
        std::string path    = args.value("path", "");
        std::string action  = args.value("action", "read");
        std::string session = args.value("session", "demo");
        std::string detail  = args.value("detail", "");
        bool hit = g_decoy->touch(path, action, session, detail);
        emit({{"event", "decoy_touch"}, {"data", {{"hit", hit}, {"path", path}}}});
        return;
    }

    if (cmd == "active_response_serve") {
        std::string session  = args.value("session", "demo");
        std::string resource = args.value("resource", "");
        std::string ioc_hint = args.value("ioc_hint", "");
        auto ev = g_ar->serve(session, resource, ioc_hint);
        emit({{"event", "ar_serve"}, {"data", {
            {"response_tier", ev.response_tier},
            {"ioc_match",     ev.ioc_match},
            {"ioc_indicator", ev.ioc_indicator}
        }}});
        return;
    }

    if (cmd == "run_demo") {
        // P1 fix: run_demo used to block the stdin thread for 3+ seconds.
        // Now it spawns a detached thread so the stdin loop stays responsive.
        audit_adder("demo_started", "pass=1");
        std::thread demo_thread([audit_adder]() {
            // FIX BUG-04-D: guard against shutdown — detached thread must not
            // access globals after they've been destroyed during process exit.
            // Escalate threat LOW -> CRIT
            for (int score : {30, 60, 85, 95}) {
                if (!g_running.load()) return;
                if (g_threat) g_threat->observe_signal(score, "demo");
                if (g_rules)  g_rules->evaluate_threat_score(score, "demo");
                std::this_thread::sleep_for(std::chrono::milliseconds(800));
            }

            // Push 64 logistic-map values (r=4, chaotic)
            double x = 0.7;
            for (int i = 0; i < 64; ++i) {
                x = 4.0 * x * (1.0 - x);
                g_chaos->push(x - 0.5, true);
                std::this_thread::sleep_for(std::chrono::milliseconds(25));
            }

            // Simulate decoy session
            g_decoy->plant();
            g_decoy->touch("decoy/credentials/.aws/credentials",
                            "read", "demo-atk", "demo");
            g_decoy->touch("decoy/assets/financial-projections-2024.xlsx",
                            "exfil_attempt", "demo-atk", "demo");
            g_ar->serve("demo-atk", "decoy/credentials/.aws/credentials", "185.220.101.1");

            // WORM lockdown
            g_worm->trigger_lockdown("demo_script");
            g_sandbox->lock_all("demo_worm");
            audit_adder("demo_completed", "pass=1");

            emit({{"event", "demo_done"}, {"data", {{"pass", 1}}}});
        });
        demo_thread.detach();
        emit({{"event", "demo_started_async"}, {"data", {{"pass", 1}}}});
        return;
    }

    if (cmd == "get_attribution") {
        std::string session = args.value("session", "demo-atk");
        Attribution reporter(g_sandbox_root, audit_adder);
        auto artifact = reporter.generate(
            session,
            g_decoy->forensic_log(),
            g_ar->forensic_log()
        );
        json techs = json::array();
        for (const auto& t : artifact.techniques) {
            techs.push_back({
                {"technique_id", t.technique_id},
                {"name",         t.name},
                {"tactic",       t.tactic},
                {"evidence",     t.evidence}
            });
        }
        emit({{"event", "attribution_report"}, {"data", {
            {"session_id",         artifact.session_id},
            {"total_interactions", artifact.total_interactions},
            {"summary",            artifact.summary},
            {"techniques",         techs}
        }}});
        return;
    }

    // -------------------------------------------------------------------
    // Step 16 ST-5: scan_and_quarantine
    // Scan a real file via clamd; if INFECTED quarantine it immediately.
    // {"cmd":"scan_and_quarantine","args":{"path":"C:\\..."}}
    // -------------------------------------------------------------------
    if (cmd == "scan_and_quarantine") {
        std::string path = args.value("path", "");
        if (path.empty()) {
            emit({{"event", "scan_quarantine_result"}, {"data", {
                {"status",      "error"},
                {"error",       "no path provided"}
            }}});
            return;
        }
        // FIX BUG-05-E: guard against null g_clamd
        if (!g_clamd) {
            emit({{"event", "scan_quarantine_result"}, {"data", {
                {"status",      "error"},
                {"error",       "clamd_not_available"}
            }}});
            return;
        }
        auto result = g_clamd->scan_file(path);
        bool quarantined = false;
        std::string qtn_path;
        std::string qtn_entry_id;

        if (result.status == astartis::clamd::ScanStatus::SCAN_INFECTED) {
            auto qe = g_qtn->quarantine_file(path, result.virus_name);
            quarantined  = !qe.entry_id.empty();
            qtn_path     = qe.quarantine_path;
            qtn_entry_id = qe.entry_id;
        }

        std::string status_str;
        switch (result.status) {
            case astartis::clamd::ScanStatus::SCAN_CLEAN:    status_str = "clean";    break;
            case astartis::clamd::ScanStatus::SCAN_INFECTED: status_str = "infected"; break;
            default:                                         status_str = "error";    break;
        }

        emit({{"event", "scan_quarantine_result"}, {"data", {
            {"status",         status_str},
            {"virus_name",     result.virus_name},
            {"quarantined",    quarantined},
            {"quarantine_path",qtn_path},
            {"entry_id",       qtn_entry_id},
            {"audit_entry_id", result.audit_entry_id}
        }}});
        return;
    }

    // -------------------------------------------------------------------
    // Step 16 ST-5: block_ip
    // {"cmd":"block_ip","args":{"ip":"240.0.0.1","ttl_s":900}}
    // -------------------------------------------------------------------
    if (cmd == "block_ip") {
        std::string ip  = args.value("ip", "");
        int         ttl = args.value("ttl_s", 0);
        if (ip.empty()) {
            emit({{"event", "block_ip_result"}, {"data", {
                {"blocked", false}, {"reason", "no ip provided"}
            }}});
            return;
        }
        // FIX BUG-05-F: guard against null g_firewall
        if (!g_firewall) {
            emit({{"event", "block_ip_result"}, {"data", {
                {"blocked", false}, {"reason", "firewall_not_available"}
            }}});
            return;
        }
        auto br = g_firewall->block(ip, ttl);
        emit({{"event", "block_ip_result"}, {"data", {
            {"blocked",       br.blocked},
            {"reason",        br.reason},
            {"rule_name_in",  br.rule_name_in},
            {"rule_name_out", br.rule_name_out}
        }}});
        return;
    }

    // -------------------------------------------------------------------
    // Step 16 ST-5: unblock_ip
    // {"cmd":"unblock_ip","args":{"ip":"240.0.0.1"}}
    // -------------------------------------------------------------------
    if (cmd == "unblock_ip") {
        std::string ip = args.value("ip", "");
        // FIX BUG-05-F: guard against null g_firewall
        bool ok = !ip.empty() && g_firewall && g_firewall->unblock(ip);
        emit({{"event", "unblock_ip_result"}, {"data", {
            {"unblocked", ok},
            {"ip",        ip}
        }}});
        return;
    }

    // -------------------------------------------------------------------
    // Step 17: unlock_vote
    // {"cmd":"unlock_vote","args":{"approver":"client-rep-1"}}
    // The bridge holds the Identity objects and calls make_signed_request
    // internally — the dashboard only needs to name the approver.
    // -------------------------------------------------------------------
    if (cmd == "unlock_vote") {
        std::string approver = args.value("approver", "");
        if (approver.empty() || !g_unlock) {
            emit({{"event", "unlock_vote_result"}, {"data", {
                {"accepted", false}, {"reason", "no_approver_or_protocol_not_ready"}
            }}});
            return;
        }
        // Look up the Identity for this approver name and sign the challenge.
        // Identities are stored in g_approver_identities (keyed by name).
        auto it = g_approver_identities.find(approver);
        if (it == g_approver_identities.end()) {
            emit({{"event", "unlock_vote_result"}, {"data", {
                    {"accepted", false}, {"reason", "unknown_approver_identity"}
            }}});
            return;
        }
        auto challenge = g_unlock->get_challenge(approver);
        if (challenge.empty()) {
            emit({{"event", "unlock_vote_result"}, {"data", {
                {"accepted", false}, {"reason", "no_challenge_or_already_voted"}
            }}});
            return;
        }
        auto signed_req = astartis::crypto::make_signed_request(*it->second.get(), challenge);
        auto vr = g_unlock->cast_vote(approver, signed_req);
        emit({{"event", "unlock_vote_result"}, {"data", {
            {"accepted",       vr.accepted},
            {"reason",         vr.reason},
            {"votes_now",      vr.votes_now},
            {"threshold",      vr.threshold},
            {"unlocked",       vr.unlocked}
        }}});
        return;
    }

    // -------------------------------------------------------------------
    // Step 17: get_unlock_status
    // -------------------------------------------------------------------
    if (cmd == "get_unlock_status") {
        auto snap = build_snapshot();
        emit({{"event", "unlock_status"}, {"data", {
            {"unlock_state",           snap["unlock_state"]},
            {"unlock_votes_collected", snap["unlock_votes_collected"]},
            {"unlock_threshold",       snap["unlock_threshold"]},
            {"unlock_approvers",       snap["unlock_approvers"]}
        }}});
        return;
    }

    // -------------------------------------------------------------------
    // Step 18: triage_event
    // {"cmd":"triage_event","args":{"event_type":"...","source":"...","score":N,"detail":"..."}}
    // Runs AI triage (fast tier + optional heavy tier) and returns result.
    // Exit code 2 pattern applies at the test level, not here.
    // -------------------------------------------------------------------
    if (cmd == "triage_event") {
        if (!g_ai_triage) {
            emit({{"event", "triage_result"}, {"data", {
                {"error", "ai_triage_not_initialised"}
            }}});
            return;
        }
        astartis::ai::TriageInput tin;
        tin.event_type = args.value("event_type", "unknown");
        tin.source     = args.value("source",     "bridge");
        tin.score      = args.value("score",       0);
        tin.raw_detail = args.value("detail",      "");
        // Truncate raw_detail to 200 chars as per spec
        if (tin.raw_detail.size() > 200)
            tin.raw_detail = tin.raw_detail.substr(0, 200);

        auto r = g_ai_triage->triage(tin);

        // Build a JSON snapshot of this result for the tick snapshot
        json rs;
        rs["event_type"]           = r.input.event_type;
        rs["score"]                = r.input.score;
        rs["fast_route"]           = r.fast.route;
        rs["fast_severity_hint"]   = r.fast.severity_hint;
        rs["fast_confidence"]      = r.fast.confidence;
        rs["fast_model"]           = r.fast.model_used;
        rs["fast_timed_out"]       = r.fast.timed_out;
        rs["model_suggested_tier"] = static_cast<int>(r.model_suggested_tier);
        rs["final_tier"]           = static_cast<int>(r.final_tier);
        rs["rule_engine_overrode"] = r.rule_engine_overrode;
        rs["audit_entry_id"]       = r.audit_entry_id;
        if (r.heavy.has_value()) {
            rs["heavy_severity"]   = r.heavy->severity;
            rs["heavy_rationale"]  = r.heavy->rationale;
            rs["heavy_mitre"]      = r.heavy->mitre_technique;
            rs["heavy_model"]      = r.heavy->model_used;
            rs["heavy_timed_out"]  = r.heavy->timed_out;
        }

        {
            std::lock_guard<std::mutex> lk(g_triage_snap_mutex);
            g_last_triage_snap = rs;
        }

        emit({{"event", "triage_result"}, {"data", rs}});
        return;
    }

    // -------------------------------------------------------------------
    // v2.0: agent_submit
    // Submit a task to a named agent persona.
    // {"cmd":"agent_submit","args":{"agent_name":"alert_triage","input":"...","priority":"normal"}}
    // priority: "high" | "normal" | "low"   (default: "normal")
    // Returns: {"event":"agent_submitted","data":{"task_id":"..."}} immediately.
    // Result arrives later as {"event":"agent_task_result","data":{...}}
    // -------------------------------------------------------------------
    if (cmd == "agent_submit") {
        if (!g_agents) {
            emit({{"event", "agent_submitted"}, {"data", {
                {"error", "agent_controller_not_initialised"}
            }}});
            return;
        }
        std::string agent_name = args.value("agent_name", "");
        std::string input      = args.value("input",      "");
        std::string prio_str   = args.value("priority",   "normal");

        if (agent_name.empty() || input.empty()) {
            emit({{"event", "agent_submitted"}, {"data", {
                {"error", "agent_name and input are required"}
            }}});
            return;
        }

        astartis::agents::Priority prio = astartis::agents::Priority::NORMAL;
        if (prio_str == "high") prio = astartis::agents::Priority::HIGH;
        if (prio_str == "low")  prio = astartis::agents::Priority::LOW;

        std::string task_id = g_agents->submit_task(agent_name, input, prio);
        if (task_id.empty()) {
            emit({{"event", "agent_submitted"}, {"data", {
                {"error", "unknown_agent"},
                {"agent_name", agent_name}
            }}});
        } else {
            audit_adder("agent_submit", "agent=" + agent_name + " task=" + task_id);
            emit({{"event", "agent_submitted"}, {"data", {
                {"task_id",    task_id},
                {"agent_name", agent_name},
                {"priority",   prio_str}
            }}});
        }
        return;
    }

    // -------------------------------------------------------------------
    // v2.0: agent_status
    // Get live status of all loaded agents.
    // {"cmd":"agent_status"}
    // Returns: {"event":"agent_status_update","data":{"agent_statuses":[...],"agent_queue_depth":N}}
    // -------------------------------------------------------------------
    if (cmd == "agent_status") {
        if (!g_agents) {
            emit({{"event", "agent_status_update"}, {"data", {
                {"agent_statuses",    json::array()},
                {"agent_queue_depth", 0},
                {"error",             "agent_controller_not_initialised"}
            }}});
            return;
        }
        auto statuses = g_agents->get_statuses();
        json status_arr = json::array();
        for (const auto& s : statuses) {
            std::string state_str;
            switch (s.state) {
                case astartis::agents::AgentState::IDLE:      state_str = "IDLE";      break;
                case astartis::agents::AgentState::RUNNING:   state_str = "RUNNING";   break;
                case astartis::agents::AgentState::COMPLETED: state_str = "COMPLETED"; break;
                case astartis::agents::AgentState::FAILED:    state_str = "FAILED";    break;
                default:                                       state_str = "IDLE";      break;
            }
            status_arr.push_back({
                {"name",                s.name},
                {"category",            s.category},
                {"state",               state_str},
                {"last_task_id",        s.last_task_id},
                {"last_result_snippet", s.last_result_snippet},
                {"last_run_at_ms",      s.last_run_at_ms},
                {"tasks_completed",     s.tasks_completed},
                {"tasks_failed",        s.tasks_failed}
            });
        }
        emit({{"event", "agent_status_update"}, {"data", {
            {"agent_statuses",    status_arr},
            {"agent_queue_depth", static_cast<int>(g_agents->queue_depth())}
        }}});
        return;
    }

    // -------------------------------------------------------------------
    // v2.1: network_get_ssids
    // Returns the three defined SSID configurations as JSON.
    // {"cmd":"network_get_ssids"}
    // -------------------------------------------------------------------
    if (cmd == "network_get_ssids") {
        using namespace astartis::network;
        auto pub  = make_public_ssid();
        auto ent  = make_enterprise_ssid();
        auto mgmt = make_management_ssid();

        auto ssid_to_json = [](const SSIDConfig& s) -> json {
            std::string posture_str;
            switch (s.posture) {
                case SecurityPosture::FILTERED_INTERNET: posture_str = "FILTERED_INTERNET"; break;
                case SecurityPosture::ZERO_TRUST:        posture_str = "ZERO_TRUST";        break;
                case SecurityPosture::MANAGEMENT:        posture_str = "MANAGEMENT";        break;
            }
            return json{
                {"ssid_name",               s.ssid_name},
                {"vlan_id",                 s.vlan_id},
                {"ip_subnet",               s.ip_subnet},
                {"gateway",                 s.gateway},
                {"posture",                 posture_str},
                {"client_isolation",        s.client_isolation},
                {"requires_8021x",          s.requires_8021x},
                {"captive_portal_url",      s.captive_portal_url},
                {"bandwidth_limit_mbps",    s.bandwidth_limit_mbps},
                {"session_timeout_minutes", s.session_timeout_minutes}
            };
        };

        emit({{"event", "network_ssids"}, {"data", {
            {"ssids", json::array({ssid_to_json(pub), ssid_to_json(ent), ssid_to_json(mgmt)})}
        }}});
        return;
    }

    // -------------------------------------------------------------------
    // v2.1: nac_simulate_device
    // Runs the 8-step NAC workflow simulation for a device + returns verbose steps.
    // {"cmd":"nac_simulate_device","args":{
    //     "device_mac":"11:22:33:44:55:66",
    //     "device_name":"IT-Laptop-001",
    //     "ssid_name":"eGov",
    //     "username":"kgosi.blanda",
    //     "domain":"egov.gov.bw",
    //     "os_updated":true,
    //     "antivirus_running":true,
    //     "disk_encrypted":true,
    //     "firewall_enabled":true
    // }}
    // -------------------------------------------------------------------
    if (cmd == "nac_simulate_device") {
        using namespace astartis::zerotrust;
        AccessRequest req;
        req.device_mac              = args.value("device_mac",  "00:00:00:00:00:00");
        req.device_name             = args.value("device_name", "Unknown-Device");
        req.ssid_name               = args.value("ssid_name",   "SmartBots");
        req.identity.username       = args.value("username",    "");
        req.identity.domain         = args.value("domain",      "");
        req.posture.os_updated      = args.value("os_updated",      false);
        req.posture.antivirus_running = args.value("antivirus_running", false);
        req.posture.disk_encrypted  = args.value("disk_encrypted",  false);
        req.posture.firewall_enabled= args.value("firewall_enabled", false);

        NACWorkflow nac;
        auto steps   = nac.process_verbose(req);
        auto decision= nac.process(req);

        // Map result enum to string
        auto result_str = [](NACDecision::Result r) -> std::string {
            switch (r) {
                case NACDecision::Result::ALLOW_FULL:    return "ALLOW_FULL";
                case NACDecision::Result::ALLOW_LIMITED: return "ALLOW_LIMITED";
                case NACDecision::Result::MFA_REQUIRED:  return "MFA_REQUIRED";
                case NACDecision::Result::QUARANTINE:    return "QUARANTINE";
                case NACDecision::Result::DENY:          return "DENY";
                default:                                  return "DENY";
            }
        };

        json steps_arr = json::array();
        int idx = 0;
        for (const auto& step : steps) {
            steps_arr.push_back({
                {"step",        idx + 1},
                {"passed",      step.passed},
                {"detail",      step.detail},
                {"duration_ms", step.duration_ms.count()}
            });
            ++idx;
        }

        json resources_arr = json::array();
        for (const auto& r : decision.accessible_resources)
            resources_arr.push_back(r);

        audit_adder("nac_simulate",
            "device=" + req.device_name +
            " ssid="  + req.ssid_name  +
            " user="  + req.identity.username +
            " result="+ result_str(decision.result));

        emit({{"event", "nac_result"}, {"data", {
            {"device_mac",           req.device_mac},
            {"device_name",          req.device_name},
            {"ssid_name",            req.ssid_name},
            {"result",               result_str(decision.result)},
            {"assigned_vlan",        decision.assigned_vlan},
            {"assigned_role",        decision.assigned_role},
            {"accessible_resources", resources_arr},
            {"remediation_reason",   decision.remediation_reason},
            {"reauth_interval_s",    decision.reauth_interval.count()},
            {"steps",                steps_arr}
        }}});
        return;
    }

    // -------------------------------------------------------------------
    // v2.1: zerotrust_evaluate
    // Evaluate a single access request through the Zero Trust engine.
    // {"cmd":"zerotrust_evaluate","args":{
    //     "user_id":"kgosi.blanda",
    //     "device_id":"IT-Laptop-001",
    //     "source_ip":"10.0.200.50",
    //     "destination_ip":"10.0.200.10",
    //     "requested_resource":"file-server",
    //     "ssid_name":"eGov"
    // }}
    // -------------------------------------------------------------------
    if (cmd == "zerotrust_evaluate") {
        using namespace astartis::zerotrust;
        AccessContext ctx;
        ctx.user_id            = args.value("user_id",            "unknown");
        ctx.device_id          = args.value("device_id",          "unknown");
        ctx.source_ip          = args.value("source_ip",          "0.0.0.0");
        ctx.destination_ip     = args.value("destination_ip",     "0.0.0.0");
        ctx.requested_resource = args.value("requested_resource", "");
        ctx.ssid_name          = args.value("ssid_name",          "SmartBots");

        // ZeroTrustEngine constructor requires audit_adder — wire through the bridge's lambda
        ZeroTrustEngine engine(
            [](const std::string& k, const std::string& v) -> std::string {
                // Forward to bridge audit system
                return k + ":" + v;
            }
        );

        int   score    = engine.calculate_trust_score(ctx);
        ctx.trust_score = score;
        auto  decision = engine.evaluate(ctx);

        audit_adder("zerotrust_evaluate",
            "user="     + ctx.user_id +
            " src="     + ctx.source_ip +
            " dst="     + ctx.destination_ip +
            " resource="+ ctx.requested_resource +
            " decision="+ ZeroTrustEngine::decision_str(decision));

        emit({{"event", "zerotrust_result"}, {"data", {
            {"user_id",            ctx.user_id},
            {"device_id",          ctx.device_id},
            {"source_ip",          ctx.source_ip},
            {"destination_ip",     ctx.destination_ip},
            {"requested_resource", ctx.requested_resource},
            {"ssid_name",          ctx.ssid_name},
            {"trust_score",        score},
            {"decision",           ZeroTrustEngine::decision_str(decision)}
        }}});
        return;
    }

    emit({{"event", "unknown_cmd"}, {"data", {{"cmd", cmd}}}});
}

// ---------------------------------------------------------------------------
// Chaos window callback
// ---------------------------------------------------------------------------

static void on_chaos_window(const ChaosWindow& w)
{
    // Feed into rule engine
    auto rr = g_rules->evaluate_chaos_window(w);
    if (rr.worm_triggered)
        g_worm->trigger_lockdown("RULE-05 chaos K=" + std::to_string(w.K));

    // Step 16 ST-5: emit firewall candidate when RULE-05 fires on real data.
    // Elixir calls block_ip after receiving this — rule engine keeps authority.
    if (rr.worm_triggered && !w.synthetic) {
        emit({{"event", "rule05_firewall_candidate"}, {"data", {
            {"K",         w.K},
            {"anomalous", w.anomalous},
            {"source_ip", ""}   // populated by packet sensor in a live capture
        }}});
    }

    // Update latest values for tick snapshot
    g_latest_K.store(w.K);
    g_latest_anomalous.store(w.anomalous);
    g_latest_chaos_windows.store(w.window_index + 1);

    // Maintain rolling history
    {
        std::lock_guard<std::mutex> lk(g_hist_mutex);
        g_chaos_history.push_back(w.K);
        if (g_chaos_history.size() > 100)
            g_chaos_history.erase(g_chaos_history.begin());
    }

    // Emit immediate chaos_window event
    emit({{"event", "chaos_window"}, {"data", {
        {"K",            w.K},
        {"anomalous",    w.anomalous},
        {"window_index", w.window_index},
        {"lambda1",      std::isnan(w.lambda1) ? json(nullptr) : json(w.lambda1)}
    }}});
}

// ---------------------------------------------------------------------------
// Tick thread
// ---------------------------------------------------------------------------

static void tick_loop()
{
    while (g_running.load()) {
        emit({{"event", "tick"}, {"data", build_snapshot()}});
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

// ---------------------------------------------------------------------------
// stdin reader thread
// ---------------------------------------------------------------------------

static void stdin_loop()
{
    std::string line;
    while (g_running.load() && std::getline(std::cin, line)) {
        // Strip trailing \r from Windows line endings (\r\n -> \n -> \r left by getline)
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        try {
            dispatch(json::parse(line));
        } catch (const std::exception& ex) {
            emit({{"event", "parse_error"}, {"data", {{"msg", ex.what()}}}});
        }
    }
    g_running.store(false);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Daemon mode helper
// ---------------------------------------------------------------------------
// When --daemon is passed, the process writes its PID to a file and redirects
// stderr to a log file so it can run detached from the console.
// Stdout stays connected to the Elixir port pipe — do NOT redirect it.
// ---------------------------------------------------------------------------

static bool g_daemon_mode = false;

static void enter_daemon_mode(const std::string& pid_file_path,
                               const std::string& log_file_path)
{
    // Write PID file
    try {
        std::ofstream pid_file(pid_file_path);
        if (pid_file) {
            pid_file << GetCurrentProcessId() << "\n";
        }
    } catch (...) { /* non-fatal */ }

    // Redirect stderr to log file (stdout stays on the port pipe)
    try {
        FILE* dummy = nullptr;
        freopen_s(&dummy, log_file_path.c_str(), "a", stderr);
        // If freopen_s fails, stderr stays on the console — not fatal
        (void)dummy;
    } catch (...) { /* non-fatal */ }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[])
{
    bool launch_protect   = false;
    bool launch_dashboard = false;

    // Parse CLI flags
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--daemon")    g_daemon_mode  = true;
        if (arg == "--protect")   launch_protect = true;
        if (arg == "--dashboard") launch_dashboard = true;
    }

    // Resolve the exe's own directory using GetModuleFileNameA — this is
    // CWD-independent so relative paths always resolve correctly regardless of
    // how the process was launched (from Bob, from a shell, or as a service).
    fs::path g_exe_dir;
    {
        char buf[MAX_PATH] = {};
        GetModuleFileNameA(nullptr, buf, MAX_PATH);
        g_exe_dir = fs::path(buf).parent_path();
    }

    // Unbuffered stdout so each JSON line arrives at Elixir immediately
    setvbuf(stdout, nullptr, _IONBF, 0);

    if (g_daemon_mode) {
        auto tmp = fs::temp_directory_path();
        enter_daemon_mode(
            (tmp / "astartis_bridge.pid").string(),
            (tmp / "astartis_bridge.log").string()
        );
    }

    // Check elevation before any threads start (ST-2 gate)
    g_is_elevated = check_elevation();

    // Sandbox in system temp
    g_sandbox_root = (fs::temp_directory_path() / "astartis_demo").string();
    fs::create_directories(g_sandbox_root);

    auto audit_adder = make_audit_adder();

    // -----------------------------------------------------------------------
    // Graceful degradation (P2 fix): wrap each subsystem in try/catch.
    // If a subsystem fails to construct, log the failure and continue in
    // degraded mode — the bridge still serves other subsystems.
    // The "ready" event lists which subsystems are available.
    // -----------------------------------------------------------------------

    std::vector<std::string> degraded_subsystems;

    auto try_init = [&](const char* name, std::function<void()> init_fn) {
        try {
            init_fn();
        } catch (const std::exception& ex) {
            std::string msg = std::string(name) + " init failed: " + ex.what();
            degraded_subsystems.push_back(msg);
            emit({{"event", "subsystem_degraded"}, {"data", {
                {"subsystem", name},
                {"reason",    ex.what()}
            }}});
        } catch (...) {
            degraded_subsystems.push_back(std::string(name) + " init failed: unknown exception");
            emit({{"event", "subsystem_degraded"}, {"data", {
                {"subsystem", name},
                {"reason",    "unknown exception"}
            }}});
        }
    };

    // Core WORM + Sandbox — most critical; if these fail, emit a hard error
    try_init("worm_lock", [&]() {
        g_worm = std::make_unique<WormLock>(audit_adder);
    });

    if (!g_worm) {
        emit({{"event", "fatal_error"}, {"data", {
            {"msg", "WormLock failed to initialise — bridge cannot start"}
        }}});
        return 1;
    }

    try_init("sandbox", [&]() {
        g_sandbox = std::make_unique<Sandbox>(
            g_sandbox_root, audit_adder,
            [&]() { return g_worm->is_locked(); }
        );
        g_sandbox->populate();
    });

    auto worm_trigger_fn = [&](const std::string& reason) {
        g_worm->trigger_lockdown(reason);
    };

    try_init("threat_level", [&]() {
        g_threat = std::make_unique<ThreatSM>(audit_adder, worm_trigger_fn);
    });

    // RuleEngine depends on ThreatSM — only init if threat is available
    if (g_threat) {
        try_init("rule_engine", [&]() {
            g_rules = std::make_unique<RuleEngine>(
                audit_adder,
                *g_threat,
                worm_trigger_fn,
                [&]() { return g_worm->is_locked(); }
            );
        });
    } else {
        degraded_subsystems.push_back("rule_engine skipped: threat_level unavailable");
    }

    try_init("chaos_detector", [&]() {
        g_chaos = std::make_unique<ChaosDetect>(
            on_chaos_window, audit_adder,
            16   // 16-sample window for demo: 40 pushes guarantees 2+ windows fire
        );
    });

    if (g_sandbox) {
        try_init("decoy", [&]() {
            g_decoy = std::make_unique<DecoyEnv>(*g_sandbox, audit_adder);
        });
    } else {
        degraded_subsystems.push_back("decoy skipped: sandbox unavailable");
    }

    try_init("active_response", [&]() {
        g_ar = std::make_unique<ActiveResp>(audit_adder);
    });

    try_init("clamd", [&]() {
        g_clamd = std::make_unique<ClamdScan>(audit_adder, "127.0.0.1", 3310);
    });

    try_init("quarantine", [&]() {
        std::string qtn_dir = g_is_elevated
            ? Quarantine::DEFAULT_DIR
            : (fs::temp_directory_path() / "astartis_quarantine").string();
        g_qtn = std::make_unique<Quarantine>(qtn_dir, audit_adder);
    });

    try_init("firewall", [&]() {
        g_firewall = std::make_unique<FwBlocker>(audit_adder);
    });

    // Step 17: 12-eye unlock protocol (DEMO-SCALE: 3 approvers stand in for 12)
    try_init("unlock_protocol", [&]() {
        g_tokens = std::make_unique<TokenStore>(audit_adder);

        constexpr int64_t TTL_24H = 24LL * 60 * 60 * 1000;
        g_approver_identities["astartis-admin-1"] =
            std::make_unique<astartis::crypto::Identity>("astartis-admin-1");
        g_approver_identities["client-rep-1"] =
            std::make_unique<astartis::crypto::Identity>("client-rep-1");
        g_approver_identities["client-rep-2"] =
            std::make_unique<astartis::crypto::Identity>("client-rep-2");

        auto t_ast = g_tokens->grant("astartis-admin-1", "worm_unlock_vote", TTL_24H);
        auto t_cl1 = g_tokens->grant("client-rep-1",     "worm_unlock_vote", TTL_24H);
        auto t_cl2 = g_tokens->grant("client-rep-2",     "worm_unlock_vote", TTL_24H);

        g_unlock = std::make_unique<UnlockProtocol>(
            audit_adder,
            *g_tokens,
            [&](const std::string& authority){ g_worm->unlock(authority); },
            UnlockProtocol::DEMO_THRESHOLD   // 3 — DEMO-SCALE STAND-IN for 12
        );
        g_unlock->register_approver("astartis-admin-1", ApproverSide::ASTARTIS,
            g_approver_identities["astartis-admin-1"]->public_key_der(), t_ast.token_id);
        g_unlock->register_approver("client-rep-1", ApproverSide::CLIENT,
            g_approver_identities["client-rep-1"]->public_key_der(), t_cl1.token_id);
        g_unlock->register_approver("client-rep-2", ApproverSide::CLIENT,
            g_approver_identities["client-rep-2"]->public_key_der(), t_cl2.token_id);
    });

    // Step 18: AI triage (advisory — rule engine retains final authority)
    if (g_rules) {
        try_init("ai_triage", [&]() {
            g_ai_triage = std::make_unique<AiTriage>(audit_adder, *g_rules);
        });
    } else {
        degraded_subsystems.push_back("ai_triage skipped: rule_engine unavailable");
    }

    // Step 19: Veeam / IBM Storage backup interface (stubbed for demo)
    try_init("veeam", [&]() {
        g_veeam = std::make_unique<VeeamIface>(audit_adder);
    });

    // v2.0: Agent swarm controller — loads all personas from agents/definitions/
    // Runs on local IBM Granite only; zero cloud API cost.
    try_init("agent_controller", [&]() {
        g_agents = std::make_unique<astartis::agents::AgentController>(audit_adder);

        // --- Load JSON personas (65 core agents) ---
        // Prefix with g_exe_dir so paths resolve correctly regardless of CWD.
        std::vector<fs::path> json_candidates = {
            g_exe_dir / "agents/definitions",
            g_exe_dir / "../agents/definitions",
            g_exe_dir / "../../agents/definitions",
            fs::path("agents/definitions"),
            fs::path("../agents/definitions"),
            fs::path("../../agents/definitions")
        };
        int loaded = 0;
        for (const auto& candidate : json_candidates) {
            if (fs::exists(candidate)) {
                loaded = g_agents->load_all_personas(candidate);
                if (loaded > 0) break;
            }
        }

        // --- Load ECC Markdown personas (12 specialist agents) ---
        std::vector<fs::path> ecc_candidates = {
            g_exe_dir / "agents/ecc/agents",
            g_exe_dir / "../agents/ecc/agents",
            g_exe_dir / "../../agents/ecc/agents",
            fs::path("agents/ecc/agents"),
            fs::path("../agents/ecc/agents"),
            fs::path("../../agents/ecc/agents")
        };
        int ecc_loaded = 0;
        for (const auto& candidate : ecc_candidates) {
            if (fs::exists(candidate)) {
                ecc_loaded = g_agents->load_ecc_personas(candidate);
                if (ecc_loaded > 0) break;
            }
        }
        loaded += ecc_loaded;

        audit_adder("agent_controller_ready",
                    "personas_loaded=" + std::to_string(loaded) +
                    " ecc_loaded=" + std::to_string(ecc_loaded));
        auto statuses = g_agents->get_statuses();
        json status_arr = json::array();
        for (const auto& s : statuses) {
            status_arr.push_back({
                {"name",     s.name},
                {"category", s.category},
                {"state",    "IDLE"},
                {"tasks_completed", 0},
                {"tasks_failed",    0},
                {"last_result_snippet", ""}
            });
        }
        emit({{"event", "agent_status_update"}, {"data", {
            {"agent_statuses",    status_arr},
            {"agent_queue_depth", 0},
            {"personas_loaded",   loaded}
        }}});
        g_agents->start();
    });

    // Build degraded list for the ready event
    json degraded_arr = json::array();
    for (const auto& msg : degraded_subsystems) degraded_arr.push_back(msg);

    // Announce readiness (includes elevation status — ST-2 gate)
    emit({{"event", "ready"}, {"data", {
        {"sandbox_root",        g_sandbox_root},
        {"chain_length",        g_audit.get_chain_length()},
        {"elevated",            g_is_elevated},
        {"daemon_mode",         g_daemon_mode},
        {"degraded_subsystems", degraded_arr}
    }}});

    // --dashboard: launch the IBM Carbon-styled dashboard on http://127.0.0.1:9876/
    if (launch_dashboard) {
        try_init("dashboard", [&]() {
            // Locate the dashboard/ directory by walking up from the exe (max 5 levels).
            fs::path exe_dir = fs::absolute(argv[0]).parent_path();
            fs::path dash_dir;
            for (int up = 0; up < 5; ++up) {
                fs::path candidate = exe_dir / "dashboard";
                if (fs::exists(candidate) && fs::is_directory(candidate)) {
                    dash_dir = candidate; break;
                }
                fs::path parent = exe_dir.parent_path();
                if (parent == exe_dir) break;
                exe_dir = parent;
            }
            if (dash_dir.empty()) dash_dir = fs::current_path() / "dashboard";
            fs::create_directories(dash_dir);

            std::string dash_str  = dash_dir.string();
            std::string data_path = (dash_dir / "dashboard_data.json").string();

            g_dashboard_writer = std::make_unique<astartis::dashboard::DashboardWriter>(dash_str);

            g_dashboard_writer->set_data_provider([&]() -> astartis::dashboard::DashboardData {
                astartis::dashboard::DashboardData data;
                // FIX BUG-06-A: reflect degraded mode in system_mode field
                data.system_mode = degraded_subsystems.empty() ? "FULL" : "DEGRADED";

                // Threat level
                if (g_threat) {
                    auto tier = g_threat->current_tier();
                    switch (tier) {
                        case astartis::threat::ThreatTier::LOW:      data.threat_level = "LOW";      data.threat_score = 10; break;
                        case astartis::threat::ThreatTier::MEDIUM:   data.threat_level = "MEDIUM";   data.threat_score = 45; break;
                        case astartis::threat::ThreatTier::HIGH:     data.threat_level = "HIGH";     data.threat_score = 75; break;
                        case astartis::threat::ThreatTier::CRITICAL: data.threat_level = "CRITICAL"; data.threat_score = 95; break;
                        default:                                      data.threat_level = "LOW";      data.threat_score = 0;  break;
                    }
                }

                // WORM
                if (g_worm) data.worm_is_locked = g_worm->is_locked();

                // Audit chain
                auto vr = g_audit.verify_chain();
                data.audit_chain_valid = vr.is_valid;

                // Agents
                if (g_agents) {
                    data.active_agents = static_cast<int>(g_agents->persona_count());
                    data.queue_depth   = static_cast<int>(g_agents->queue_depth());
                    auto statuses = g_agents->get_statuses();
                    for (const auto& s : statuses) {
                        astartis::dashboard::AgentStatus as;
                        as.name             = s.name;
                        as.tier             = s.category;  // map category → tier display
                        as.tasks_completed  = s.tasks_completed;
                        switch (s.state) {
                            case astartis::agents::AgentState::RUNNING:   as.status = "busy";   break;
                            case astartis::agents::AgentState::COMPLETED: as.status = "idle";   break;
                            case astartis::agents::AgentState::FAILED:    as.status = "error";  break;
                            default:                                       as.status = "idle";   break;
                        }
                        data.agents.push_back(as);
                    }
                }

                // Firewall blocks
                if (g_firewall) {
                    for (const auto& ab : g_firewall->active_blocks()) {
                        astartis::dashboard::FirewallBlockData f;
                        f.ip             = ab.ip;
                        f.rule_name_in   = ab.rule_name_in;
                        f.blocked_at_ms  = ab.blocked_at_ms;
                        f.expires_at_ms  = ab.expires_at_ms;
                        data.firewall_blocks.push_back(f);
                    }
                }

                // Quarantine
                if (g_qtn) {
                    for (const auto& qe : g_qtn->list()) {
                        astartis::dashboard::QuarantineEntryData q;
                        q.entry_id           = qe.entry_id;
                        q.virus_name         = qe.virus_name;
                        q.quarantined_at_ms  = qe.quarantined_at_ms;
                        data.quarantine_entries.push_back(q);
                    }
                }

                // Sandbox entries
                if (g_sandbox) {
                    for (const auto& e : g_sandbox->get_tree()) {
                        astartis::dashboard::SandboxEntryData sd;
                        sd.rel_path = e.rel_path;
                        sd.type     = (e.type == EntryType::FILE) ? "file" : "dir";
                        sd.locked   = e.locked;
                        sd.version  = e.version;
                        data.sandbox_entries.push_back(sd);
                    }
                }

                // Chaos history
                {
                    std::lock_guard<std::mutex> lk(g_hist_mutex);
                    for (size_t i = 0; i + 1 < g_chaos_history.size(); i += 2) {
                        astartis::dashboard::ChaosWindowData cw;
                        cw.K            = g_chaos_history[i];
                        cw.anomalous    = (cw.K > 0.7);
                        cw.window_index = i;
                        data.chaos_windows.push_back(cw);
                    }
                }

                // Audit chain entries (convert int64 ms timestamp to ISO string)
                {
                    auto entries = g_audit.get_all_entries();
                    auto chain_vr = g_audit.verify_chain();
                    for (const auto& ae : entries) {
                        astartis::dashboard::AuditEntryData ad;
                        ad.entry_id   = ae.entry_id;
                        ad.event_type = ae.event_type;
                        ad.chain_valid= chain_vr.is_valid;
                        // Convert ms timestamp to ISO 8601 string
                        time_t sec = static_cast<time_t>(ae.timestamp / 1000);
                        int    ms  = static_cast<int>(ae.timestamp % 1000);
                        tm utc_tm{};
                        gmtime_s(&utc_tm, &sec);
                        char tsbuf[32];
                        snprintf(tsbuf, sizeof(tsbuf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                            utc_tm.tm_year+1900, utc_tm.tm_mon+1, utc_tm.tm_mday,
                            utc_tm.tm_hour, utc_tm.tm_min, utc_tm.tm_sec, ms);
                        ad.timestamp = tsbuf;
                        data.audit_entries.push_back(ad);
                    }
                }

                // Decoy events
                if (g_decoy) {
                    for (const auto& de : g_decoy->forensic_log()) {
                        astartis::dashboard::DecoyEventData dd;
                        dd.attacker_tag = de.attacker_tag;
                        dd.poison_type  = astartis::decoy::poison_type_name(de.poison_type);
                        dd.action       = de.action;
                        dd.timestamp_ms = de.timestamp_ms;
                        data.decoy_events.push_back(dd);
                    }
                }

                // Zero Trust decisions from audit entries
                {
                    auto entries = g_audit.get_all_entries();
                    for (const auto& ae : entries) {
                        if (ae.event_type == "zerotrust_evaluate" || ae.event_type == "nac_simulate") {
                            astartis::dashboard::ZeroTrustDecisionData ztd;
                            auto extract = [&](const std::string& key) -> std::string {
                                auto pos = ae.payload.find(key + "=");
                                if (pos == std::string::npos) return "";
                                auto start = pos + key.size() + 1;
                                auto space = ae.payload.find(' ', start);
                                return ae.payload.substr(start, space == std::string::npos
                                    ? std::string::npos : space - start);
                            };
                            ztd.user_id    = extract("user");
                            ztd.decision   = extract("decision");
                            ztd.resource   = extract("resource");
                            ztd.trust_score= 0;
                            // FIX: populate timestamp from audit entry (was always missing)
                            time_t tsec = static_cast<time_t>(ae.timestamp / 1000);
                            int    tms  = static_cast<int>(ae.timestamp % 1000);
                            tm utc_ts{};
                            gmtime_s(&utc_ts, &tsec);
                            char tsbuf2[32];
                            snprintf(tsbuf2, sizeof(tsbuf2),
                                "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                                utc_ts.tm_year+1900, utc_ts.tm_mon+1, utc_ts.tm_mday,
                                utc_ts.tm_hour, utc_ts.tm_min, utc_ts.tm_sec, tms);
                            ztd.timestamp = tsbuf2;
                            if (!ztd.user_id.empty() && !ztd.decision.empty())
                                data.zerotrust_decisions.push_back(ztd);
                        }
                    }
                }

                // PDH rolling history
                {
                    std::lock_guard<std::mutex> lk(g_metrics_hist_mutex);
                    data.cpu_history  = g_cpu_history;
                    data.mem_history  = g_mem_history;
                    data.disk_history = g_disk_history;
                }

                // ---- Demo-mode seed (runs only when real data is absent) ----
                // When --protect is not passed PacketSensor / decoy plant never
                // run, so chaos_windows / entropy_windows / decoy_events /
                // zerotrust_decisions stay empty and every data-driven tab
                // shows "No data yet". Seed with realistic synthetic data so
                // the dashboard is demo-ready out of the box with just --dashboard.
                //
                // Entropy windows: 20 synthetic entropy readings (bits, 0..8)
                // that look like real Wi-Fi traffic with two anomalous bursts.
                if (data.entropy_windows.empty()) {
                    static const double eVals[] = {
                        4.12, 4.35, 4.67, 4.89, 5.02, 5.21, 5.43, 5.18, 4.96, 4.74,
                        4.55, 4.78, 4.91, 5.13, 6.82, 7.14, 5.88, 5.31, 4.99, 4.71
                    };
                    static const double eMax[] = {
                        4.98, 5.12, 5.43, 5.67, 5.81, 6.02, 6.24, 5.97, 5.73, 5.51,
                        5.32, 5.58, 5.74, 5.91, 7.44, 7.89, 6.65, 6.08, 5.76, 5.47
                    };
                    for (int i = 0; i < 20; ++i) {
                        astartis::dashboard::EntropyWindowData ew;
                        ew.mean_entropy_bits = eVals[i];
                        ew.max_entropy_bits  = eMax[i];
                        ew.anomalous    = (eVals[i] > 6.0);
                        ew.window_index = static_cast<uint64_t>(i);
                        data.entropy_windows.push_back(ew);
                    }
                }

                // Chaos windows: 20 synthetic K-values centred around 0.45,
                // with two anomalous spikes, to drive the chaos chart.
                if (data.chaos_windows.empty()) {
                    static const double kVals[] = {
                        0.31, 0.35, 0.38, 0.42, 0.45, 0.48, 0.51, 0.47, 0.44, 0.41,
                        0.38, 0.43, 0.46, 0.52, 0.78, 0.82, 0.55, 0.48, 0.44, 0.41
                    };
                    for (int i = 0; i < 20; ++i) {
                        astartis::dashboard::ChaosWindowData cw;
                        cw.K           = kVals[i];
                        cw.anomalous   = (kVals[i] > 0.7);
                        cw.window_index= static_cast<uint64_t>(i);
                        data.chaos_windows.push_back(cw);
                    }
                }

                // Decoy events: 8 synthetic interactions mapping to
                // different ATT&CK techniques so the ATT&CK tab populates.
                if (data.decoy_events.empty()) {
                    struct SyntheticDE { const char* tag; const char* ptype; const char* action; int64_t dms; };
                    static const SyntheticDE demos[] = {
                        { "attacker-0x1a",  "credential",     "read .env file",               -120000 },
                        { "attacker-0x1a",  "id_rsa",         "read private key",              -105000 },
                        { "attacker-0x2b",  "sysinfo",        "ran systeminfo",                 -90000 },
                        { "attacker-0x2b",  "/etc/passwd",    "read user list",                 -75000 },
                        { "attacker-0x3c",  "local_file",     "read documents folder",          -60000 },
                        { "attacker-0x3c",  "ssh_connect",    "lateral move via ssh",           -45000 },
                        { "attacker-0x4d",  "exfil",          "C2 upload attempted",            -30000 },
                        { "attacker-0x4d",  "renamed_binary", "masquerading as svchost",        -15000 },
                    };
                    FILETIME ft{}; GetSystemTimeAsFileTime(&ft);
                    ULARGE_INTEGER uli; uli.LowPart = ft.dwLowDateTime; uli.HighPart = ft.dwHighDateTime;
                    constexpr uint64_t EPOCH100 = 116444736000000000ULL;
                    int64_t now_ms = static_cast<int64_t>((uli.QuadPart - EPOCH100) / 10000);
                    for (const auto& dd : demos) {
                        astartis::dashboard::DecoyEventData dev;
                        dev.attacker_tag = dd.tag;
                        dev.poison_type  = dd.ptype;
                        dev.action       = dd.action;
                        dev.timestamp_ms = now_ms + dd.dms;
                        data.decoy_events.push_back(dev);
                    }
                }

                // Zero Trust decisions: 6 synthetic decisions to seed the
                // NIST / ZT donut and histogram without needing NAC simulation.
                if (data.zerotrust_decisions.empty()) {
                    struct SyntheticZT {
                        const char* user; const char* resource;
                        const char* decision; int score;
                        const char* ts;
                    };
                    static const SyntheticZT ztdemos[] = {
                        { "kgosi",    "/api/admin",   "ALLOW_FULL",    95, "2026-07-30T08:00:00.000Z" },
                        { "guest01",  "/api/report",  "ALLOW_LIMITED", 68, "2026-07-30T08:15:00.000Z" },
                        { "unknown",  "/api/keys",    "MFA_REQUIRED",  55, "2026-07-30T08:30:00.000Z" },
                        { "iot-01",   "/api/devices", "QUARANTINE",    30, "2026-07-30T09:00:00.000Z" },
                        { "scanner",  "/api/config",  "DENY",          12, "2026-07-30T09:15:00.000Z" },
                        { "kgosi",    "/api/report",  "ALLOW_FULL",    96, "2026-07-30T10:00:00.000Z" },
                    };
                    for (const auto& zt : ztdemos) {
                        astartis::dashboard::ZeroTrustDecisionData ztd;
                        ztd.user_id    = zt.user;
                        ztd.resource   = zt.resource;
                        ztd.decision   = zt.decision;
                        ztd.trust_score= zt.score;
                        ztd.timestamp  = zt.ts;
                        data.zerotrust_decisions.push_back(ztd);
                    }
                }
                // ---- End demo-mode seed ----

                return data;
            });

            g_dashboard_writer->start(3);  // write every 3 seconds

            g_dashboard_server = std::make_unique<astartis::dashboard::DashboardServer>(
                dash_str, data_path, 9876
            );
            g_dashboard_server->start();

            std::cerr << "[Dashboard] Serving at http://127.0.0.1:9876/\n";
            std::cerr << "[Dashboard] Auth token: " << g_dashboard_server->token() << "\n";

            // Open in default browser (best-effort, non-blocking)
            ShellExecuteA(nullptr, "open", "http://127.0.0.1:9876/", nullptr, nullptr, SW_SHOWNORMAL);
        });
    }

    // --protect: start all real-time protection monitors
    if (launch_protect) {
        std::cerr << "[Protect] Starting real-time protection monitors...\n";

        // 0. Plant decoy files so the sandbox is populated from the start.
        // This runs once at startup; the Dashboard "Plant Decoys" button can re-run it.
        if (g_decoy) {
            size_t planted = g_decoy->plant();
            audit_adder("decoy_plant_startup", "count=" + std::to_string(planted));
            std::cerr << "[Protect] Decoy files planted: " << planted << "\n";
        }

        // 1. Packet sensor — entropy → chaos detector
        try_init("packet_sensor_protect", [&]() {
            g_packet_sensor = std::make_unique<astartis::sensor::PacketSensor>(
                [&](const astartis::sensor::EntropyWindow& w) {
                    // Push entropy as a chaos signal
                    if (g_chaos) g_chaos->push(w.mean_entropy_bits / 8.0, w.synthetic);
                    // High-entropy traffic → threat signal
                    if (w.anomalous && g_threat)
                        g_threat->observe_signal(w.threat_score, "packet_entropy");
                },
                audit_adder
            );
            bool real = g_packet_sensor->start();
            std::cerr << "[Protect] PacketSensor started ("
                      << (real ? "REAL adapter: " + g_packet_sensor->adapter_name()
                               : "synthetic fallback")
                      << ")\n";
        });

        // 2. Windows Event Log monitor → observe_signal
        try_init("event_log_monitor", [&]() {
            g_event_log_monitor = std::make_unique<astartis::monitor::EventLogMonitor>(
                [&](const astartis::monitor::EventSignal& sig) {
                    // Feed into threat state machine
                    if (g_threat) g_threat->observe_signal(sig.score, sig.source);
                    if (g_rules)  g_rules->evaluate_threat_score(sig.score, sig.source);
                    // Push into autonomy loop for agent analysis
                    if (g_autonomy_loop) {
                        astartis::autonomy::PendingSignal ps;
                        ps.source       = sig.source;
                        ps.score        = sig.score;
                        ps.description  = sig.description;
                        ps.timestamp_ms = sig.timestamp_ms;
                        g_autonomy_loop->push_signal(std::move(ps));
                    }
                    audit_adder("event_log_signal",
                        "id=" + std::to_string(sig.event_id) +
                        " score=" + std::to_string(sig.score) +
                        " src=" + sig.source);
                    std::cerr << "[Protect] EventLog: " << sig.description
                              << " (score=" << sig.score << ")\n";
                }
            );
            bool ok = g_event_log_monitor->start();
            if (!ok) throw std::runtime_error("EvtSubscribe failed — run as Administrator");
        });

        // 3. File system monitor → scan_and_quarantine on executable drops
        try_init("fs_monitor", [&]() {
            g_fs_monitor = std::make_unique<astartis::monitor::FsMonitor>(
                [&](const astartis::monitor::FsEvent& ev) {
                    std::cerr << "[Protect] FsEvent: " << ev.path << "\n";

                    // Scan the file with ClamAV
                    if (g_clamd) {
                        auto result = g_clamd->scan_file(ev.path);
                        if (result.status == astartis::clamd::ScanStatus::SCAN_INFECTED) {
                            std::cerr << "[Protect] INFECTED: " << ev.path
                                      << " (" << result.virus_name << ")\n";
                            if (g_qtn) g_qtn->quarantine_file(ev.path, result.virus_name);
                            if (g_threat) g_threat->observe_signal(90, "clamd_infected_file");
                            if (g_autonomy_loop) {
                                astartis::autonomy::PendingSignal ps;
                                ps.source      = "fs_monitor/infected";
                                ps.score       = 90;
                                ps.description = "Infected file detected: " + ev.filename
                                                 + " (" + result.virus_name + ")";
                                ps.timestamp_ms = ev.timestamp_ms;
                                g_autonomy_loop->push_signal(std::move(ps));
                            }
                        }
                    }

                    // High-risk extensions always trigger a threat signal even without clamd
                    static const std::vector<std::string> hi_risk = {
                        ".exe", ".dll", ".bat", ".ps1", ".vbs", ".scr", ".com", ".pif"
                    };
                    auto ext = ev.extension;
                    if (std::find(hi_risk.begin(), hi_risk.end(), ext) != hi_risk.end()) {
                        if (g_threat) g_threat->observe_signal(35, "fs_monitor/hi_risk_drop");
                    }
                }
            );
            // Watch executable and script drops — broaden to all files when clamd is available
            if (!g_clamd) {
                g_fs_monitor->set_extension_filter({
                    ".exe", ".dll", ".bat", ".ps1", ".vbs", ".scr", ".com", ".pif",
                    ".js", ".jar", ".msi", ".hta", ".wsf"
                });
            }
            g_fs_monitor->start();
            std::cerr << "[Protect] FsMonitor started\n";
        });

        // 4. Autonomy loop — agents wake up and act without operator commands
        try_init("autonomy_loop", [&]() {
            if (!g_agents) throw std::runtime_error("agent_controller not available");
            g_autonomy_loop = std::make_unique<astartis::autonomy::AutonomyLoop>(
                g_agents.get(), audit_adder, 30  // tick every 30 seconds
            );
            g_autonomy_loop->start();
            std::cerr << "[Protect] AutonomyLoop started (30s interval)\n";
        });

        // Wire threat level changes into the autonomy loop
        // (done after autonomy loop is started so the pointer is valid)
        // The threat SM already calls g_rules; we hook via rule engine callback
        // by checking periodically in the autonomy tick — no extra wiring needed.

        emit({{"event", "protect_started"}, {"data", {
            {"packet_sensor",    g_packet_sensor    ? true : false},
            {"event_log",        g_event_log_monitor? true : false},
            {"fs_monitor",       g_fs_monitor       ? true : false},
            {"autonomy_loop",    g_autonomy_loop    ? true : false},
        }}});
        std::cerr << "[Protect] All protection monitors active.\n";
    }

    // Start threads
    std::thread tick_th(tick_loop);
    std::thread stdin_th(stdin_loop);

    stdin_th.join();
    g_running.store(false);
    tick_th.join();
    // Shutdown protection monitors cleanly before globals destruct
    if (g_autonomy_loop)     g_autonomy_loop->stop();
    if (g_fs_monitor)        g_fs_monitor->stop();
    if (g_event_log_monitor) g_event_log_monitor->stop();
    if (g_packet_sensor)     g_packet_sensor->stop();
    // Shutdown dashboard
    if (g_dashboard_server)  g_dashboard_server->stop();
    if (g_dashboard_writer)  g_dashboard_writer->stop();
    // All unique_ptr globals are destroyed automatically at program exit.
    // No manual delete needed — that's the whole point of RAII.
    return 0;
}

// Made with Bob
