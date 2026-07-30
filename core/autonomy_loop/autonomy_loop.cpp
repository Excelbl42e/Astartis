// autonomy_loop.cpp — Autonomous agent dispatch loop implementation

#include "autonomy_loop.h"
#include "agents/controller/agent_controller.h"

#include <iostream>
#include <sstream>
#include <chrono>
#include <algorithm>

namespace astartis {
namespace autonomy {

// ---------------------------------------------------------------------------
// SOC rotation table — these agents run unsupervised on schedule
// ---------------------------------------------------------------------------

const std::vector<std::string> AutonomyLoop::k_soc_rotation = {
    "threat_hunter",
    "siem_analyst",
    "alert_triage",
    "incident_responder",
    "ioc_manager",
    "forensics_investigator",
    "compliance_monitor",
    "vulnerability_mgr",
    "insider_threat_detector",
    "ransomware_hunter",
};

// ---------------------------------------------------------------------------
// Constructor / Destructor
// ---------------------------------------------------------------------------

AutonomyLoop::AutonomyLoop(agents::AgentController* controller,
                           AuditAdder               audit_adder,
                           int                      interval_seconds)
    : controller_(controller)
    , audit_adder_(std::move(audit_adder))
    , interval_seconds_(interval_seconds)
{}

AutonomyLoop::~AutonomyLoop() { stop(); }

// ---------------------------------------------------------------------------
// start / stop
// ---------------------------------------------------------------------------

void AutonomyLoop::start()
{
    if (running_.exchange(true)) return;
    thread_ = std::thread([this]() { loop(); });
    std::cerr << "[AutonomyLoop] Started, interval=" << interval_seconds_ << "s\n";
}

void AutonomyLoop::stop()
{
    if (!running_.exchange(false)) return;
    if (thread_.joinable()) thread_.join();
    std::cerr << "[AutonomyLoop] Stopped, tasks_submitted=" << tasks_submitted_.load() << "\n";
}

// ---------------------------------------------------------------------------
// push_signal / notify_threat_level (thread-safe inbound)
// ---------------------------------------------------------------------------

void AutonomyLoop::push_signal(PendingSignal signal)
{
    std::lock_guard<std::mutex> lk(signals_mutex_);
    pending_signals_.push_back(std::move(signal));
    // Ring buffer — keep last 100
    while (pending_signals_.size() > 100)
        pending_signals_.pop_front();
}

void AutonomyLoop::notify_threat_level(const std::string& level, int score)
{
    std::lock_guard<std::mutex> lk(threat_mutex_);
    current_threat_level_ = level;
    current_threat_score_ = score;
}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

void AutonomyLoop::loop()
{
    while (running_.load()) {
        tick_threat_response();
        tick_signal_drain();
        tick_soc_rotation();

        audit_adder_("autonomy_tick",
            "tasks_submitted=" + std::to_string(tasks_submitted_.load()));

        // Sleep in 500ms increments so stop() returns quickly
        int steps = interval_seconds_ * 2;
        for (int i = 0; i < steps && running_.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

// ---------------------------------------------------------------------------
// Tick 1: threat-driven response
// ---------------------------------------------------------------------------

void AutonomyLoop::tick_threat_response()
{
    if (!controller_) return;

    std::string level;
    int score = 0;
    {
        std::lock_guard<std::mutex> lk(threat_mutex_);
        level = current_threat_level_;
        score = current_threat_score_;
    }

    if (level == "CRITICAL" || level == "HIGH") {
        // Submit high-priority tasks to incident response agents
        static const std::vector<std::string> response_agents = {
            "incident_responder", "threat_hunter", "forensics_investigator"
        };
        for (const auto& agent : response_agents) {
            std::string input = "AUTONOMOUS ALERT: System threat level is " + level +
                " (score=" + std::to_string(score) + "). "
                "Perform immediate assessment. Check for active intrusion, "
                "suspicious processes, lateral movement indicators. "
                "Recommend specific containment actions.";

            auto task_id = controller_->submit_task(
                agent, input, agents::Priority::HIGH);

            if (!task_id.empty()) {
                ++tasks_submitted_;
                std::cerr << "[AutonomyLoop] HIGH priority task -> " << agent
                          << " task=" << task_id << "\n";
            }
        }
    } else if (level == "MEDIUM") {
        // Medium threat — lighter triage
        auto task_id = controller_->submit_task(
            "alert_triage",
            "AUTONOMOUS: Threat level elevated to MEDIUM (score=" +
            std::to_string(score) + "). Analyse recent event patterns. "
            "Identify false positives vs real threats.",
            agents::Priority::NORMAL
        );
        if (!task_id.empty()) ++tasks_submitted_;
    }
}

// ---------------------------------------------------------------------------
// Tick 2: drain pending signals from EventLogMonitor / FsMonitor
// ---------------------------------------------------------------------------

void AutonomyLoop::tick_signal_drain()
{
    if (!controller_) return;

    std::vector<PendingSignal> batch;
    {
        std::lock_guard<std::mutex> lk(signals_mutex_);
        if (pending_signals_.empty()) return;
        // Drain up to 20 signals per tick
        size_t take = std::min(pending_signals_.size(), size_t(20));
        batch.assign(pending_signals_.begin(),
                     pending_signals_.begin() + static_cast<ptrdiff_t>(take));
        pending_signals_.erase(pending_signals_.begin(),
                               pending_signals_.begin() + static_cast<ptrdiff_t>(take));
    }

    // Build a summary string for the agent
    std::ostringstream oss;
    oss << "AUTONOMOUS: " << batch.size() << " security signals received:\n";
    int max_score = 0;
    for (const auto& s : batch) {
        oss << "  [score=" << s.score << "] " << s.source << ": " << s.description << "\n";
        max_score = std::max(max_score, s.score);
    }
    oss << "Analyse these signals. Identify attack patterns, false positives, "
        << "and recommended actions (block IP, quarantine file, escalate).";

    // Route to appropriate agent based on max score
    std::string agent = (max_score >= 60) ? "incident_responder"
                      : (max_score >= 40) ? "alert_triage"
                      :                     "siem_analyst";

    agents::Priority prio = (max_score >= 60) ? agents::Priority::HIGH
                          : (max_score >= 40) ? agents::Priority::NORMAL
                          :                     agents::Priority::LOW;

    auto task_id = controller_->submit_task(agent, oss.str(), prio);
    if (!task_id.empty()) {
        ++tasks_submitted_;
        std::cerr << "[AutonomyLoop] Signal batch (" << batch.size() << " signals) -> "
                  << agent << " task=" << task_id << "\n";
    }
}

// ---------------------------------------------------------------------------
// Tick 3: SOC rotation — one agent per tick does a routine check
// ---------------------------------------------------------------------------

void AutonomyLoop::tick_soc_rotation()
{
    if (!controller_ || k_soc_rotation.empty()) return;

    const std::string& agent = k_soc_rotation[soc_rotation_index_ % k_soc_rotation.size()];
    ++soc_rotation_index_;

    std::string input =
        "AUTONOMOUS ROUTINE CHECK: Perform a standard health and threat assessment. "
        "Review any recent anomalies in your domain. "
        "Report status: GREEN (normal), AMBER (watch), or RED (action required). "
        "Keep response under 100 words.";

    auto task_id = controller_->submit_task(agent, input, agents::Priority::LOW);
    if (!task_id.empty()) {
        ++tasks_submitted_;
        std::cerr << "[AutonomyLoop] Routine check -> " << agent
                  << " task=" << task_id << "\n";
    }
}

} // namespace autonomy
} // namespace astartis

// Made with Bob
