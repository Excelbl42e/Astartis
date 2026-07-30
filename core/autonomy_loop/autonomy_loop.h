// autonomy_loop.h — Autonomous agent dispatch loop (Astartis v3.1)
//
// Runs a background thread that wakes up on a configurable interval and
// submits self-directed tasks to the agent swarm based on the current
// system state.  This is what makes the agents actually autonomous rather
// than waiting for operator commands.
//
// Per tick, it:
//   1. Checks threat level — if HIGH/CRITICAL, submits high-priority triage tasks
//   2. Drains the recent_signals ring buffer — one task per signal batch
//   3. Runs the SOC rotation — each SOC agent gets a routine health-check turn
//   4. Emits a heartbeat audit entry

#ifndef ASTARTIS_AUTONOMY_LOOP_H
#define ASTARTIS_AUTONOMY_LOOP_H

#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <thread>
#include <atomic>
#include <functional>
#include <cstdint>
#include <memory>

// Forward declare — avoid pulling all agent headers into everything
namespace astartis { namespace agents { class AgentController; enum class Priority : int; } }

namespace astartis {
namespace autonomy {

// A recent security signal buffered for agent analysis
struct PendingSignal {
    std::string source;
    int         score;
    std::string description;
    int64_t     timestamp_ms;
};

class AutonomyLoop {
public:
    using AuditAdder = std::function<std::string(const std::string&, const std::string&)>;

    // agent_controller: the swarm to submit tasks to
    // audit_adder: wired to AuditChain::add_entry
    // interval_seconds: how often the loop ticks (default 30s)
    explicit AutonomyLoop(
        agents::AgentController* agent_controller,
        AuditAdder               audit_adder,
        int                      interval_seconds = 30
    );

    ~AutonomyLoop();

    AutonomyLoop(const AutonomyLoop&)            = delete;
    AutonomyLoop& operator=(const AutonomyLoop&) = delete;

    void start();
    void stop();

    bool is_running() const { return running_.load(); }

    // Push a signal into the pending buffer (thread-safe).
    // Called by EventLogMonitor and FsMonitor callbacks.
    void push_signal(PendingSignal signal);

    // Called by the bridge's threat state machine when tier changes.
    void notify_threat_level(const std::string& level, int score);

    // Total autonomous tasks submitted since start().
    uint64_t tasks_submitted() const { return tasks_submitted_.load(); }

private:
    void loop();
    void tick_threat_response();
    void tick_signal_drain();
    void tick_soc_rotation();

    agents::AgentController* controller_;
    AuditAdder               audit_adder_;
    int                      interval_seconds_;

    std::thread              thread_;
    std::atomic<bool>        running_{false};

    // Pending signals ring (max 100)
    mutable std::mutex       signals_mutex_;
    std::deque<PendingSignal> pending_signals_;

    // Current threat state
    mutable std::mutex       threat_mutex_;
    std::string              current_threat_level_{"LOW"};
    int                      current_threat_score_{0};

    // SOC rotation state — which agent is next in the round-robin
    size_t soc_rotation_index_{0};

    std::atomic<uint64_t> tasks_submitted_{0};

    // SOC agents that run autonomously on rotation
    static const std::vector<std::string> k_soc_rotation;
};

} // namespace autonomy
} // namespace astartis

#endif // ASTARTIS_AUTONOMY_LOOP_H

// Made with Bob
