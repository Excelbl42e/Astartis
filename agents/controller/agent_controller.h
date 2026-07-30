// agent_controller.h -- 75+ autonomous agent swarm controller (Astartis v3.0)
//
// Loads persona JSON definitions, manages a priority task queue, and dispatches
// tasks to the correct Granite model tier.  All agents run on local IBM Granite
// — no cloud APIs, no external dependencies.
//
// Architecture:
//   - Two models in Ollama (MoE 3B fast + Dense 8B heavy) stay loaded.
//   - Each "agent" is a JSON persona file that sets the system prompt + skills.
//   - The controller swaps the system prompt per task (no separate binary per agent).
//   - Tasks run on a configurable pool of worker threads (default 4).

#ifndef ASTARTIS_AGENT_CONTROLLER_H
#define ASTARTIS_AGENT_CONTROLLER_H

#include <string>
#include <vector>
#include <map>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <functional>
#include <filesystem>
#include <atomic>
#include <memory>
#include <cstddef>

#include "agents/controller/granite_client.h"

// Forward-declare ActionDispatcher to avoid pulling all protection headers
// into every translation unit that includes agent_controller.h.
namespace astartis { class ActionDispatcher; }

namespace astartis {
namespace agents {

// ---------------------------------------------------------------------------
// AgentPersona — loaded from a JSON definition file
// ---------------------------------------------------------------------------

struct AgentPersona {
    std::string              name;
    std::string              description;
    std::string              category;        ///< "pen_test" | "se_team" | "soc"
    GraniteModel             preferred_model; ///< FAST or HEAVY
    std::string              system_prompt;
    std::vector<std::string> skills;
    int                      max_tokens   = 512;
    double                   temperature  = 0.2;
    std::string              input_schema;
    std::string              output_schema;
};

// ---------------------------------------------------------------------------
// Task priority
// ---------------------------------------------------------------------------

enum class Priority : int { HIGH = 0, NORMAL = 1, LOW = 2 };

// ---------------------------------------------------------------------------
// Task entry in the queue
// ---------------------------------------------------------------------------

struct TaskEntry {
    std::string task_id;
    std::string agent_name;
    std::string input;
    Priority    priority;
    int64_t     enqueued_at_ms;

    bool operator>(const TaskEntry& o) const {
        // Lower priority value = higher urgency
        return static_cast<int>(priority) > static_cast<int>(o.priority);
    }
};

// ---------------------------------------------------------------------------
// Task result
// ---------------------------------------------------------------------------

struct TaskResult {
    std::string task_id;
    std::string agent_name;
    bool        ok;
    std::string output;
    std::string model_used;
    int64_t     completed_at_ms;
    // Phase 2B: action dispatch result
    bool        action_taken   = false;
    std::string action_type;
    std::string action_target;
};

// ---------------------------------------------------------------------------
// Memory snapshot — estimated in-process RAM usage of the controller
// ---------------------------------------------------------------------------
struct MemorySnapshot {
    std::size_t personas_bytes;    ///< approx bytes used by persona map
    std::size_t queue_bytes;       ///< approx bytes used by task queue
    std::size_t statuses_bytes;    ///< approx bytes used by status map
    std::size_t total_estimated_mb;///< rough total in MB
};

// ---------------------------------------------------------------------------
// Agent status (for dashboard)
// ---------------------------------------------------------------------------

enum class AgentState { IDLE, RUNNING, COMPLETED, FAILED };

struct AgentStatus {
    std::string name;
    std::string category;
    std::string tier;                 ///< "FAST" | "HEAVY" | "ACCURACY" | "ORCHESTRATOR"
    AgentState  state;
    std::string last_task_id;
    std::string last_result_snippet;  ///< first 100 chars of last output
    int64_t     last_run_at_ms;
    int         tasks_completed;
    int         tasks_failed;
    std::string last_active;          ///< ISO 8601 timestamp of last run
};

// ---------------------------------------------------------------------------
// AgentController
// ---------------------------------------------------------------------------

class AgentController {
public:
    explicit AgentController(
        std::function<std::string(const std::string&, const std::string&)> audit_adder,
        const std::string& ollama_host  = GraniteClient::DEFAULT_HOST,
        uint16_t           ollama_port  = GraniteClient::DEFAULT_PORT,
        int                worker_count = 4
    );

    ~AgentController();

    AgentController(const AgentController&)            = delete;
    AgentController& operator=(const AgentController&) = delete;

    // Load a single persona from a JSON file. Returns false if invalid.
    bool load_persona(const std::filesystem::path& json_path);

    // Load all *.json files from a directory. Returns count loaded.
    int load_all_personas(const std::filesystem::path& defs_dir);

    // Load *.json personas filtered by an optional demo-mode config file.
    // config_path: path to a JSON file with "agent_allowlist": [...] array.
    // If config_path is empty or file doesn't exist, loads all (same as above).
    int load_all_personas(const std::filesystem::path& defs_dir,
                          const std::filesystem::path& config_path);

    // Load all ECC *.md agent files from a directory. Returns count loaded.
    int load_ecc_personas(const std::filesystem::path& ecc_agents_dir);

    // Set a callback that fires when ANY worker completes a task.
    // The callback is called from the worker thread — must be thread-safe.
    void set_task_completed_callback(std::function<void(const TaskResult&)> callback);

    // Submit a task. Returns task_id (UUID-style string). Thread-safe.
    std::string submit_task(const std::string& agent_name,
                            const std::string& input,
                            Priority           priority = Priority::NORMAL);

    // Start the worker thread.
    void start();

    // Stop the worker thread and drain the queue.
    void stop();

    // Snapshot of all agent statuses (for dashboard).
    std::vector<AgentStatus> get_statuses() const;

    // Number of tasks currently waiting in queue.
    std::size_t queue_depth() const;

    // Total personas loaded.
    std::size_t persona_count() const;

    // Estimate in-process RAM usage of the controller data structures.
    MemorySnapshot get_memory_usage() const;

    bool is_running() const { return running_.load(); }

    // Inject an ActionDispatcher to enable auto-dispatch after inference.
    // Pass nullptr to disable (advisory-only mode — default for tests).
    // The dispatcher must outlive this AgentController.
    void set_action_dispatcher(ActionDispatcher* dispatcher) {
        action_dispatcher_ = dispatcher;
    }

private:
    void worker_loop();
    TaskResult execute_task(const TaskEntry& entry);

    std::unique_ptr<GraniteClient>                          granite_;
    std::atomic<uint64_t>                                   tasks_since_last_mem_log_{0};
    // S3.4: cached persona byte estimate updated at load time, read lock-free on hot path
    std::atomic<std::size_t>                                cached_personas_bytes_{0};
    ActionDispatcher*                                       action_dispatcher_{nullptr};
    std::map<std::string, AgentPersona>                     personas_;
    std::map<std::string, AgentStatus>                      statuses_;
    std::priority_queue<TaskEntry,
                        std::vector<TaskEntry>,
                        std::greater<TaskEntry>>             queue_;
    mutable std::mutex                                       mutex_;
    std::condition_variable                                  cv_;
    std::vector<std::thread>                                 workers_;
    int                                                      worker_count_;
    std::atomic<bool>                                        running_{false};
    std::function<std::string(const std::string&, const std::string&)> audit_adder_;
    uint64_t                                                 next_task_id_{1};
    std::function<void(const TaskResult&)>                   task_completed_callback_;
};

} // namespace agents
} // namespace astartis

#endif // ASTARTIS_AGENT_CONTROLLER_H

// Made with Bob
