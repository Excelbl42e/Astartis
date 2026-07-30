// agent_controller.cpp -- Agent swarm controller implementation (Astartis v3.0)

// Windows headers first — needed for GetModuleFileNameA, MAX_PATH
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#pragma warning(push)
#pragma warning(disable: 4706 4127 4244)
#include "nlohmann/json.hpp"
#pragma warning(pop)

#include "agents/controller/agent_controller.h"
#include "agents/controller/persona_loader.h"
#include "agents/ecc/ecc_adapter.h"
#include "agents/controller/action_dispatcher.h"

#include <fstream>
#include <sstream>
#include <chrono>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <iostream>

using json = nlohmann::json;

namespace astartis {
namespace agents {

namespace {
    int64_t now_ms() {
        using namespace std::chrono;
        return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    }

    // Convert GraniteModel enum to the tier string used in dashboard/API
    const char* model_to_tier(GraniteModel m) {
        switch (m) {
            case GraniteModel::FAST:         return "FAST";
            case GraniteModel::HEAVY:        return "HEAVY";
            case GraniteModel::ACCURACY:     return "ACCURACY";
            case GraniteModel::ORCHESTRATOR: return "ORCHESTRATOR";
            default:                         return "HEAVY";
        }
    }

    // ISO 8601 UTC timestamp string for "now"
    std::string iso_now() {
        using namespace std::chrono;
        auto t = system_clock::to_time_t(system_clock::now());
        std::tm tm{};
        gmtime_s(&tm, &t);
        char buf[32]{};
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
        return buf;
    }
}

// ---------------------------------------------------------------------------
// Skill fragment cache — loads prompt_fragment from agents/skills/<name>.json
// on first use and caches it in-process.
// S3.3 fix: resolve skill dirs relative to the executable's own path, not CWD.
// Falls back to the bare skill name if the file is not found.
// ---------------------------------------------------------------------------
namespace {
    std::mutex skill_cache_mutex;
    std::unordered_map<std::string, std::string> skill_cache;

    // Returns the executable's parent directory (e.g. build/Release/).
    // Used to locate agents/skills/ regardless of CWD (important for --daemon mode).
    static std::filesystem::path exe_dir() {
        char buf[MAX_PATH] = {};
        GetModuleFileNameA(nullptr, buf, MAX_PATH);
        return std::filesystem::path(buf).parent_path();
    }

    // Build skill search dirs relative to the exe path, then fall back to CWD paths.
    static std::vector<std::filesystem::path> make_skill_search_dirs() {
        auto base = exe_dir();
        return {
            // Walk up from build/Release → project root → agents/skills
            base / "agents" / "skills",
            base / ".." / "agents" / "skills",
            base / ".." / ".." / "agents" / "skills",
            base / ".." / ".." / ".." / "agents" / "skills",
            // CWD-relative fallbacks (dev mode)
            std::filesystem::path("agents/skills"),
            std::filesystem::path("../agents/skills"),
            std::filesystem::path("../../agents/skills"),
        };
    }

    const std::string& load_skill_fragment(const std::string& skill_name) {
        std::lock_guard<std::mutex> lk(skill_cache_mutex);
        auto it = skill_cache.find(skill_name);
        if (it != skill_cache.end()) return it->second;

        static const auto search_dirs = make_skill_search_dirs();

        // Try to load from disk
        for (const auto& dir : search_dirs) {
            auto path = dir / (skill_name + ".json");
            std::error_code ec;
            if (!std::filesystem::exists(path, ec)) continue;
            try {
                std::ifstream f(path);
                nlohmann::json j;
                f >> j;
                std::string fragment = j.value("prompt_fragment", skill_name);
                skill_cache[skill_name] = std::move(fragment);
                return skill_cache[skill_name];
            } catch (...) {}
        }
        // File not found or parse error — fall back to bare name
        skill_cache[skill_name] = skill_name;
        return skill_cache[skill_name];
    }
} // anonymous namespace

AgentController::AgentController(
    std::function<std::string(const std::string&, const std::string&)> audit_adder,
    const std::string& ollama_host,
    uint16_t           ollama_port,
    int                worker_count)
    : granite_(std::make_unique<GraniteClient>(audit_adder, ollama_host, ollama_port))
    , audit_adder_(std::move(audit_adder))
    , worker_count_(worker_count > 0 ? worker_count : 1)
{}

AgentController::~AgentController()
{
    stop();
}

bool AgentController::load_persona(const std::filesystem::path& json_path)
{
    try {
        auto persona = PersonaLoader::load_from_json(json_path);
        if (!PersonaLoader::validate_persona(persona)) return false;
        if (!PersonaLoader::is_granite_only(persona)) {
            audit_adder_("persona_rejected",
                         "name=" + persona.name + " reason=non_granite_model");
            return false;
        }
        std::lock_guard<std::mutex> lk(mutex_);
        personas_[persona.name] = persona;
        statuses_[persona.name] = AgentStatus{
            persona.name, persona.category, model_to_tier(persona.preferred_model),
            AgentState::IDLE, "", "", 0, 0, 0, ""
        };
        // S3.4: update cached byte estimate at load time (not on every hot-path call)
        std::size_t bytes = persona.name.size() + persona.description.size()
                          + persona.category.size() + persona.system_prompt.size()
                          + persona.input_schema.size() + persona.output_schema.size()
                          + sizeof(AgentPersona);
        for (const auto& s : persona.skills) bytes += s.size();
        cached_personas_bytes_.fetch_add(bytes);
        return true;
    } catch (...) {
        return false;
    }
}

int AgentController::load_all_personas(const std::filesystem::path& defs_dir)
{
    if (!std::filesystem::exists(defs_dir)) return 0;
    int count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(defs_dir)) {
        if (entry.path().extension() == ".json") {
            if (load_persona(entry.path())) ++count;
        }
    }
    return count;
}

int AgentController::load_all_personas(const std::filesystem::path& defs_dir,
                                        const std::filesystem::path& config_path)
{
    // If config doesn't exist, fall back to loading all
    if (config_path.empty() || !std::filesystem::exists(config_path)) {
        return load_all_personas(defs_dir);
    }

    // Parse allowlist from config JSON
    std::unordered_set<std::string> allowlist;
    try {
        std::ifstream f(config_path);
        auto j = json::parse(f);
        if (j.contains("agent_allowlist") && j["agent_allowlist"].is_array()) {
            for (const auto& name : j["agent_allowlist"]) {
                if (name.is_string()) allowlist.insert(name.get<std::string>());
            }
        }
    } catch (...) {
        // Config unreadable — fall back to loading all
        return load_all_personas(defs_dir);
    }

    if (allowlist.empty()) return load_all_personas(defs_dir);

    // Load only agents in the allowlist
    if (!std::filesystem::exists(defs_dir)) return 0;
    int count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(defs_dir)) {
        if (entry.path().extension() != ".json") continue;
        std::string stem = entry.path().stem().string();
        if (allowlist.count(stem) == 0) continue;
        if (load_persona(entry.path())) ++count;
    }
    return count;
}

int AgentController::load_ecc_personas(const std::filesystem::path& ecc_agents_dir)
{
    if (!std::filesystem::exists(ecc_agents_dir)) return 0;
    int count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(ecc_agents_dir)) {
        if (entry.path().extension() != ".md") continue;
        if (!ECCAdapter::is_ecc_file(entry.path())) continue;
        try {
            AgentPersona persona;
            if (!ECCAdapter::load_from_md(entry.path(), persona)) continue;
            if (!PersonaLoader::is_granite_only(persona)) {
                audit_adder_("ecc_persona_rejected",
                             "name=" + persona.name + " reason=non_granite_model");
                continue;
            }
            std::lock_guard<std::mutex> lk(mutex_);
            personas_[persona.name] = persona;
            statuses_[persona.name] = AgentStatus{
                persona.name, persona.category, model_to_tier(persona.preferred_model),
                AgentState::IDLE, "", "", 0, 0, 0, ""
            };
            ++count;
        } catch (...) {}
    }
    return count;
}

std::string AgentController::submit_task(const std::string& agent_name,
                                          const std::string& input,
                                          Priority           priority)
{
    std::lock_guard<std::mutex> lk(mutex_);
    if (personas_.find(agent_name) == personas_.end()) {
        return "";  // unknown agent
    }
    std::string task_id = "task_" + std::to_string(next_task_id_++);
    queue_.push(TaskEntry{task_id, agent_name, input, priority, now_ms()});
    cv_.notify_one();
    return task_id;
}

void AgentController::start()
{
    if (running_.exchange(true)) return;  // already running
    for (int i = 0; i < worker_count_; ++i) {
        workers_.emplace_back(&AgentController::worker_loop, this);
    }
}

void AgentController::stop()
{
    if (!running_.exchange(false)) return;
    cv_.notify_all();  // wake ALL workers
    for (auto& t : workers_) {
        if (t.joinable()) t.join();
    }
    workers_.clear();
}

void AgentController::set_task_completed_callback(
    std::function<void(const TaskResult&)> callback)
{
    std::lock_guard<std::mutex> lk(mutex_);
    task_completed_callback_ = std::move(callback);
}

void AgentController::worker_loop()
{
    while (running_.load()) {
        TaskEntry entry;
        {
            std::unique_lock<std::mutex> lk(mutex_);
            cv_.wait(lk, [&]{ return !queue_.empty() || !running_.load(); });
            if (!running_.load() && queue_.empty()) break;
            entry = queue_.top();
            queue_.pop();
        }

        // Mark agent as running
        {
            std::lock_guard<std::mutex> lk(mutex_);
            if (statuses_.count(entry.agent_name)) {
                statuses_[entry.agent_name].state = AgentState::RUNNING;
            }
        }

        auto result = execute_task(entry);

        // Update agent status
        {
            std::lock_guard<std::mutex> lk(mutex_);
            auto& st = statuses_[entry.agent_name];
            st.state               = result.ok ? AgentState::COMPLETED : AgentState::FAILED;
            st.last_task_id        = result.task_id;
            st.last_run_at_ms      = result.completed_at_ms;
            st.last_result_snippet = result.output.substr(0, std::min<size_t>(100, result.output.size()));
            st.last_active         = iso_now();
            if (result.ok) ++st.tasks_completed;
            else           ++st.tasks_failed;
        }

        // S2.1 fix: copy callback out under lock, release lock, then invoke.
        // Prevents deadlock if callback calls back into AgentController methods
        // that also take mutex_ (e.g. submit_task, get_statuses).
        {
            std::function<void(const TaskResult&)> cb;
            {
                std::lock_guard<std::mutex> lk(mutex_);
                cb = task_completed_callback_;
            }
            if (cb) cb(result);
        }

        audit_adder_("agent_task_completed",
                     "agent=" + entry.agent_name +
                     " task=" + entry.task_id +
                     " ok="   + (result.ok ? "true" : "false") +
                     " model=" + result.model_used);
    }
}

TaskResult AgentController::execute_task(const TaskEntry& entry)
{
    TaskResult result;
    result.task_id    = entry.task_id;
    result.agent_name = entry.agent_name;
    result.ok         = false;

    AgentPersona persona;
    {
        std::lock_guard<std::mutex> lk(mutex_);
        auto it = personas_.find(entry.agent_name);
        if (it == personas_.end()) {
            result.completed_at_ms = now_ms();
            return result;
        }
        persona = it->second;
    }

    // Build system prompt: base + full skill prompt_fragments loaded from disk.
    // Each skill file contains a "prompt_fragment" field with detailed instructions.
    // Falls back gracefully to the bare skill name if the JSON file is not found.
    std::string system_prompt = persona.system_prompt;
    if (!persona.skills.empty()) {
        system_prompt += "\n\n--- Skills ---";
        for (const auto& skill : persona.skills) {
            const std::string& fragment = load_skill_fragment(skill);
            system_prompt += "\n[" + skill + "] " + fragment;
        }
    }

    auto resp = granite_->generate(
        persona.preferred_model,
        system_prompt,
        entry.input,
        persona.max_tokens,
        persona.temperature
    );

    result.ok             = resp.ok;
    result.output          = resp.text;
    result.model_used      = resp.model_used;
    result.completed_at_ms = now_ms();

    // Auto-dispatch: if an ActionDispatcher is wired in and inference succeeded,
    // parse the output and trigger real protective actions per policy.
    if (action_dispatcher_ && result.ok && !result.output.empty()) {
        auto dr = action_dispatcher_->dispatch(persona.name, result.output);
        if (dr.action_taken) {
            result.action_taken  = true;
            result.action_type   = dr.action_type;
            result.action_target = dr.target;
        }
    }

    // S3.4 fix: memory snapshot moved off the hot path.
    // Increment counter; actual snapshot is printed only when the counter
    // hits a multiple of 10, but the estimate is now done lock-free using
    // the cached sizes rather than re-iterating every persona string.
    // cached_personas_bytes_ is updated at load time in load_persona/load_ecc_personas.
    uint64_t n = ++tasks_since_last_mem_log_;
    if (n % 10 == 0) {
        std::size_t pb = cached_personas_bytes_.load();
        std::size_t qd = queue_depth();  // acquires/releases lock internally
        std::size_t qb = qd * (sizeof(TaskEntry) + 128);
        std::size_t sb = statuses_.size() * (sizeof(AgentStatus) + 64);
        std::size_t total_mb = (pb + qb + sb + (2*1024*1024)) / (1024*1024);
        if (total_mb < 1) total_mb = 1;
        std::cerr << "[MEM] personas=" << pb/1024 << "KB"
                  << " queue_est=" << qb/1024 << "KB"
                  << " statuses_est=" << sb/1024 << "KB"
                  << " total_estimated=" << total_mb << "MB\n";
    }

    return result;
}

std::vector<AgentStatus> AgentController::get_statuses() const
{
    std::lock_guard<std::mutex> lk(mutex_);
    std::vector<AgentStatus> out;
    out.reserve(statuses_.size());
    for (const auto& [name, st] : statuses_) {
        out.push_back(st);
    }
    return out;
}

std::size_t AgentController::queue_depth() const
{
    std::lock_guard<std::mutex> lk(mutex_);
    return queue_.size();
}

std::size_t AgentController::persona_count() const
{
    std::lock_guard<std::mutex> lk(mutex_);
    return personas_.size();
}

MemorySnapshot AgentController::get_memory_usage() const
{
    std::lock_guard<std::mutex> lk(mutex_);

    // Estimate persona map size: each persona holds strings + vector
    std::size_t personas_bytes = 0;
    for (const auto& [name, p] : personas_) {
        personas_bytes += name.size()
                       + p.name.size()
                       + p.description.size()
                       + p.category.size()
                       + p.system_prompt.size()
                       + p.input_schema.size()
                       + p.output_schema.size();
        for (const auto& s : p.skills) personas_bytes += s.size();
        personas_bytes += sizeof(AgentPersona);
    }

    // Estimate queue size: each TaskEntry holds strings
    std::size_t queue_bytes = 0;
    // priority_queue doesn't expose iteration; estimate from depth
    queue_bytes = queue_.size() * (sizeof(TaskEntry) + 128); // 128B avg strings

    // Estimate status map size
    std::size_t statuses_bytes = 0;
    for (const auto& [name, st] : statuses_) {
        statuses_bytes += name.size()
                       + st.name.size()
                       + st.category.size()
                       + st.last_task_id.size()
                       + st.last_result_snippet.size()
                       + sizeof(AgentStatus);
    }

    // Very rough OS-level estimate: process base + loaded models (Ollama)
    // Models are in Ollama process, not ours — we just estimate our heap
    std::size_t our_heap = personas_bytes + queue_bytes + statuses_bytes + (2 * 1024 * 1024);
    std::size_t total_mb = our_heap / (1024 * 1024);
    if (total_mb < 1) total_mb = 1;

    return {personas_bytes, queue_bytes, statuses_bytes, total_mb};
}

} // namespace agents
} // namespace astartis

// Made with Bob
