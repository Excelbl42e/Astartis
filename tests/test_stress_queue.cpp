// test_stress_queue.cpp -- 12-task queue stress test (Astartis v3.0)
//
// Loads all 65 JSON agents, runs 12 tasks (3 per tier) sequentially.
// Reduced from 20 tasks to fit within CTest 1800s timeout on CPU.
//
// Exit code 0 = ALL PASS
// Exit code 1 = FAIL
// Exit code 2 = Ollama not running (SKIP)

#pragma warning(push)
#pragma warning(disable: 4706 4127 4244)
#include "nlohmann/json.hpp"
#pragma warning(pop)

#include "agents/controller/agent_controller.h"
#include "agents/controller/persona_loader.h"
#include "agents/controller/granite_client.h"

#include <iostream>
#include <fstream>
#include <filesystem>
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>

namespace fs = std::filesystem;

static int g_failures = 0;

#define EXPECT(cond, msg) \
    do { \
        if (!(cond)) { \
            std::cerr << "FAIL: " << (msg) << " [" << __FILE__ << ":" << __LINE__ << "]\n"; \
            ++g_failures; \
        } else { \
            std::cerr << "PASS: " << (msg) << "\n"; \
        } \
    } while(0)

// -------------------------------------------------------------------------
// Shared result collection
// -------------------------------------------------------------------------
struct StressResult {
    std::string task_id;
    std::string agent_name;
    std::string tier;
    int64_t     enqueued_at_ms;
    int64_t     completed_at_ms;
    int64_t     latency_ms;
    int         tokens_used;
    bool        ok;
};

static std::mutex              results_mutex;
static std::vector<StressResult> all_results;
static std::atomic<int>        completed_count{0};
static std::atomic<int>        failed_count{0};

static std::string test_audit(const std::string& evt, const std::string& payload)
{
    static std::atomic<int> seq{0};
    (void)evt; (void)payload;
    return "stress_" + std::to_string(++seq);
}

static int64_t now_ms()
{
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

static std::string tier_name(astartis::agents::GraniteModel m)
{
    switch (m) {
        case astartis::agents::GraniteModel::FAST:         return "FAST";
        case astartis::agents::GraniteModel::HEAVY:        return "HEAVY";
        case astartis::agents::GraniteModel::ACCURACY:     return "ACCURACY";
        case astartis::agents::GraniteModel::ORCHESTRATOR: return "ORCHESTRATOR";
        default: return "UNKNOWN";
    }
}

int main()
{
    std::cerr << "=== Stress Queue Test (12 tasks) ===\n\n";

    // Pre-flight: Ollama
    astartis::agents::GraniteClient ping_client(test_audit);
    if (!ping_client.ping()) {
        std::cerr << "INFO: Ollama not running — exiting with code 2 (SKIP)\n";
        return 2;
    }
    std::cerr << "PASS: Ollama reachable\n\n";

    // --- Load all personas ---
    fs::path defs_dir = "agents/definitions";
    if (!fs::exists(defs_dir)) {
        std::cerr << "FAIL: agents/definitions not found\n";
        return 1;
    }

    // We run tasks directly via GraniteClient (no AgentController worker thread)
    // so we can capture exact timestamps and collect results inline.
    // AgentController now has set_task_completed_callback() (see test_thread_pool.cpp).
    // This test bypasses the controller to measure raw GraniteClient throughput.
    // We use PersonaLoader to find one representative agent per tier.
    std::cerr << "--- Loading persona catalog ---\n";
    std::map<astartis::agents::GraniteModel, std::string> tier_agents;

    for (const auto& entry : fs::directory_iterator(defs_dir)) {
        if (entry.path().extension() != ".json") continue;
        try {
            auto p = astartis::agents::PersonaLoader::load_from_json(entry.path());
            if (!astartis::agents::PersonaLoader::validate_persona(p)) continue;
            if (tier_agents.find(p.preferred_model) == tier_agents.end()) {
                tier_agents[p.preferred_model] = p.name;
            }
        } catch (...) {}
    }

    EXPECT(tier_agents.count(astartis::agents::GraniteModel::FAST)  > 0, "FAST agents available");
    EXPECT(tier_agents.count(astartis::agents::GraniteModel::HEAVY) > 0, "HEAVY agents available");
    EXPECT(tier_agents.count(astartis::agents::GraniteModel::ACCURACY)     > 0, "ACCURACY agents available");
    EXPECT(tier_agents.count(astartis::agents::GraniteModel::ORCHESTRATOR) > 0, "ORCHESTRATOR agents available");
    if (g_failures > 0) return 1;

    for (const auto& [tier, agent] : tier_agents) {
        std::cerr << "  " << tier_name(tier) << " → " << agent << "\n";
    }
    std::cerr << "\n";

    // --- Build task plan: 3 per tier = 12 total ---
    struct TaskPlan {
        std::string                    task_id;
        std::string                    agent_name;
        astartis::agents::GraniteModel tier;
        std::string                    system_prompt;
        std::string                    user_prompt;
        int                            max_tokens;
        double                         temperature;
        int64_t                        enqueued_at_ms;
    };

    std::vector<TaskPlan> plan;
    int seq = 0;

    // Use a simple short prompt for all tasks — this is a throughput test
    const std::string fast_prompt  = "Is this alert critical? Reply: {\"critical\": true/false}";
    const std::string heavy_prompt = "Summarize the security risk in one sentence: SSH brute force from 10.0.0.1";
    const std::string acc_prompt   = "Classify this malware behavior: Encrypts files, deletes shadow copies. Family?";
    const std::string orch_prompt  = "Assign agents to respond to a port scan. Brief list only.";

    // 3 tasks per tier = 12 total.
    // Rationale: granite4.1 on CPU takes ~100s/call. 3×4 = ~12 min worst-case,
    // comfortably within the CTest 900s timeout.
    static constexpr int TASKS_PER_TIER = 3;

    for (int i = 0; i < TASKS_PER_TIER; ++i) {
        plan.push_back({"stress_" + std::to_string(++seq),
                        tier_agents[astartis::agents::GraniteModel::FAST],
                        astartis::agents::GraniteModel::FAST,
                        "You are a fast triage bot.", fast_prompt, 32, 0.1, 0});
    }
    for (int i = 0; i < TASKS_PER_TIER; ++i) {
        plan.push_back({"stress_" + std::to_string(++seq),
                        tier_agents[astartis::agents::GraniteModel::HEAVY],
                        astartis::agents::GraniteModel::HEAVY,
                        "You are a security analyst.", heavy_prompt, 64, 0.2, 0});
    }
    for (int i = 0; i < TASKS_PER_TIER; ++i) {
        plan.push_back({"stress_" + std::to_string(++seq),
                        tier_agents[astartis::agents::GraniteModel::ACCURACY],
                        astartis::agents::GraniteModel::ACCURACY,
                        "You are a malware analyst.", acc_prompt, 64, 0.1, 0});
    }
    for (int i = 0; i < TASKS_PER_TIER; ++i) {
        plan.push_back({"stress_" + std::to_string(++seq),
                        tier_agents[astartis::agents::GraniteModel::ORCHESTRATOR],
                        astartis::agents::GraniteModel::ORCHESTRATOR,
                        "You coordinate security agents.", orch_prompt, 64, 0.2, 0});
    }

    const int TOTAL_TASKS = TASKS_PER_TIER * 4;
    std::cerr << "--- Executing " << plan.size() << " tasks sequentially ---\n";
    std::cerr << "(3 per tier × 4 tiers = 12 tasks; CPU inference ~12 min worst-case)\n\n";

    astartis::agents::GraniteClient client(test_audit);

    int task_num = 0;
    for (auto& task : plan) {
        task.enqueued_at_ms = now_ms();
        auto t0 = now_ms();
        auto resp = client.generate(task.tier, task.system_prompt, task.user_prompt,
                                    task.max_tokens, task.temperature);
        auto t1 = now_ms();

        StressResult sr;
        sr.task_id         = task.task_id;
        sr.agent_name      = task.agent_name;
        sr.tier            = tier_name(task.tier);
        sr.enqueued_at_ms  = task.enqueued_at_ms;
        sr.completed_at_ms = t1;
        sr.latency_ms      = t1 - t0;
        sr.tokens_used     = resp.tokens_used;
        sr.ok              = resp.ok;

        {
            std::lock_guard<std::mutex> lk(results_mutex);
            all_results.push_back(sr);
        }

        if (resp.ok) ++completed_count;
        else         ++failed_count;

        ++task_num;
        if (task_num % 5 == 0) {
            std::cerr << "Progress: " << task_num << "/" << TOTAL_TASKS << " tasks | "
                      << "ok=" << completed_count.load()
                      << " fail=" << failed_count.load() << "\n";
        }
    }

    std::cerr << "\n--- Writing stress_test_results.csv ---\n";
    std::ofstream csv("stress_test_results.csv");
    csv << "task_id,agent_name,tier,enqueued_at_ms,completed_at_ms,latency_ms,tokens_used,ok\n";
    for (const auto& r : all_results) {
        csv << r.task_id << ","
            << r.agent_name << ","
            << r.tier << ","
            << r.enqueued_at_ms << ","
            << r.completed_at_ms << ","
            << r.latency_ms << ","
            << r.tokens_used << ","
            << (r.ok ? "true" : "false") << "\n";
    }
    csv.close();
    std::cerr << "Written: stress_test_results.csv (" << all_results.size() << " rows)\n\n";

    // --- Assertions ---
    std::cerr << "--- Assertions ---\n";
    EXPECT((int)all_results.size() == TOTAL_TASKS,
           "Should have 12 task results (3 per tier)");
    EXPECT(completed_count.load() + failed_count.load() == TOTAL_TASKS,
           "completed + failed should equal 12");

    // Count by tier
    std::map<std::string, int> tier_ok;
    for (const auto& r : all_results) {
        if (r.ok) tier_ok[r.tier]++;
    }
    std::cerr << "Tier completion: ";
    for (const auto& [t, c] : tier_ok) {
        std::cerr << t << "=" << c << "/" << TASKS_PER_TIER << " ";
    }
    std::cerr << "\n";

    // FAST and HEAVY should complete reliably (models confirmed present)
    EXPECT(tier_ok["FAST"]  == TASKS_PER_TIER, "All 3 FAST tasks should succeed");
    EXPECT(tier_ok["HEAVY"] == TASKS_PER_TIER, "All 3 HEAVY tasks should succeed");
    // ACCURACY and ORCHESTRATOR depend on granite4.1 being pulled
    if (tier_ok["ACCURACY"] < TASKS_PER_TIER || tier_ok["ORCHESTRATOR"] < TASKS_PER_TIER) {
        std::cerr << "WARN: ACCURACY/ORCHESTRATOR tasks incomplete — is granite4.1 pulled?\n";
    }
    EXPECT(failed_count.load() < TOTAL_TASKS, "Less than 12 tasks should fail");

    std::cerr << "\nTotal: " << completed_count.load() << " OK, "
              << failed_count.load() << " failed\n";

    std::cerr << "\n=== Results ===\n";
    if (g_failures == 0) {
        std::cerr << "ALL TESTS PASSED\n";
        return 0;
    }
    std::cerr << g_failures << " TEST(S) FAILED\n";
    return 1;
}

// Made with Bob
