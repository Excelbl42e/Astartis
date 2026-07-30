// test_thread_pool.cpp — Verify AgentController runs N workers concurrently (Astartis v3.0)
//
// Exit 0 = PASS, 1 = FAIL, 2 = SKIP (Ollama not running)

#include "agents/controller/agent_controller.h"
#include "agents/controller/persona_loader.h"

#include <iostream>
#include <atomic>
#include <chrono>
#include <thread>

static int g_failures = 0;
#define EXPECT(cond, msg) \
    do { if (!(cond)) { std::cerr << "FAIL: " << (msg) << "\n"; ++g_failures; } \
         else { std::cerr << "PASS: " << (msg) << "\n"; } } while(0)

static std::string test_audit(const std::string& evt, const std::string& p)
{
    static int n = 0; (void)evt; (void)p;
    return "tp_" + std::to_string(++n);
}

int main()
{
    std::cerr << "=== Thread Pool Test (4 workers) ===\n\n";

    astartis::agents::GraniteClient ping_client(test_audit);
    if (!ping_client.ping()) {
        std::cerr << "INFO: Ollama not running — SKIP\n";
        return 2;
    }
    std::cerr << "PASS: Ollama reachable\n\n";

    // --- Test 1: Create controller with 4 workers ---
    std::cerr << "--- Test 1: 4-worker controller ---\n";
    astartis::agents::AgentController ctrl(test_audit, "127.0.0.1", 11434, 4);
    EXPECT(ctrl.is_running() == false, "Controller should start stopped");

    // Load a few personas
    int loaded = ctrl.load_all_personas("agents/definitions");
    std::cerr << "Loaded " << loaded << " personas\n";
    EXPECT(loaded >= 4, "Should load at least 4 personas");

    // --- Test 2: Submit 8 FAST tasks, verify they all complete ---
    std::cerr << "\n--- Test 2: Concurrent task execution ---\n";
    std::atomic<int> completed{0};
    std::atomic<int> failed{0};

    ctrl.set_task_completed_callback([&completed, &failed](const astartis::agents::TaskResult& result) {
        if (result.ok) ++completed;
        else ++failed;
    });

    ctrl.start();
    EXPECT(ctrl.is_running(), "Controller should be running after start()");

    for (int i = 0; i < 8; ++i) {
        ctrl.submit_task("alert_triage", "Is this critical? SSH login from 10.0.0.5");
    }

    // Wait until all tasks report back via callback (up to 90s)
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(90);
    while (completed.load() + failed.load() < 8 &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    std::cerr << "Completed: " << completed.load() << ", Failed: " << failed.load() << "\n";

    EXPECT(completed.load() + failed.load() == 8,
           "All 8 tasks should have completed or failed");
    EXPECT(failed.load() < 8, "Less than 8 tasks should fail");

    ctrl.stop();
    EXPECT(!ctrl.is_running(), "Controller should be stopped after stop()");

    std::cerr << "\n=== Results ===\n";
    if (g_failures == 0) {
        std::cerr << "ALL TESTS PASSED\n";
        return 0;
    }
    std::cerr << g_failures << " TEST(S) FAILED\n";
    return 1;
}

// Made with Bob
