// test_warm_model.cpp — Verify GraniteClient keep-alive keeps models warm (Astartis v3.0)
//
// Exit 0 = PASS, 1 = FAIL, 2 = SKIP (Ollama not running)

#include "agents/controller/granite_client.h"

#include <iostream>
#include <chrono>
#include <thread>

static int g_failures = 0;
#define EXPECT(cond, msg) \
    do { if (!(cond)) { std::cerr << "FAIL: " << (msg) << "\n"; ++g_failures; } \
         else { std::cerr << "PASS: " << (msg) << "\n"; } } while(0)

static std::string test_audit(const std::string& evt, const std::string& p)
{
    static int n = 0; (void)evt; (void)p;
    return "warm_" + std::to_string(++n);
}

int main()
{
    std::cerr << "=== Warm Model Keep-Alive Test ===\n\n";

    astartis::agents::GraniteClient client(test_audit);
    if (!client.ping()) {
        std::cerr << "INFO: Ollama not running — SKIP\n";
        return 2;
    }
    std::cerr << "PASS: Ollama reachable\n\n";

    // --- Test 1: Start keep-alive with 5-second interval ---
    std::cerr << "--- Test 1: Start keep-alive (5s interval) ---\n";
    client.start_keep_alive(5000);
    std::cerr << "Keep-alive started\n";

    // Wait for at least 2 keep-alive cycles (10s + margin)
    std::cerr << "Waiting 12 seconds for keep-alive cycles...\n";
    std::this_thread::sleep_for(std::chrono::seconds(12));

    // --- Test 2: Generate after keep-alive — should be warm (fast) ---
    std::cerr << "\n--- Test 2: Generate on warm model ---\n";
    auto t0 = std::chrono::steady_clock::now();
    auto resp = client.generate(
        astartis::agents::GraniteModel::FAST,
        "You are a triage bot.",
        "Keep-alive test.",
        32, 0.1
    );
    auto t1 = std::chrono::steady_clock::now();

    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    EXPECT(resp.ok, "Generate after keep-alive should succeed");
    EXPECT(!resp.text.empty(), "Response should not be empty");
    EXPECT(elapsed_ms < 15000,
           "Warm FAST model should respond in < 15s (cold start can be > 30s)");

    std::cerr << "Elapsed: " << elapsed_ms << "ms\n";
    std::cerr << "Response: " << resp.text.substr(0, 60) << "\n";

    // --- Test 3: Stop keep-alive ---
    std::cerr << "\n--- Test 3: Stop keep-alive ---\n";
    client.stop_keep_alive();
    std::cerr << "Keep-alive stopped cleanly\n";
    EXPECT(true, "stop_keep_alive() should not crash");

    std::cerr << "\n=== Results ===\n";
    if (g_failures == 0) {
        std::cerr << "ALL TESTS PASSED\n";
        return 0;
    }
    std::cerr << g_failures << " TEST(S) FAILED\n";
    return 1;
}

// Made with Bob
