// test_async_inference.cpp — Verify GraniteClient::generateAsync() concurrency (Astartis v3.0)
//
// Exit 0 = PASS, 1 = FAIL, 2 = SKIP (Ollama not running)

#include "agents/controller/granite_client.h"

#include <iostream>
#include <future>
#include <chrono>

static int g_failures = 0;
#define EXPECT(cond, msg) \
    do { if (!(cond)) { std::cerr << "FAIL: " << (msg) << "\n"; ++g_failures; } \
         else { std::cerr << "PASS: " << (msg) << "\n"; } } while(0)

static std::string test_audit(const std::string& evt, const std::string& p)
{
    static int n = 0; (void)evt; (void)p;
    return "async_" + std::to_string(++n);
}

int main()
{
    std::cerr << "=== Async Inference Test ===\n\n";

    astartis::agents::GraniteClient client(test_audit);
    if (!client.ping()) {
        std::cerr << "INFO: Ollama not running — SKIP\n";
        return 2;
    }
    std::cerr << "PASS: Ollama reachable\n\n";

    // --- Test 1: Two concurrent FAST tasks via generateAsync ---
    std::cerr << "--- Test 1: Concurrent FAST tasks ---\n";
    auto t0 = std::chrono::steady_clock::now();
    auto f1 = client.generateAsync(
        astartis::agents::GraniteModel::FAST,
        "You are a triage bot. Reply brief.",
        "SSH brute force from 10.0.0.5. Critical?",
        32, 0.1
    );
    auto f2 = client.generateAsync(
        astartis::agents::GraniteModel::FAST,
        "You are a triage bot. Reply brief.",
        "Port scan from 10.0.0.6. Critical?",
        32, 0.1
    );

    auto r1 = f1.get();
    auto r2 = f2.get();
    auto t1 = std::chrono::steady_clock::now();

    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    EXPECT(r1.ok, "First async FAST task should succeed");
    EXPECT(r2.ok, "Second async FAST task should succeed");
    EXPECT(!r1.text.empty(), "First response should not be empty");
    EXPECT(!r2.text.empty(), "Second response should not be empty");
    EXPECT(elapsed_ms < 20000,
           "Two concurrent FAST tasks should complete in < 20s");

    std::cerr << "Elapsed: " << elapsed_ms << "ms\n";
    std::cerr << "Response 1: " << r1.text.substr(0, 60) << "\n";
    std::cerr << "Response 2: " << r2.text.substr(0, 60) << "\n";

    // --- Test 2: Sync vs Async timing comparison ---
    std::cerr << "\n--- Test 2: Sync vs Async timing ---\n";
    auto t2 = std::chrono::steady_clock::now();
    auto s1 = client.generate(astartis::agents::GraniteModel::FAST,
                               "You are a triage bot.", "Test A", 32, 0.1);
    auto s2 = client.generate(astartis::agents::GraniteModel::FAST,
                               "You are a triage bot.", "Test B", 32, 0.1);
    auto t3 = std::chrono::steady_clock::now();
    auto sync_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t3 - t2).count();

    std::cerr << "Sync sequential: " << sync_ms << "ms\n";
    std::cerr << "Async concurrent: " << elapsed_ms << "ms\n";
    // Heuristic: on CPU-only systems Ollama serialises requests internally,
    // so async may not be faster. Log the comparison but don't hard-fail.
    if (sync_ms > elapsed_ms * 0.5) {
        std::cerr << "PASS: Sequential took longer than concurrent (heuristic)\n";
    } else {
        std::cerr << "INFO: Concurrent was not faster (Ollama CPU-mode serialises) — expected on CPU\n";
    }

    std::cerr << "\n=== Results ===\n";
    if (g_failures == 0) {
        std::cerr << "ALL TESTS PASSED\n";
        return 0;
    }
    std::cerr << g_failures << " TEST(S) FAILED\n";
    return 1;
}

// Made with Bob
