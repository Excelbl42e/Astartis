// test_ollama_recovery.cpp -- GraniteClient crash/recovery simulation (Astartis v3.0)
//
// Tests that GraniteClient fails gracefully when Ollama is unreachable
// and recovers correctly when reconnected. Uses a custom port to simulate
// unavailability WITHOUT killing the real Ollama process.
//
// Exit code 0 = ALL PASS
// Exit code 1 = FAIL
// Exit code 2 = Ollama not running (SKIP)

#include "agents/controller/granite_client.h"

#include <iostream>
#include <string>
#include <chrono>
#include <thread>

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

static std::string test_audit(const std::string& evt, const std::string& payload)
{
    static int seq = 0;
    std::cerr << "[AUDIT] " << evt << " | " << payload << "\n";
    return "rec_" + std::to_string(++seq);
}

int main()
{
    std::cerr << "=== Ollama Recovery Test ===\n\n";

    // --- Step 1: Verify Ollama is running on real port ---
    std::cerr << "--- Step 1: Baseline — Ollama on port 11434 ---\n";
    astartis::agents::GraniteClient real_client(test_audit, "127.0.0.1", 11434);
    if (!real_client.ping()) {
        std::cerr << "INFO: Ollama not running — exiting with code 2 (SKIP)\n";
        return 2;
    }
    std::cerr << "PASS: Ollama reachable on 11434\n\n";

    // --- Step 2: Submit a FAST task — should work ---
    std::cerr << "--- Step 2: FAST task on live Ollama ---\n";
    auto r1 = real_client.generate(
        astartis::agents::GraniteModel::FAST,
        "You are a classifier.",
        "Is this critical? Failed login from 10.0.0.5.",
        32, 0.1
    );
    EXPECT(r1.ok, "Live Ollama FAST task should succeed");
    EXPECT(r1.model_used == astartis::agents::GraniteClient::FAST_MODEL_TAG,
           "Should use FAST model tag");
    EXPECT(r1.model_used != "unavailable", "Should not be unavailable");
    EXPECT(r1.model_used != "rejected",    "Should not be rejected");
    std::cerr << "Response: " << r1.text.substr(0, 60) << "...\n\n";

    // --- Step 3: Create client pointing at dead port 11435 ---
    std::cerr << "--- Step 3: Graceful failure on dead port 11435 ---\n";
    astartis::agents::GraniteClient dead_client(test_audit, "127.0.0.1", 11435);
    EXPECT(!dead_client.ping(), "Dead port 11435 should not be reachable");

    auto r2 = dead_client.generate(
        astartis::agents::GraniteModel::FAST,
        "You are a classifier.",
        "Is this critical? Scan detected.",
        32, 0.1
    );
    EXPECT(!r2.ok,  "Dead port task should return ok=false");
    EXPECT(r2.text.empty(), "Dead port task should return empty text");
    EXPECT(r2.model_used == "unavailable",
           "Dead port task should report model_used=unavailable");
    std::cerr << "Correctly failed: ok=" << r2.ok
              << " model_used=" << r2.model_used << "\n\n";

    // --- Step 4: Submit HEAVY to dead port — also fails gracefully ---
    std::cerr << "--- Step 4: HEAVY task on dead port ---\n";
    auto r3 = dead_client.generate(
        astartis::agents::GraniteModel::HEAVY,
        "You are an analyst.",
        "Analyze this log entry: ERROR auth failed",
        64, 0.2
    );
    EXPECT(!r3.ok,  "HEAVY task on dead port should fail");
    EXPECT(r3.model_used == "unavailable", "HEAVY on dead port → unavailable");
    std::cerr << "Correctly failed: ok=" << r3.ok << "\n\n";

    // --- Step 5: No zombie threads — dead client destructs cleanly ---
    std::cerr << "--- Step 5: Dead client cleanup (no zombie threads) ---\n";
    {
        astartis::agents::GraniteClient temp_dead(test_audit, "127.0.0.1", 11435);
        auto r4 = temp_dead.generate(
            astartis::agents::GraniteModel::FAST,
            "Test.", "Test.", 10, 0.1
        );
        EXPECT(!r4.ok, "Temp dead client should fail");
        // Destructor runs here — no crash = pass
    }
    EXPECT(true, "Dead client destructor completed without crash");

    // --- Step 6: Recovery — real client still works after dead client used ---
    std::cerr << "\n--- Step 6: Recovery — real client still works ---\n";
    auto r5 = real_client.generate(
        astartis::agents::GraniteModel::FAST,
        "You are a classifier.",
        "Classify: auth success from admin.",
        32, 0.1
    );
    EXPECT(r5.ok, "Real client should still work after dead client test");
    EXPECT(!r5.text.empty(), "Recovery response should not be empty");
    EXPECT(r5.model_used == astartis::agents::GraniteClient::FAST_MODEL_TAG,
           "Recovery should use correct model tag");
    std::cerr << "Recovery response: " << r5.text.substr(0, 60) << "...\n\n";

    // --- Step 7: Verify ping() correctly reflects availability ---
    std::cerr << "--- Step 7: Ping correctness ---\n";
    EXPECT(real_client.ping(), "Real client should ping successfully");
    EXPECT(!dead_client.ping(), "Dead client should NOT ping successfully");

    std::cerr << "\n=== Results ===\n";
    if (g_failures == 0) {
        std::cerr << "ALL TESTS PASSED\n";
        return 0;
    }
    std::cerr << g_failures << " TEST(S) FAILED\n";
    return 1;
}

// Made with Bob
