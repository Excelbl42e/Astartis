// benchmark_tiers.cpp -- 4-tier latency benchmark (Astartis v3.0)
//
// Standalone executable. Runs 5 identical tasks per tier, discards
// fastest + slowest, reports median latency + tokens + TPS.
// Writes benchmark_results.csv.
//
// Usage: .\benchmark_tiers.exe
// Prerequisites: Ollama running with granite3.1-moe:3b, granite3.1-dense:8b,
//                and ideally granite4.1-8b-q5_K_M.

#include "agents/controller/granite_client.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <chrono>
#include <numeric>
#include <iomanip>
#include <sstream>

static int64_t now_ms()
{
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

static std::string bench_audit(const std::string& evt, const std::string& p)
{
    static int n = 0;
    (void)evt; (void)p;
    return "bench_" + std::to_string(++n);
}

struct TierResult {
    std::string tier;
    std::string model_tag;
    std::string task_prompt;
    int64_t     median_latency_ms;
    int         median_tokens;
    double      median_tps;
    std::vector<int64_t> raw_latencies;
    std::vector<int>     raw_tokens;
};

static TierResult benchmark_tier(
    astartis::agents::GraniteClient& client,
    astartis::agents::GraniteModel   model,
    const std::string&               tier_name,
    const std::string&               model_tag,
    const std::string&               system_prompt,
    const std::string&               user_prompt,
    int                              max_tokens = 64,
    double                           temperature = 0.1,
    int                              runs = 5)
{
    TierResult result;
    result.tier        = tier_name;
    result.model_tag   = model_tag;
    result.task_prompt = user_prompt.substr(0, 60);

    std::cerr << "\n  Benchmarking " << tier_name << " (" << model_tag << ") — "
              << runs << " runs...\n";

    for (int i = 0; i < runs; ++i) {
        std::cerr << "    Run " << (i + 1) << "/" << runs << "... ";
        auto t0   = now_ms();
        auto resp = client.generate(model, system_prompt, user_prompt,
                                    max_tokens, temperature);
        auto t1   = now_ms();

        if (!resp.ok) {
            std::cerr << "FAIL (model unavailable)\n";
            // Record -1 to mark failure; filtered out in median calc
            result.raw_latencies.push_back(-1);
            result.raw_tokens.push_back(0);
            continue;
        }

        int64_t lat = t1 - t0;
        result.raw_latencies.push_back(lat);
        result.raw_tokens.push_back(resp.tokens_used);
        std::cerr << lat << "ms / " << resp.tokens_used << " tok\n";
    }

    // Filter out failed runs (-1 latencies)
    std::vector<int64_t> good_latencies;
    std::vector<int>     good_tokens;
    for (size_t i = 0; i < result.raw_latencies.size(); ++i) {
        if (result.raw_latencies[i] >= 0) {
            good_latencies.push_back(result.raw_latencies[i]);
            good_tokens.push_back(result.raw_tokens[i]);
        }
    }

    if (good_latencies.size() < 3) {
        std::cerr << "  WARNING: Not enough successful runs for median calc\n";
        result.median_latency_ms = 0;
        result.median_tokens     = 0;
        result.median_tps        = 0.0;
        return result;
    }

    // Sort and discard min/max (if >= 3 values)
    std::sort(good_latencies.begin(), good_latencies.end());
    std::sort(good_tokens.begin(), good_tokens.end());
    // Discard first (min) and last (max) if we have enough
    if (good_latencies.size() >= 5) {
        good_latencies.erase(good_latencies.begin());         // remove min
        good_latencies.pop_back();                            // remove max
        good_tokens.erase(good_tokens.begin());
        good_tokens.pop_back();
    }

    // Median of remaining
    size_t mid = good_latencies.size() / 2;
    result.median_latency_ms = good_latencies[mid];
    result.median_tokens     = good_tokens[mid];
    if (result.median_latency_ms > 0) {
        result.median_tps = (result.median_tokens * 1000.0) / result.median_latency_ms;
    }

    return result;
}

int main()
{
    std::cerr << "=== Astartis 4-Tier Benchmark ===\n";
    std::cerr << "Each tier: 5 runs, discard fastest+slowest, median reported.\n\n";

    astartis::agents::GraniteClient client(bench_audit);

    if (!client.ping()) {
        std::cerr << "FAIL: Ollama not running. Cannot benchmark.\n";
        return 1;
    }
    std::cerr << "Ollama reachable.\n";

    std::vector<TierResult> results;

    // FAST tier
    results.push_back(benchmark_tier(
        client,
        astartis::agents::GraniteModel::FAST,
        "FAST",
        astartis::agents::GraniteClient::FAST_MODEL_TAG,
        "You are a security classifier. Be brief.",
        "Is this a critical alert? SSH failed login from 10.0.0.5. Reply: {\"critical\":true/false}",
        32, 0.1
    ));

    // HEAVY tier
    results.push_back(benchmark_tier(
        client,
        astartis::agents::GraniteModel::HEAVY,
        "HEAVY",
        astartis::agents::GraniteClient::HEAVY_MODEL_TAG,
        "You are a security analyst. Be concise.",
        "Summarize in one sentence: SSH brute force attempt detected, 100 failed logins in 60 seconds from single IP.",
        64, 0.2
    ));

    // ACCURACY tier
    results.push_back(benchmark_tier(
        client,
        astartis::agents::GraniteModel::ACCURACY,
        "ACCURACY",
        astartis::agents::GraniteClient::ACCURACY_MODEL_TAG,
        "You are a malware analyst.",
        "Classify: encrypts files with .locked extension, deletes VSS, beacons to 185.220.101.42. Family name?",
        64, 0.1
    ));

    // ORCHESTRATOR tier
    results.push_back(benchmark_tier(
        client,
        astartis::agents::GraniteModel::ORCHESTRATOR,
        "ORCHESTRATOR",
        astartis::agents::GraniteClient::ORCHESTRATOR_MODEL_TAG,
        "You coordinate security response agents.",
        "Ransomware on endpoint WIN-01. List the 3 agents needed. Brief JSON only.",
        64, 0.2
    ));

    // --- CSV output ---
    std::ofstream csv("benchmark_results.csv");
    csv << "tier,model_tag,task_prompt,median_latency_ms,median_tokens,median_tps\n";
    for (const auto& r : results) {
        csv << r.tier << ","
            << r.model_tag << ","
            << "\"" << r.task_prompt << "\","
            << r.median_latency_ms << ","
            << r.median_tokens << ","
            << std::fixed << std::setprecision(1) << r.median_tps << "\n";
    }
    csv.close();
    std::cerr << "\nWritten: benchmark_results.csv\n";

    // --- Console summary ---
    std::cerr << "\n=== Tier Benchmark Summary ===\n";
    std::cerr << std::left
              << std::setw(36) << "Tier"
              << std::setw(12) << "Latency"
              << std::setw(10) << "Tokens"
              << std::setw(10) << "TPS"
              << "\n";
    std::cerr << std::string(66, '-') << "\n";
    for (const auto& r : results) {
        std::string label = r.tier + " (" + r.model_tag + ")";
        std::cerr << std::left  << std::setw(36) << label
                  << std::right << std::setw(8)  << r.median_latency_ms << "ms"
                  << std::setw(8)  << r.median_tokens << " tok"
                  << std::setw(7)  << std::fixed << std::setprecision(0)
                  << r.median_tps  << " tps\n";
    }

    return 0;
}

// Made with Bob
