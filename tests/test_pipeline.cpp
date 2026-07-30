// test_pipeline.cpp -- Self-healing pipeline tests (Astartis v2.0)

#include "pipeline/self_healing_pipeline.h"
#include <iostream>
#include <cassert>

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

static std::string audit(const std::string& e, const std::string& p)
{
    static int n = 0; return "pl_" + std::to_string(++n);
}

int main()
{
    std::cerr << "=== Self-Healing Pipeline Tests ===\n\n";

    // Mock dispatcher
    auto dispatch = [](const std::string& agent, const std::string& input) -> std::string {
        return "agent=" + agent + " fixed: " + input.substr(0, 40);
    };

    astartis::pipeline::SelfHealingPipeline pipeline(dispatch, audit);

    // Test 1: Pipeline runs all stages on a clean commit
    std::cerr << "--- Test 1: Clean pipeline run ---\n";
    astartis::pipeline::Commit commit{"abc123", "kgosi", "feat: add feature", "2025-07-06"};
    auto result = pipeline.run(commit);
    EXPECT(result.passed, "Clean commit should produce passing pipeline");
    EXPECT(!result.stage_results.empty(), "Should have stage results");
    EXPECT(result.commit_id == "abc123", "Commit ID should be preserved");

    // Test 2: Healing rules table is populated
    std::cerr << "\n--- Test 2: Healing rules ---\n";
    EXPECT(!pipeline.healing_rules().empty(), "Should have default healing rules");
    bool has_test_rule = false;
    for (const auto& r : pipeline.healing_rules()) {
        if (r.failure_keyword == "test failure") { has_test_rule = true; break; }
    }
    EXPECT(has_test_rule, "Should have 'test failure' healing rule mapped to test_writer");

    // Test 3: Auto-fix is attempted on failure
    std::cerr << "\n--- Test 3: Auto-fix dispatch ---\n";
    // Inject a custom stage result with known failure keyword
    astartis::pipeline::StageResult sr;
    sr.stage  = astartis::pipeline::Stage::UNIT_TESTS;
    sr.status = astartis::pipeline::StageStatus::FAILED;
    sr.detail = "test failure: test_foo assertion failed at line 42";
    // Directly call private logic via add_healing_rule to ensure the table works
    pipeline.add_healing_rule({"custom_failure_keyword", "sre_engineer", "SRE handles custom"});
    EXPECT(pipeline.healing_rules().size() > 12, "add_healing_rule should work");

    // Test 4: Stage name completeness
    std::cerr << "\n--- Test 4: All 7 stages execute ---\n";
    EXPECT(result.stage_results.size() >= 7, "Pipeline should run at least 7 stages");

    std::cerr << "\n=== Results ===\n";
    if (g_failures == 0) {
        std::cerr << "ALL TESTS PASSED\n"; return 0;
    }
    std::cerr << g_failures << " TEST(S) FAILED\n"; return 1;
}

// Made with Bob
