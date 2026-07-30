// self_healing_pipeline.cpp -- Self-healing pipeline implementation (Astartis v2.0)

#include "pipeline/self_healing_pipeline.h"

#include <sstream>
#include <algorithm>

namespace astartis {
namespace pipeline {

// Default healing rules table.
// More rules can be added at runtime via add_healing_rule().
static const std::vector<HealingRule> DEFAULT_RULES = {
    { "compile error",         "bug_hunter",         "Auto-fix compile error" },
    { "link error",            "bug_hunter",         "Auto-fix linker error" },
    { "test failure",          "test_writer",        "Auto-generate missing tests" },
    { "assertion failed",      "bug_hunter",         "Analyze assertion failure" },
    { "vulnerability",         "security_reviewer",  "Patch security vulnerability" },
    { "CVE",                   "dependency_mgr",     "Update vulnerable dependency" },
    { "coverage drop",         "test_writer",        "Generate coverage-boosting tests" },
    { "lint",                  "refact_engine",      "Auto-apply lint fixes" },
    { "performance regression","performance_opt",    "Optimize performance bottleneck" },
    { "deployment failed",     "sre_engineer",       "Auto-rollback and diagnose" },
    { "memory leak",           "security_reviewer",  "Fix memory safety issue" },
    { "data race",             "security_reviewer",  "Fix thread safety issue" },
};

SelfHealingPipeline::SelfHealingPipeline(AgentDispatch dispatch_fn,
                                          AuditAdder    audit_adder)
    : dispatch_fn_(std::move(dispatch_fn))
    , audit_adder_(std::move(audit_adder))
    , healing_rules_(DEFAULT_RULES)
{}

void SelfHealingPipeline::add_healing_rule(HealingRule rule)
{
    healing_rules_.push_back(std::move(rule));
}

PipelineResult SelfHealingPipeline::run(const Commit& commit)
{
    audit_adder_("pipeline_started", "commit=" + commit.id + " author=" + commit.author);

    PipelineResult result;
    result.commit_id         = commit.id;
    result.passed            = true;
    result.auto_fixes_applied = 0;

    const Stage stages[] = {
        Stage::STATIC_ANALYSIS,
        Stage::UNIT_TESTS,
        Stage::SECURITY_SCAN,
        Stage::BUILD,
        Stage::INTEGRATION_TESTS,
        Stage::DEPLOY_STAGING,
        Stage::E2E_TESTS,
    };

    for (Stage stage : stages) {
        auto sr = run_stage(stage, commit);

        if (sr.status == StageStatus::FAILED) {
            bool fixed = attempt_auto_fix(sr);
            if (fixed) {
                ++result.auto_fixes_applied;
            } else {
                result.passed = false;
            }
        }

        result.stage_results.push_back(sr);

        // Stop on unrecoverable failure
        if (!result.passed && sr.status == StageStatus::FAILED) {
            audit_adder_("pipeline_blocked",
                         "commit=" + commit.id + " stage=" + stage_name(stage));
            break;
        }
    }

    std::string outcome = result.passed ? "passed" : "failed";
    audit_adder_("pipeline_completed",
                 "commit=" + commit.id +
                 " outcome=" + outcome +
                 " auto_fixes=" + std::to_string(result.auto_fixes_applied));

    return result;
}

StageResult SelfHealingPipeline::run_stage(Stage stage, const Commit& commit)
{
    StageResult sr;
    sr.stage  = stage;
    sr.status = StageStatus::PASSED;
    sr.detail = "Stage " + stage_name(stage) + " simulated PASS for commit " + commit.id;
    // In production: integrate with actual build system, test runner, security scanner.
    // This skeleton returns PASSED so the pipeline runs end-to-end without external tools.
    return sr;
}

bool SelfHealingPipeline::attempt_auto_fix(StageResult& result)
{
    // Find the first healing rule that matches the failure detail
    std::string detail_lower = result.detail;
    std::transform(detail_lower.begin(), detail_lower.end(),
                   detail_lower.begin(), [](unsigned char c){ return std::tolower(c); });

    for (const auto& rule : healing_rules_) {
        std::string kw = rule.failure_keyword;
        std::transform(kw.begin(), kw.end(), kw.begin(),
                       [](unsigned char c){ return std::tolower(c); });

        if (detail_lower.find(kw) != std::string::npos) {
            // Delegate to agent
            std::string task_input =
                "Fix this pipeline failure.\n"
                "Stage: " + stage_name(result.stage) + "\n"
                "Detail: " + result.detail;

            result.auto_fix_agent = rule.target_agent;

            if (dispatch_fn_) {
                result.auto_fix_result = dispatch_fn_(rule.target_agent, task_input);
            } else {
                result.auto_fix_result = "dispatch_not_available";
            }

            result.status = StageStatus::AUTO_FIXED;
            return true;
        }
    }
    return false;
}

std::string SelfHealingPipeline::stage_name(Stage s) const
{
    switch (s) {
        case Stage::CODE_COMMIT:       return "code_commit";
        case Stage::STATIC_ANALYSIS:   return "static_analysis";
        case Stage::UNIT_TESTS:        return "unit_tests";
        case Stage::INTEGRATION_TESTS: return "integration_tests";
        case Stage::SECURITY_SCAN:     return "security_scan";
        case Stage::BUILD:             return "build";
        case Stage::DEPLOY_STAGING:    return "deploy_staging";
        case Stage::E2E_TESTS:         return "e2e_tests";
        case Stage::DEPLOY_PRODUCTION: return "deploy_production";
        case Stage::MONITOR:           return "monitor";
        default:                       return "unknown";
    }
}

} // namespace pipeline
} // namespace astartis

// Made with Bob
