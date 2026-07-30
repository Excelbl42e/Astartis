// self_healing_pipeline.h -- Self-healing CI/CD pipeline (Astartis v2.0)
//
// Detects build failures, test failures, security vulnerabilities, and
// performance regressions then delegates auto-fix tasks to the agent swarm.
// All agents run locally on IBM Granite — zero API cost.

#ifndef ASTARTIS_SELF_HEALING_PIPELINE_H
#define ASTARTIS_SELF_HEALING_PIPELINE_H

#include <string>
#include <vector>
#include <functional>
#include <memory>

namespace astartis {
namespace pipeline {

// ---------------------------------------------------------------------------
// Pipeline stage enum
// ---------------------------------------------------------------------------

enum class Stage {
    CODE_COMMIT      = 1,
    STATIC_ANALYSIS  = 2,
    UNIT_TESTS       = 3,
    INTEGRATION_TESTS = 4,
    SECURITY_SCAN    = 5,
    BUILD            = 6,
    DEPLOY_STAGING   = 7,
    E2E_TESTS        = 8,
    DEPLOY_PRODUCTION = 9,
    MONITOR          = 10
};

// ---------------------------------------------------------------------------
// Stage result
// ---------------------------------------------------------------------------

enum class StageStatus { PASSED, FAILED, SKIPPED, AUTO_FIXED };

struct StageResult {
    Stage       stage;
    StageStatus status;
    std::string detail;
    std::string auto_fix_agent;  ///< which agent was delegated to auto-fix
    std::string auto_fix_result; ///< what the agent returned
};

// ---------------------------------------------------------------------------
// Commit (trigger for the pipeline)
// ---------------------------------------------------------------------------

struct Commit {
    std::string id;
    std::string author;
    std::string message;
    std::string timestamp;
};

// ---------------------------------------------------------------------------
// Pipeline result
// ---------------------------------------------------------------------------

struct PipelineResult {
    std::string              commit_id;
    bool                     passed;
    std::vector<StageResult> stage_results;
    int                      auto_fixes_applied;
};

// ---------------------------------------------------------------------------
// Self-healing failure → agent mapping
// ---------------------------------------------------------------------------

struct HealingRule {
    std::string failure_keyword;   ///< substring to look for in stage failure detail
    std::string target_agent;     ///< which agent persona handles this failure
    std::string description;
};

// ---------------------------------------------------------------------------
// SelfHealingPipeline
// ---------------------------------------------------------------------------

class SelfHealingPipeline {
public:
    using AgentDispatch = std::function<std::string(
        const std::string& agent_name,
        const std::string& task_input)>;

    using AuditAdder = std::function<std::string(
        const std::string& event_type,
        const std::string& payload)>;

    explicit SelfHealingPipeline(AgentDispatch dispatch_fn, AuditAdder audit_adder);

    ~SelfHealingPipeline() = default;

    // Run the full pipeline for a commit.
    PipelineResult run(const Commit& commit);

    // Get current healing rules.
    const std::vector<HealingRule>& healing_rules() const { return healing_rules_; }

    // Add a custom healing rule.
    void add_healing_rule(HealingRule rule);

private:
    StageResult run_stage(Stage stage, const Commit& commit);
    bool attempt_auto_fix(StageResult& result);
    std::string stage_name(Stage s) const;

    AgentDispatch            dispatch_fn_;
    AuditAdder               audit_adder_;
    std::vector<HealingRule> healing_rules_;
};

} // namespace pipeline
} // namespace astartis

#endif // ASTARTIS_SELF_HEALING_PIPELINE_H

// Made with Bob
