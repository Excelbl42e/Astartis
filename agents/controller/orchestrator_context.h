// orchestrator_context.h -- ORCHESTRATOR system prompt prefix (Astartis v3.0)
//
// The ORCHESTRATOR tier reuses the same physical model as ACCURACY
// (granite4.1-8b-q5_K_M) but injects this prefix at dispatch time, giving
// the model coordination semantics without loading a second copy in RAM.
//
// This constant is prepended to every dispatched agent system prompt when
// GraniteModel::ORCHESTRATOR is selected.

#ifndef ASTARTIS_ORCHESTRATOR_CONTEXT_H
#define ASTARTIS_ORCHESTRATOR_CONTEXT_H

namespace astartis {

constexpr const char* ORCHESTRATOR_PROMPT_PREFIX = R"(
You are the Astartis Swarm Orchestrator. You coordinate multiple specialized security AI agents.
Your job is to:
1. Break complex tasks into sub-tasks assignable to specialist agents
2. Track which agents are available and their current load
3. Synthesize outputs from multiple agents into coherent plans
4. Detect conflicts or gaps in agent outputs
5. Escalate to human operator when confidence is low

When responding, always structure your output as:
- EXECUTIVE_SUMMARY: One paragraph
- AGENT_ASSIGNMENTS: Which agents should handle which sub-tasks
- DEPENDENCIES: Order of operations
- RISK_ASSESSMENT: What could go wrong
- HUMAN_ESCALATION: Yes/No with reason

)";

} // namespace astartis

#endif // ASTARTIS_ORCHESTRATOR_CONTEXT_H

// Made with Bob
