#ifndef ASTARTIS_AI_TRIAGE_H
#define ASTARTIS_AI_TRIAGE_H

// Step 18 -- AI Triage Integration (fully local, no external AI vendor)
//
// Two-tier Granite inference via local Ollama REST API (127.0.0.1:11434).
// All calls are synchronous HTTP POST to /api/generate with stream:false.
//
// FAST tier  : granite3.1-moe:3b   — routing + initial severity hint
// HEAVY tier : granite3.1-dense:8b — full severity + rationale + MITRE tag
//
// Both outputs are advisory input to the Step 7 RuleEngine, which retains
// final authority.  Neither model can bypass or override a rule engine
// decision.  rule_engine_overrode=true is recorded when the rule engine's
// final tier differs from the model suggestion.
//
// Timeout behaviour:
//   Fast tier : 15 s socket timeout.  On timeout → immediate fallback.
//   Heavy tier: 90 s socket timeout.  On timeout → fallback, no crash.
//   Fallback  : raw score passed directly to the rule engine; model_used
//               is set to "fallback_timeout" or "fallback_unavailable".

#include <string>
#include <functional>
#include <optional>
#include <cstdint>
#include <mutex>

#include "threat_level/threat_level.h"
#include "rule_engine/rule_engine.h"

namespace astartis {
namespace ai {

// ---------------------------------------------------------------------------
// Input
// ---------------------------------------------------------------------------

struct TriageInput {
    std::string event_type;   ///< e.g. "entropy_anomaly", "auth_failure_spike"
    std::string source;       ///< originating sensor / component
    int         score;        ///< 0–100 raw threat score
    std::string raw_detail;   ///< short free-text context (≤ 200 chars)
};

// ---------------------------------------------------------------------------
// Fast-tier result (granite3.1-moe:3b)
// ---------------------------------------------------------------------------

struct FastResult {
    std::string route;          ///< "handle" | "escalate" | "ignore"
    std::string severity_hint;  ///< "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    double      confidence;     ///< 0.0–1.0
    std::string model_used;     ///< actual model tag, or "fallback_*"
    bool        timed_out;
    bool        parse_ok;       ///< false if model returned non-JSON
};

// ---------------------------------------------------------------------------
// Heavy-tier result (granite3.1-dense:8b)
// ---------------------------------------------------------------------------

struct HeavyResult {
    std::string severity;         ///< "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    std::string rationale;        ///< one-sentence explanation
    std::string mitre_technique;  ///< e.g. "T1046" or empty
    std::string model_used;
    bool        timed_out;
    bool        parse_ok;
};

// ---------------------------------------------------------------------------
// Combined triage result
// ---------------------------------------------------------------------------

struct TriageResult {
    TriageInput              input;
    FastResult               fast;
    std::optional<HeavyResult> heavy;   ///< populated only when heavy tier ran
    threat::ThreatTier       model_suggested_tier;  ///< from fast (or heavy if ran)
    threat::ThreatTier       final_tier;            ///< rule engine's verdict
    bool                     rule_engine_overrode;
    std::string              audit_entry_id;
};

// ---------------------------------------------------------------------------
// AiTriage
// ---------------------------------------------------------------------------

class AiTriage {
public:
    // Default Ollama endpoint
    static constexpr const char* DEFAULT_HOST = "127.0.0.1";
    static constexpr uint16_t    DEFAULT_PORT = 11434;

    // Model tags
    static constexpr const char* FAST_MODEL  = "granite3.1-moe:3b";
    static constexpr const char* HEAVY_MODEL = "granite3.1-dense:8b";

    // Timeouts
    static constexpr int FAST_TIMEOUT_MS  =  15'000;  //  15 s
    static constexpr int HEAVY_TIMEOUT_MS =  90'000;  //  90 s

    // Escalation heuristic: call heavy tier when fast confidence < this
    static constexpr double ESCALATE_CONFIDENCE_THRESHOLD = 0.70;

    /**
     * @param audit_adder  Callable (event_type, payload) -> entry_id.
     * @param rule_engine  Reference to the live RuleEngine (Step 7).
     *                     AiTriage calls evaluate_threat_score() after
     *                     every triage so the rule engine stays authoritative.
     * @param ollama_host  Ollama host (default "127.0.0.1").
     * @param ollama_port  Ollama port (default 11434).
     */
    explicit AiTriage(
        std::function<std::string(const std::string&, const std::string&)> audit_adder,
        astartis::rules::RuleEngine& rule_engine,
        const std::string& ollama_host = DEFAULT_HOST,
        uint16_t           ollama_port = DEFAULT_PORT
    );

    // Destructor closes the single WSAStartup opened in the constructor (P1 fix).
    ~AiTriage();
    AiTriage(const AiTriage&)            = delete;
    AiTriage& operator=(const AiTriage&) = delete;

    /**
     * @brief Run AI triage on an event.
     *
     * 1. Calls fast tier.
     * 2. If route=="escalate" OR confidence < threshold: calls heavy tier.
     * 3. Passes model's severity suggestion as a score to RuleEngine.
     * 4. Writes "ai_triage" audit entry.
     * 5. Returns TriageResult with rule engine's final tier.
     */
    TriageResult triage(const TriageInput& input);

    /**
     * @brief Check that Ollama is reachable (sends a minimal /api/tags GET).
     * @return true if HTTP 200 is received within FAST_TIMEOUT_MS.
     */
    bool ping() const;

    const std::string& host() const { return host_; }
    uint16_t           port() const { return port_; }

private:
    // Call Ollama /api/generate; returns the raw response body or "" on error.
    // timeout_ms: socket receive timeout (SO_RCVTIMEO).
    std::string call_ollama(const std::string& model,
                            const std::string& prompt,
                            int                timeout_ms) const;

    // Parse the "response" field out of the Ollama /api/generate JSON reply.
    static std::string extract_response(const std::string& ollama_json);

    // Parse fast-tier model output (JSON string) into FastResult.
    static FastResult  parse_fast(const std::string& model_json,
                                  const std::string& model_tag,
                                  bool timed_out);

    // Parse heavy-tier model output into HeavyResult.
    static HeavyResult parse_heavy(const std::string& model_json,
                                   const std::string& model_tag,
                                   bool timed_out);

    // Convert a severity string ("LOW"/"MEDIUM"/"HIGH"/"CRITICAL") to ThreatTier.
    static threat::ThreatTier severity_to_tier(const std::string& s);

    // Convert a ThreatTier to a 0-100 score suitable for evaluate_threat_score().
    static int tier_to_score(threat::ThreatTier t);

    // Build the fast-tier prompt.
    static std::string fast_prompt(const TriageInput& in);

    // Build the heavy-tier prompt.
    static std::string heavy_prompt(const TriageInput& in,
                                    const FastResult&  fast);

    std::function<std::string(const std::string&, const std::string&)> audit_adder_;
    astartis::rules::RuleEngine& rule_engine_;
    std::string host_;
    uint16_t    port_;
    mutable std::mutex mutex_;  // serialise Ollama calls (one at a time)
};

} // namespace ai
} // namespace astartis

#endif // ASTARTIS_AI_TRIAGE_H

// Made with Bob
