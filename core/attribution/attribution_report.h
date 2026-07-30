#ifndef ASTARTIS_ATTRIBUTION_REPORT_H
#define ASTARTIS_ATTRIBUTION_REPORT_H

// Step 13 -- DIBANET Layer 4: Attribution Report
//
// Compiles a structured report artifact from:
//   - DecoyEnvironment forensic log (Step 10)
//   - ActiveResponse forensic log + IOC matches (Step 11)
//   - AuditChain entries for the session
//
// Output: a plain-text report file written to the sandbox reports/ directory,
// plus an in-memory ReportArtifact struct for programmatic access.
//
// MITRE ATT&CK technique mapping:
//   Observed attacker behaviour is matched against a small inline table of
//   ATT&CK technique IDs.  This is tag-based (pattern matching on action
//   strings and resource paths) -- sufficient for a demo attribution report.
//   The full ATT&CK matrix is not embedded; only the techniques observable
//   within Astartis's decoy surface are covered.

#include <string>
#include <vector>
#include <functional>
#include <cstdint>

#include "../decoy/decoy.h"
#include "../active_response/active_response.h"

namespace astartis {
namespace attribution {

// ---------------------------------------------------------------------------
// ATT&CK technique match
// ---------------------------------------------------------------------------

struct AttackTechnique {
    std::string technique_id;   // e.g. "T1078"
    std::string name;           // e.g. "Valid Accounts"
    std::string tactic;         // e.g. "Initial Access"
    std::string evidence;       // what triggered the match
};

// ---------------------------------------------------------------------------
// IOC hit record (summary of Step 11 correlation results)
// ---------------------------------------------------------------------------

struct IocHit {
    std::string indicator;
    std::string type;
    std::string description;
    std::string source;
    int64_t     timestamp_ms;
};

// ---------------------------------------------------------------------------
// Full report artifact
// ---------------------------------------------------------------------------

struct ReportArtifact {
    std::string session_id;
    int64_t     session_start_ms;
    int64_t     session_end_ms;
    int         total_interactions;

    std::vector<AttackTechnique>              techniques;
    std::vector<IocHit>                       ioc_hits;
    std::vector<decoy::DecoyEvent>            decoy_events;
    std::vector<active_response::ResponseEvent> response_events;

    std::string summary;          // one-paragraph plain-English summary
    std::string report_file_path; // absolute path of the written .txt file
};

// ---------------------------------------------------------------------------
// AttributionReporter
// ---------------------------------------------------------------------------

class AttributionReporter {
public:
    /**
     * @param sandbox_root  Absolute path to sandbox root (reports/ written here).
     * @param audit_adder   Callable (event_type, payload) -> entry_id.
     */
    AttributionReporter(
        const std::string& sandbox_root,
        std::function<std::string(const std::string&, const std::string&)> audit_adder
    );

    ~AttributionReporter() = default;
    AttributionReporter(const AttributionReporter&)            = delete;
    AttributionReporter& operator=(const AttributionReporter&) = delete;

    /**
     * @brief Generate and write an attribution report for a completed session.
     *
     * Pulls all events for session_id from the decoy and active-response logs,
     * maps observed behaviour to ATT&CK techniques, summarises IOC hits, and
     * writes a plain-text .txt file to <sandbox_root>/reports/<session_id>.txt.
     *
     * Writes a "attribution_report_generated" audit entry on completion.
     *
     * @param session_id      The session identifier used in Steps 10/11.
     * @param decoy_log       Full forensic log from DecoyEnvironment::forensic_log().
     * @param response_log    Full forensic log from ActiveResponse::forensic_log().
     * @return Populated ReportArtifact.
     */
    ReportArtifact generate(
        const std::string&                                      session_id,
        const std::vector<decoy::DecoyEvent>&                   decoy_log,
        const std::vector<active_response::ResponseEvent>&      response_log
    );

    /**
     * @brief Map a single decoy event's action + resource to ATT&CK techniques.
     * Public for unit testing.
     */
    static std::vector<AttackTechnique> map_techniques(
        const std::string& action,
        const std::string& rel_path,
        decoy::PoisonType  poison_type
    );

private:
    static std::string build_report_text(const ReportArtifact& r);
    static std::string format_timestamp(int64_t ms);

    std::string sandbox_root_;
    std::function<std::string(const std::string&, const std::string&)> audit_adder_;
};

} // namespace attribution
} // namespace astartis

#endif // ASTARTIS_ATTRIBUTION_REPORT_H

// Made with Bob
