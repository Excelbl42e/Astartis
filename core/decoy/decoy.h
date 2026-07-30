#ifndef ASTARTIS_DECOY_H
#define ASTARTIS_DECOY_H

/*
 * Step 10 — Decoy Environment (DIBANET Layer 2)
 *
 * Operates ENTIRELY within the Step 9 Sandbox.  No operation in this module
 * ever touches a path outside the sandbox root — the Sandbox::is_inside()
 * path guard is called before every write.
 *
 * Three named poisoning mechanisms (architecture §Step 10):
 *
 *   1. DATA VALUATION POISONING
 *      Plant decoy files that look like high-value assets (financial records,
 *      credentials databases, IP documents).  Content is statistically
 *      realistic but entirely synthetic — no real data.  An attacker
 *      spending time on these files is time spent inside the trap.
 *
 *   2. LATERAL MOVEMENT POISONING
 *      Create a fabricated "second server" subtree inside the sandbox
 *      (e.g. sandbox/decoy-server-02/).  Any lateral-movement attempt
 *      is silently redirected into this subtree.  It looks like a real
 *      neighbour server but is entirely synthetic and monitored.
 *
 *   3. CREDENTIAL POISONING
 *      Plant fake credentials (API keys, passwords, tokens) in realistic
 *      locations (/home/admin/.aws/credentials, /etc/shadow stub, etc.).
 *      Every access attempt to these files is forensically logged.
 *
 * Silent redirect:
 *      When a simulated breach crosses the configured threshold (default:
 *      any access to a poisoned file), the DecoyEnvironment::redirect()
 *      method silently moves subsequent attacker interactions into the
 *      lateral-movement subtree.  Called by the rule engine / Step 11.
 *
 * Forensic log:
 *      Every interaction with a poisoned asset writes a DecoyEvent to the
 *      internal forensic log AND to the AuditChain.  Step 12 reads this
 *      log to generate the attribution report.
 */

#include <string>
#include <vector>
#include <functional>
#include <mutex>
#include <cstdint>

#include "../sandbox/sandbox.h"

namespace astartis {
namespace decoy {

// ---------------------------------------------------------------------------
// Poisoning mechanism tag
// ---------------------------------------------------------------------------

enum class PoisonType {
    DATA_VALUATION,     ///< High-value fake asset
    LATERAL_MOVEMENT,   ///< Fabricated second-server path
    CREDENTIAL,         ///< Fake credential file
};

const char* poison_type_name(PoisonType t);

// ---------------------------------------------------------------------------
// Forensic event — written on every attacker interaction
// ---------------------------------------------------------------------------

struct DecoyEvent {
    int64_t     timestamp_ms;
    std::string rel_path;       ///< Path relative to sandbox root
    PoisonType  poison_type;
    std::string action;         ///< "read", "write_attempt", "redirect", etc.
    std::string attacker_tag;   ///< Caller-supplied attacker identifier
    std::string detail;         ///< Free-form forensic detail
};

// ---------------------------------------------------------------------------
// DecoyEnvironment
// ---------------------------------------------------------------------------

/**
 * @brief DIBANET Layer 2 — decoy environment inside the Step 9 sandbox.
 *
 * All three poisoning mechanisms are seeded via plant().
 * Attacker interactions are recorded via touch() and redirect().
 * The full forensic log is available for Step 12's attribution report.
 *
 * Thread-safe.
 */
class DecoyEnvironment {
public:
    /**
     * @param sb            Reference to the live Sandbox.  All writes go through it.
     * @param audit_adder   Callable (event_type, payload) -> entry_id.
     */
    explicit DecoyEnvironment(
        sandbox::Sandbox& sb,
        std::function<std::string(const std::string&, const std::string&)> audit_adder
    );

    ~DecoyEnvironment() = default;

    // Non-copyable.
    DecoyEnvironment(const DecoyEnvironment&)            = delete;
    DecoyEnvironment& operator=(const DecoyEnvironment&) = delete;

    // -----------------------------------------------------------------------
    // Setup
    // -----------------------------------------------------------------------

    /**
     * @brief Plant all three poisoning mechanisms inside the sandbox.
     *
     * Creates the poisoned files on disk (via Sandbox::write) and registers
     * them in the internal poisoned-path registry.
     *
     * DATA VALUATION files planted:
     *   decoy/assets/financial-projections-2024.xlsx  (fake spreadsheet stub)
     *   decoy/assets/customer-pii-export.csv          (fake PII stub)
     *   decoy/assets/ip-source-code-archive.tar.gz    (fake source archive stub)
     *   decoy/assets/strategic-roadmap-confidential.pdf
     *
     * LATERAL MOVEMENT server planted:
     *   decoy/server-02/etc/hostname                  (fake neighbour server)
     *   decoy/server-02/etc/nginx.conf
     *   decoy/server-02/var/log/auth.log
     *   decoy/server-02/home/admin/.ssh/authorized_keys
     *   decoy/server-02/opt/app/config.json
     *
     * CREDENTIAL files planted:
     *   decoy/credentials/.aws/credentials            (fake AWS keys)
     *   decoy/credentials/.ssh/id_rsa                 (fake private key)
     *   decoy/credentials/etc/shadow                  (fake /etc/shadow)
     *   decoy/credentials/opt/app/.env                (fake .env with DB password)
     *
     * Writes a "decoy_planted" audit entry.
     *
     * @return Number of poisoned files created.
     */
    size_t plant();

    // -----------------------------------------------------------------------
    // Attacker interaction recording
    // -----------------------------------------------------------------------

    /**
     * @brief Record an attacker touching a poisoned asset.
     *
     * Called whenever an attacker reads or attempts to use a poisoned path.
     * Writes a "decoy_event" audit entry and appends to the forensic log.
     *
     * If the path is not a known poisoned asset, this is a no-op (returns false).
     *
     * @param rel_path      Path relative to sandbox root (e.g. "decoy/assets/...").
     * @param action        What the attacker did ("read", "exfil_attempt", etc.).
     * @param attacker_tag  Identifier for the simulated attacker session.
     * @param detail        Any additional forensic detail to log.
     * @return true if the path was a known poisoned asset.
     */
    bool touch(const std::string& rel_path,
               const std::string& action,
               const std::string& attacker_tag,
               const std::string& detail = "");

    /**
     * @brief Trigger silent redirect — move attacker into the lateral-movement subtree.
     *
     * Records a "decoy_redirect" event in the forensic log and audit chain.
     * The redirect destination is the server-02 root inside the sandbox.
     *
     * @param attacker_tag  Identifier for the simulated attacker session.
     * @param trigger_path  The path that triggered the redirect.
     * @return The redirect destination rel_path (server-02 root).
     */
    std::string redirect(const std::string& attacker_tag,
                         const std::string& trigger_path);

    // -----------------------------------------------------------------------
    // Forensic log access (for Step 12 attribution report)
    // -----------------------------------------------------------------------

    /**
     * @brief Return the full forensic event log, oldest-first.
     */
    std::vector<DecoyEvent> forensic_log() const;

    /**
     * @brief Number of events in the forensic log.
     */
    size_t event_count() const;

    /**
     * @brief True if the given rel_path is a registered poisoned asset.
     */
    bool is_poisoned(const std::string& rel_path) const;

    /**
     * @brief Return the PoisonType for a registered path.
     *        Throws std::invalid_argument if path is not poisoned.
     */
    PoisonType poison_type_of(const std::string& rel_path) const;

    /**
     * @brief The rel_path of the lateral-movement redirect destination.
     */
    static const char* LATERAL_MOVEMENT_ROOT;

private:
    void log_event(const DecoyEvent& ev);

    sandbox::Sandbox& sb_;
    std::function<std::string(const std::string&, const std::string&)> audit_adder_;

    // rel_path -> PoisonType for all planted assets
    std::map<std::string, PoisonType> poisoned_;

    std::vector<DecoyEvent> forensic_log_;
    mutable std::mutex mutex_;
};

} // namespace decoy
} // namespace astartis

#endif // ASTARTIS_DECOY_H

// Made with Bob
