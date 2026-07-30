#ifndef ASTARTIS_ACCESS_TOKEN_H
#define ASTARTIS_ACCESS_TOKEN_H

/*
 * Step 8 — Zero-Trust Access Layer
 *
 * Short-lived, scoped access tokens. Every grant and revoke is written to
 * the AuditChain. No persistent session state — callers must present a valid
 * token on every check. Tokens expire after their TTL regardless of activity.
 *
 * Design (architecture §Step 8 / NIST ZTA SP 800-207):
 *   - Each token has a single named scope (e.g. "read:config", "write:records").
 *   - Tokens are keyed by a random token_id (hex string).
 *   - Expiry is checked on every is_valid() / check_access() call — no background thread.
 *   - Revocation is explicit: revoke(token_id) burns the token immediately,
 *     before its TTL expires, and writes a "token_revoked" audit entry.
 *   - Grant writes a "token_granted" audit entry.
 *   - Access denial (wrong scope, expired, revoked) writes a "token_denied" entry.
 *
 * The Step 15 12-eye unlock protocol wires into this: each approver presents
 * an AccessToken with scope "worm_unlock_vote".
 */

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <mutex>
#include <cstdint>

namespace astartis {
namespace access {

// ---------------------------------------------------------------------------
// Token descriptor (returned on grant; presented on check)
// ---------------------------------------------------------------------------

/**
 * @brief A granted access token.
 *
 * Store and present this on every check_access() call.
 * The token_id is the only key — the rest is metadata.
 */
struct AccessToken {
    std::string token_id;       ///< Random hex ID (32 chars)
    std::string identity_name;  ///< Who this token was issued to
    std::string scope;          ///< The single operation this token permits
    int64_t     granted_at_ms;  ///< Unix timestamp (ms) when granted
    int64_t     expires_at_ms;  ///< Unix timestamp (ms) when it expires
};

/**
 * @brief Result of a check_access() call.
 */
struct AccessResult {
    bool        granted;   ///< true if access is permitted
    std::string reason;    ///< "ok", "expired", "revoked", "scope_mismatch", "not_found"
};

// ---------------------------------------------------------------------------
// TokenStore — manages the full lifecycle
// ---------------------------------------------------------------------------

/**
 * @brief Zero-trust token store.
 *
 * Thread-safe. Tokens are stored in memory (sufficient for the demo).
 */
class TokenStore {
public:
    static constexpr int64_t DEFAULT_TTL_MS = 30'000; ///< 30 seconds

    /**
     * @param audit_adder  Callable (event_type, payload) -> entry_id.
     *                     Wired to AuditChain::add_entry.
     */
    explicit TokenStore(
        std::function<std::string(const std::string&, const std::string&)> audit_adder
    );

    ~TokenStore() = default;

    // Non-copyable.
    TokenStore(const TokenStore&)            = delete;
    TokenStore& operator=(const TokenStore&) = delete;

    // -----------------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------------

    /**
     * @brief Issue a new short-lived scoped token.
     *
     * Writes a "token_granted" audit entry.
     *
     * @param identity  Who is being granted access.
     * @param scope     The single operation permitted (e.g. "read:config").
     * @param ttl_ms    Lifetime in milliseconds (default 30 s).
     * @return The newly created AccessToken.
     */
    AccessToken grant(const std::string& identity,
                      const std::string& scope,
                      int64_t            ttl_ms = DEFAULT_TTL_MS);

    /**
     * @brief Explicitly revoke a token before it expires.
     *
     * Writes a "token_revoked" audit entry.
     * No-op if the token_id is not found (already expired or never issued).
     *
     * @param token_id  The ID returned by grant().
     * @param reason    Why it is being revoked (logged).
     * @return true if the token was found and burned.
     */
    bool revoke(const std::string& token_id, const std::string& reason = "");

    // -----------------------------------------------------------------------
    // Access check
    // -----------------------------------------------------------------------

    /**
     * @brief Check whether a token grants access to a given scope.
     *
     * Checks in order:
     *   1. Token exists.
     *   2. Token has not expired (current_time >= expires_at_ms → expired).
     *   3. Token has not been explicitly revoked.
     *   4. Token scope matches the required scope.
     *
     * Writes a "token_denied" audit entry on any failure.
     * Does NOT write an entry on success (success is the normal path — silent).
     *
     * @param token_id       The token to check.
     * @param required_scope The scope the caller requires.
     * @return AccessResult.
     */
    AccessResult check_access(const std::string& token_id,
                               const std::string& required_scope) const;

    // -----------------------------------------------------------------------
    // Diagnostics
    // -----------------------------------------------------------------------

    /** Total live (non-expired, non-revoked) tokens currently in the store. */
    size_t live_token_count() const;

    /** Total tokens ever granted. */
    uint64_t total_granted() const;

private:
    int64_t now_ms() const;
    std::string generate_token_id() const;

    struct StoredToken {
        AccessToken token;
        bool        revoked = false;
    };

    std::function<std::string(const std::string&, const std::string&)> audit_adder_;

    std::map<std::string, StoredToken> tokens_;   // key = token_id
    uint64_t total_granted_ = 0;

    mutable std::mutex mutex_;
};

} // namespace access
} // namespace astartis

#endif // ASTARTIS_ACCESS_TOKEN_H

// Made with Bob
