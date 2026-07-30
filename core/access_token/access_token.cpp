#include "access_token.h"

#include <openssl/rand.h>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <stdexcept>

namespace astartis {
namespace access {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

TokenStore::TokenStore(
    std::function<std::string(const std::string&, const std::string&)> audit_adder)
    : audit_adder_(std::move(audit_adder))
{}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

int64_t TokenStore::now_ms() const
{
    auto tp = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(tp).count();
}

std::string TokenStore::generate_token_id() const
{
    unsigned char buf[16];
    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        throw std::runtime_error("RAND_bytes failed generating token ID");
    }
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (int i = 0; i < 16; ++i) {
        oss << std::setw(2) << static_cast<int>(buf[i]);
    }
    return oss.str();
}

// ---------------------------------------------------------------------------
// grant
// ---------------------------------------------------------------------------

AccessToken TokenStore::grant(const std::string& identity,
                               const std::string& scope,
                               int64_t            ttl_ms)
{
    if (identity.empty()) throw std::invalid_argument("identity must not be empty");
    if (scope.empty())    throw std::invalid_argument("scope must not be empty");
    if (ttl_ms <= 0)      throw std::invalid_argument("ttl_ms must be positive");

    std::lock_guard<std::mutex> lk(mutex_);

    AccessToken tok;
    tok.token_id      = generate_token_id();
    tok.identity_name = identity;
    tok.scope         = scope;
    tok.granted_at_ms = now_ms();
    tok.expires_at_ms = tok.granted_at_ms + ttl_ms;

    tokens_[tok.token_id] = StoredToken{tok, false};
    ++total_granted_;

    std::ostringstream p;
    p << "token_id=" << tok.token_id
      << " identity=" << identity
      << " scope=" << scope
      << " ttl_ms=" << ttl_ms;
    audit_adder_("token_granted", p.str());

    return tok;
}

// ---------------------------------------------------------------------------
// revoke
// ---------------------------------------------------------------------------

bool TokenStore::revoke(const std::string& token_id, const std::string& reason)
{
    std::lock_guard<std::mutex> lk(mutex_);

    auto it = tokens_.find(token_id);
    if (it == tokens_.end()) {
        return false;   // not found — no-op
    }

    if (it->second.revoked) {
        return false;   // already revoked — idempotent no-op
    }

    it->second.revoked = true;

    std::ostringstream p;
    p << "token_id=" << token_id
      << " identity=" << it->second.token.identity_name
      << " scope=" << it->second.token.scope
      << " reason=\"" << reason << "\"";
    audit_adder_("token_revoked", p.str());

    return true;
}

// ---------------------------------------------------------------------------
// check_access
// ---------------------------------------------------------------------------

AccessResult TokenStore::check_access(const std::string& token_id,
                                       const std::string& required_scope) const
{
    std::lock_guard<std::mutex> lk(mutex_);

    auto it = tokens_.find(token_id);
    if (it == tokens_.end()) {
        std::ostringstream p;
        p << "token_id=" << token_id
          << " required_scope=" << required_scope
          << " reason=not_found";
        audit_adder_("token_denied", p.str());
        return {false, "not_found"};
    }

    const auto& st = it->second;

    // Check expiry
    if (now_ms() >= st.token.expires_at_ms) {
        std::ostringstream p;
        p << "token_id=" << token_id
          << " identity=" << st.token.identity_name
          << " scope=" << st.token.scope
          << " required_scope=" << required_scope
          << " reason=expired";
        audit_adder_("token_denied", p.str());
        return {false, "expired"};
    }

    // Check revocation
    if (st.revoked) {
        std::ostringstream p;
        p << "token_id=" << token_id
          << " identity=" << st.token.identity_name
          << " scope=" << st.token.scope
          << " required_scope=" << required_scope
          << " reason=revoked";
        audit_adder_("token_denied", p.str());
        return {false, "revoked"};
    }

    // Check scope
    if (st.token.scope != required_scope) {
        std::ostringstream p;
        p << "token_id=" << token_id
          << " identity=" << st.token.identity_name
          << " token_scope=" << st.token.scope
          << " required_scope=" << required_scope
          << " reason=scope_mismatch";
        audit_adder_("token_denied", p.str());
        return {false, "scope_mismatch"};
    }

    return {true, "ok"};
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

size_t TokenStore::live_token_count() const
{
    std::lock_guard<std::mutex> lk(mutex_);
    int64_t now = now_ms();
    size_t count = 0;
    for (const auto& kv : tokens_) {
        const auto& st = kv.second;
        if (!st.revoked && now < st.token.expires_at_ms) {
            ++count;
        }
    }
    return count;
}

uint64_t TokenStore::total_granted() const
{
    std::lock_guard<std::mutex> lk(mutex_);
    return total_granted_;
}

} // namespace access
} // namespace astartis

// Made with Bob
