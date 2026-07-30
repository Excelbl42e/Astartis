#ifndef ASTARTIS_CRYPTO_IDENTITY_H
#define ASTARTIS_CRYPTO_IDENTITY_H

#include <string>
#include <vector>
#include <functional>
#include <cstdint>

namespace astartis {
namespace crypto {

/**
 * @brief A secp256k1 keypair bound to an identity name.
 *
 * Wraps OpenSSL EVP_PKEY for secp256k1. The private key never leaves
 * this object — callers sign challenges and verify signatures through
 * the public API only.
 *
 * Design (architecture §4):
 *   - Per-request signing: every request carries a fresh signature over
 *     (identity_name + challenge + timestamp). No session tokens.
 *   - Challenge-response: the verifier supplies a random challenge;
 *     the prover signs it; the verifier checks the signature against
 *     the stored public key. Replay is rejected because each challenge
 *     is single-use (enforced by the caller — see ChallengeVerifier).
 */
class Identity {
public:
    /**
     * @brief Generate a new secp256k1 keypair for the given identity name.
     * @throws std::runtime_error if key generation fails.
     */
    explicit Identity(const std::string& name);

    ~Identity();

    // Non-copyable — private key must not be duplicated.
    Identity(const Identity&)            = delete;
    Identity& operator=(const Identity&) = delete;

    // Movable.
    Identity(Identity&&) noexcept;
    Identity& operator=(Identity&&) noexcept;

    // -----------------------------------------------------------------------
    // Identity metadata
    // -----------------------------------------------------------------------

    const std::string& name() const { return name_; }

    /**
     * @brief DER-encoded public key (safe to share / store).
     */
    std::vector<uint8_t> public_key_der() const;

    // -----------------------------------------------------------------------
    // Signing
    // -----------------------------------------------------------------------

    /**
     * @brief Sign a message with this identity's private key.
     *
     * Uses ECDSA over SHA-256 with the secp256k1 curve.
     * The message is hashed internally — pass raw bytes.
     *
     * @param message  Arbitrary bytes to sign.
     * @return DER-encoded ECDSA signature.
     * @throws std::runtime_error on failure.
     */
    std::vector<uint8_t> sign(const std::vector<uint8_t>& message) const;

    // -----------------------------------------------------------------------
    // Verification (static — only needs the public key)
    // -----------------------------------------------------------------------

    /**
     * @brief Verify an ECDSA signature against a DER-encoded public key.
     *
     * @param message    The original message bytes.
     * @param signature  DER-encoded ECDSA signature.
     * @param public_key DER-encoded secp256k1 public key.
     * @return true if the signature is valid.
     */
    static bool verify(const std::vector<uint8_t>& message,
                       const std::vector<uint8_t>& signature,
                       const std::vector<uint8_t>& public_key);

private:
    std::string name_;
    void*       pkey_ = nullptr;   // EVP_PKEY* — opaque to avoid OpenSSL headers leaking
};

// ---------------------------------------------------------------------------

/**
 * @brief Per-request signed token — what a caller presents per request.
 *
 * Contains:
 *   - identity_name : who is making the request
 *   - challenge     : random bytes issued by the verifier
 *   - timestamp_ms  : Unix time in ms when the token was created
 *   - signature     : ECDSA over SHA-256(identity_name || challenge || timestamp_ms)
 *
 * No session state is kept — every request is independently verified.
 */
struct SignedRequest {
    std::string          identity_name;
    std::vector<uint8_t> challenge;
    int64_t              timestamp_ms;
    std::vector<uint8_t> signature;
};

/**
 * @brief Builds a SignedRequest for a given challenge using an Identity.
 *
 * Hashes (identity_name || challenge || timestamp_ms) and signs it.
 */
SignedRequest make_signed_request(const Identity&              identity,
                                  const std::vector<uint8_t>&  challenge);

/**
 * @brief Verifies a SignedRequest.
 *
 * Checks:
 *   1. The signature is valid for the message over the supplied public key.
 *   2. The challenge matches the one the verifier issued (caller's responsibility
 *      to pass the correct expected_challenge and mark it used after verification).
 *
 * @param request           The signed request to verify.
 * @param expected_challenge The challenge the verifier originally issued.
 * @param public_key_der    DER-encoded public key of the claimed identity.
 * @return true if signature valid AND challenge matches.
 */
bool verify_signed_request(const SignedRequest&          request,
                            const std::vector<uint8_t>&  expected_challenge,
                            const std::vector<uint8_t>&  public_key_der);

/**
 * @brief Generate cryptographically random challenge bytes.
 * @param length Number of bytes (default 32).
 */
std::vector<uint8_t> generate_challenge(size_t length = 32);

} // namespace crypto
} // namespace astartis

#endif // ASTARTIS_CRYPTO_IDENTITY_H

// Made with Bob
