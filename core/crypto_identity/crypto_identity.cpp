#include "crypto_identity.h"

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include <chrono>
#include <stdexcept>
#include <sstream>
#include <cstring>

namespace astartis {
namespace crypto {

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

static std::string openssl_error_string() {
    unsigned long err = ERR_get_error();
    if (err == 0) return "unknown OpenSSL error";
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

static EVP_PKEY* raw_pkey(void* p) {
    return static_cast<EVP_PKEY*>(p);
}

// Build the message bytes signed per-request:
//   identity_name (utf-8 bytes) || challenge bytes || timestamp_ms (8 bytes, big-endian)
static std::vector<uint8_t> build_request_message(const std::string&           identity_name,
                                                   const std::vector<uint8_t>&  challenge,
                                                   int64_t                      timestamp_ms)
{
    std::vector<uint8_t> msg;
    msg.insert(msg.end(), identity_name.begin(), identity_name.end());
    msg.insert(msg.end(), challenge.begin(), challenge.end());
    // timestamp as 8 big-endian bytes
    for (int i = 7; i >= 0; --i) {
        msg.push_back(static_cast<uint8_t>((timestamp_ms >> (i * 8)) & 0xFF));
    }
    return msg;
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

Identity::Identity(const std::string& name) : name_(name) {
    // Generate secp256k1 keypair via EVP_PKEY_keygen
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!ctx) {
        throw std::runtime_error("EVP_PKEY_CTX_new_from_name failed: " + openssl_error_string());
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_keygen_init failed: " + openssl_error_string());
    }

    // Set curve to secp256k1
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp256k1) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("set_ec_paramgen_curve_nid(secp256k1) failed: " + openssl_error_string());
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_keygen failed: " + openssl_error_string());
    }

    EVP_PKEY_CTX_free(ctx);
    pkey_ = pkey;
}

Identity::~Identity() {
    if (pkey_) {
        EVP_PKEY_free(raw_pkey(pkey_));
        pkey_ = nullptr;
    }
}

Identity::Identity(Identity&& other) noexcept
    : name_(std::move(other.name_))
    , pkey_(other.pkey_)
{
    other.pkey_ = nullptr;
}

Identity& Identity::operator=(Identity&& other) noexcept {
    if (this != &other) {
        if (pkey_) EVP_PKEY_free(raw_pkey(pkey_));
        name_       = std::move(other.name_);
        pkey_       = other.pkey_;
        other.pkey_ = nullptr;
    }
    return *this;
}

std::vector<uint8_t> Identity::public_key_der() const {
    unsigned char* buf = nullptr;
    int len = i2d_PUBKEY(raw_pkey(pkey_), &buf);
    if (len <= 0 || !buf) {
        throw std::runtime_error("i2d_PUBKEY failed: " + openssl_error_string());
    }
    std::vector<uint8_t> result(buf, buf + len);
    OPENSSL_free(buf);
    return result;
}

std::vector<uint8_t> Identity::sign(const std::vector<uint8_t>& message) const {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) throw std::runtime_error("EVP_MD_CTX_new failed");

    if (EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, raw_pkey(pkey_)) <= 0) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestSignInit failed: " + openssl_error_string());
    }

    if (EVP_DigestSignUpdate(mdctx, message.data(), message.size()) <= 0) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestSignUpdate failed: " + openssl_error_string());
    }

    // First call: get required length
    size_t sig_len = 0;
    if (EVP_DigestSignFinal(mdctx, nullptr, &sig_len) <= 0) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestSignFinal (len) failed: " + openssl_error_string());
    }

    std::vector<uint8_t> sig(sig_len);
    if (EVP_DigestSignFinal(mdctx, sig.data(), &sig_len) <= 0) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestSignFinal failed: " + openssl_error_string());
    }
    sig.resize(sig_len);

    EVP_MD_CTX_free(mdctx);
    return sig;
}

bool Identity::verify(const std::vector<uint8_t>& message,
                      const std::vector<uint8_t>& signature,
                      const std::vector<uint8_t>& public_key_der)
{
    // Decode DER public key
    const unsigned char* ptr = public_key_der.data();
    EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &ptr,
                                 static_cast<long>(public_key_der.size()));
    if (!pkey) return false;

    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        return false;
    }

    bool valid = false;

    if (EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) > 0 &&
        EVP_DigestVerifyUpdate(mdctx, message.data(), message.size()) > 0 &&
        EVP_DigestVerifyFinal(mdctx,
                              signature.data(),
                              signature.size()) == 1)
    {
        valid = true;
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return valid;
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

SignedRequest make_signed_request(const Identity&             identity,
                                  const std::vector<uint8_t>& challenge)
{
    SignedRequest req;
    req.identity_name = identity.name();
    req.challenge     = challenge;

    auto now = std::chrono::system_clock::now();
    req.timestamp_ms  = std::chrono::duration_cast<std::chrono::milliseconds>(
                            now.time_since_epoch()).count();

    auto msg      = build_request_message(req.identity_name, req.challenge, req.timestamp_ms);
    req.signature = identity.sign(msg);
    return req;
}

bool verify_signed_request(const SignedRequest&         request,
                            const std::vector<uint8_t>& expected_challenge,
                            const std::vector<uint8_t>& public_key_der)
{
    // Challenge must match exactly
    if (request.challenge != expected_challenge) {
        return false;
    }

    auto msg = build_request_message(request.identity_name,
                                     request.challenge,
                                     request.timestamp_ms);

    return Identity::verify(msg, request.signature, public_key_der);
}

std::vector<uint8_t> generate_challenge(size_t length) {
    std::vector<uint8_t> buf(length);
    if (RAND_bytes(buf.data(), static_cast<int>(length)) != 1) {
        throw std::runtime_error("RAND_bytes failed: " + openssl_error_string());
    }
    return buf;
}

} // namespace crypto
} // namespace astartis

// Made with Bob
