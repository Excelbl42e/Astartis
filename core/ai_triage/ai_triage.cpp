// Step 18 -- AiTriage implementation
// See ai_triage.h for API documentation.

// Winsock2 before windows.h
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#pragma warning(push)
#pragma warning(disable: 4706 4127 4244)
#include "nlohmann/json.hpp"
#pragma warning(pop)

#include "ai_triage/ai_triage.h"

#include <sstream>
#include <iomanip>
#include <algorithm>
#include <stdexcept>
#include <cstring>
#include <chrono>

using json = nlohmann::json;

namespace astartis {
namespace ai {

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

AiTriage::AiTriage(
    std::function<std::string(const std::string&, const std::string&)> audit_adder,
    astartis::rules::RuleEngine& rule_engine,
    const std::string& ollama_host,
    uint16_t           ollama_port
)
    : audit_adder_(std::move(audit_adder))
    , rule_engine_(rule_engine)
    , host_(ollama_host)
    , port_(ollama_port)
{
    // P1 fix: initialise Winsock once here, not per-request.
    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);
}

AiTriage::~AiTriage()
{
    // Matching cleanup for the single WSAStartup in the constructor.
    WSACleanup();
}

// ---------------------------------------------------------------------------
// WinSock2 HTTP helper
// ---------------------------------------------------------------------------

// Send an HTTP POST to /api/generate and return the full response body.
// Returns "" on any error (connection refused, timeout, parse failure).
std::string AiTriage::call_ollama(const std::string& model,
                                   const std::string& prompt,
                                   int                timeout_ms) const
{
    // Build JSON body
    json req_body = {
        {"model",  model},
        {"prompt", prompt},
        {"stream", false},
        {"options", {{"num_predict", 128}}}  // cap tokens for speed
    };
    std::string body = req_body.dump();

    // Build HTTP request
    std::ostringstream req;
    req << "POST /api/generate HTTP/1.0\r\n"
        << "Host: " << host_ << ":" << port_ << "\r\n"
        << "Content-Type: application/json\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Connection: close\r\n"
        << "\r\n"
        << body;
    std::string request_str = req.str();

    // Resolve & connect (Winsock already initialised in constructor — no WSAStartup here)
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    std::string port_str = std::to_string(port_);
    if (getaddrinfo(host_.c_str(), port_str.c_str(), &hints, &res) != 0) {
        return "";
    }

    SOCKET sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(res); return "";
    }

    // Connect timeout via non-blocking connect + select
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
    connect(sock, res->ai_addr, static_cast<int>(res->ai_addrlen));
    freeaddrinfo(res);

    fd_set wfds; FD_ZERO(&wfds); FD_SET(sock, &wfds);
    // Use a fixed 5s connect timeout regardless of timeout_ms
    timeval tv_connect{5, 0};
    int sel = select(0, nullptr, &wfds, nullptr, &tv_connect);
    if (sel <= 0) {
        closesocket(sock); return "";
    }
    // Check that connect actually succeeded
    int err = 0; int errlen = sizeof(err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &errlen);
    if (err != 0) { closesocket(sock); return ""; }

    // Switch back to blocking, apply receive timeout
    mode = 0; ioctlsocket(sock, FIONBIO, &mode);
    DWORD rcv_timeout = static_cast<DWORD>(timeout_ms);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&rcv_timeout), sizeof(rcv_timeout));

    // Send request
    const char* ptr = request_str.data();
    int remaining   = static_cast<int>(request_str.size());
    while (remaining > 0) {
        int sent = send(sock, ptr, remaining, 0);
        if (sent <= 0) { closesocket(sock); return ""; }
        ptr += sent; remaining -= sent;
    }

    // Receive response
    std::string response;
    char buf[4096];
    while (true) {
        int n = recv(sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;  // connection closed or timeout
        buf[n] = '\0';
        response += buf;
    }
    closesocket(sock);

    // Strip HTTP headers — find \r\n\r\n
    auto pos = response.find("\r\n\r\n");
    if (pos == std::string::npos) return "";
    return response.substr(pos + 4);
}

// ---------------------------------------------------------------------------
// ping
// ---------------------------------------------------------------------------

bool AiTriage::ping() const
{
    // Winsock already initialised in constructor — just connect and check.
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    std::string port_str = std::to_string(port_);
    if (getaddrinfo(host_.c_str(), port_str.c_str(), &hints, &res) != 0) {
        return false;
    }
    SOCKET sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == INVALID_SOCKET) { freeaddrinfo(res); return false; }

    u_long nb = 1; ioctlsocket(sock, FIONBIO, &nb);
    connect(sock, res->ai_addr, static_cast<int>(res->ai_addrlen));
    freeaddrinfo(res);
    fd_set wfds; FD_ZERO(&wfds); FD_SET(sock, &wfds);
    timeval tv{3, 0};
    int sel = select(0, nullptr, &wfds, nullptr, &tv);
    closesocket(sock);
    return sel > 0;
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

std::string AiTriage::extract_response(const std::string& ollama_json)
{
    // Ollama /api/generate with stream:false returns:
    // {"model":"...","response":"<text>","done":true,...}
    try {
        auto j = json::parse(ollama_json);
        return j.value("response", "");
    } catch (...) {
        return "";
    }
}

FastResult AiTriage::parse_fast(const std::string& model_json,
                                 const std::string& model_tag,
                                 bool timed_out)
{
    FastResult r;
    r.model_used = model_tag;
    r.timed_out  = timed_out;
    r.parse_ok   = false;
    r.route          = "handle";
    r.severity_hint  = "LOW";
    r.confidence     = 0.0;

    if (timed_out || model_json.empty()) {
        r.model_used = timed_out ? "fallback_timeout" : "fallback_unavailable";
        return r;
    }
    try {
        // The model is prompted to return JSON; find the first '{' in case
        // there's any leading whitespace or boilerplate.
        auto start = model_json.find('{');
        auto end   = model_json.rfind('}');
        if (start == std::string::npos || end == std::string::npos) return r;
        auto j = json::parse(model_json.substr(start, end - start + 1));
        r.route         = j.value("route", "handle");
        r.severity_hint = j.value("severity_hint", "LOW");
        r.confidence    = j.value("confidence", 0.5);
        r.parse_ok      = true;
    } catch (...) {}
    return r;
}

HeavyResult AiTriage::parse_heavy(const std::string& model_json,
                                   const std::string& model_tag,
                                   bool timed_out)
{
    HeavyResult r;
    r.model_used      = model_tag;
    r.timed_out       = timed_out;
    r.parse_ok        = false;
    r.severity        = "LOW";
    r.rationale       = "";
    r.mitre_technique = "";

    if (timed_out || model_json.empty()) {
        r.model_used = timed_out ? "fallback_timeout" : "fallback_unavailable";
        return r;
    }
    try {
        auto start = model_json.find('{');
        auto end   = model_json.rfind('}');
        if (start == std::string::npos || end == std::string::npos) return r;
        auto j = json::parse(model_json.substr(start, end - start + 1));
        r.severity        = j.value("severity", "LOW");
        r.rationale       = j.value("rationale", "");
        r.mitre_technique = j.value("mitre_technique", "");
        r.parse_ok        = true;
    } catch (...) {}
    return r;
}

// ---------------------------------------------------------------------------
// Conversion helpers
// ---------------------------------------------------------------------------

threat::ThreatTier AiTriage::severity_to_tier(const std::string& s)
{
    if (s == "CRITICAL") return threat::ThreatTier::CRITICAL;
    if (s == "HIGH")     return threat::ThreatTier::HIGH;
    if (s == "MEDIUM")   return threat::ThreatTier::MEDIUM;
    return threat::ThreatTier::LOW;
}

int AiTriage::tier_to_score(threat::ThreatTier t)
{
    switch (t) {
        case threat::ThreatTier::CRITICAL: return 90;
        case threat::ThreatTier::HIGH:     return 76;
        case threat::ThreatTier::MEDIUM:   return 50;
        default:                           return 10;
    }
}

// ---------------------------------------------------------------------------
// Prompt builders
// ---------------------------------------------------------------------------

std::string AiTriage::fast_prompt(const TriageInput& in)
{
    // Deterministic, structured prompt — JSON-only output enforced.
    std::ostringstream p;
    p << "You are a security triage classifier. "
      << "Reply ONLY with a single valid JSON object, no other text. "
      << "Schema: {\"route\":\"handle|escalate|ignore\","
         "\"severity_hint\":\"LOW|MEDIUM|HIGH|CRITICAL\","
         "\"confidence\":0.0-1.0}\n"
      << "Event: type=" << in.event_type
      << " source=" << in.source
      << " score=" << in.score
      << " detail=" << in.raw_detail.substr(0, 200);
    return p.str();
}

std::string AiTriage::heavy_prompt(const TriageInput& in,
                                    const FastResult&  fast)
{
    std::ostringstream p;
    p << "You are a senior security analyst. "
      << "Reply ONLY with a single valid JSON object, no other text. "
      << "Schema: {\"severity\":\"LOW|MEDIUM|HIGH|CRITICAL\","
         "\"rationale\":\"one sentence\","
         "\"mitre_technique\":\"Txxxx or empty\"}\n"
      << "Event: type=" << in.event_type
      << " source=" << in.source
      << " score=" << in.score
      << " detail=" << in.raw_detail.substr(0, 200)
      << "\nFast-tier hint: severity=" << fast.severity_hint
      << " confidence=" << fast.confidence;
    return p.str();
}

// ---------------------------------------------------------------------------
// triage() — main entry point
// ---------------------------------------------------------------------------

TriageResult AiTriage::triage(const TriageInput& input)
{
    std::lock_guard<std::mutex> lk(mutex_);

    TriageResult result;
    result.input = input;

    // ------------------------------------------------------------------
    // 1. Fast tier
    // ------------------------------------------------------------------
    std::string fast_raw    = call_ollama(FAST_MODEL,
                                          fast_prompt(input),
                                          FAST_TIMEOUT_MS);
    bool fast_timed_out = fast_raw.empty();  // empty = timeout or refused
    std::string fast_model_resp = extract_response(fast_raw);
    result.fast = parse_fast(fast_model_resp, FAST_MODEL, fast_timed_out);

    // ------------------------------------------------------------------
    // 2. Heavy tier — when escalated or low fast confidence
    // ------------------------------------------------------------------
    bool call_heavy = (result.fast.route == "escalate")
                   || (result.fast.confidence < ESCALATE_CONFIDENCE_THRESHOLD)
                   || (!result.fast.parse_ok);

    if (call_heavy) {
        std::string heavy_raw  = call_ollama(HEAVY_MODEL,
                                              heavy_prompt(input, result.fast),
                                              HEAVY_TIMEOUT_MS);
        bool heavy_timed_out = heavy_raw.empty();
        std::string heavy_model_resp = extract_response(heavy_raw);
        result.heavy = parse_heavy(heavy_model_resp, HEAVY_MODEL, heavy_timed_out);
    }

    // ------------------------------------------------------------------
    // 3. Derive model-suggested tier
    // ------------------------------------------------------------------
    std::string model_severity;
    if (result.heavy.has_value() && result.heavy->parse_ok) {
        model_severity = result.heavy->severity;
    } else {
        model_severity = result.fast.severity_hint;
    }
    result.model_suggested_tier = severity_to_tier(model_severity);

    // ------------------------------------------------------------------
    // 4. Rule engine has final authority
    // ------------------------------------------------------------------
    int advisory_score = tier_to_score(result.model_suggested_tier);
    // If model is in fallback, use the raw input score instead.
    // Also use the raw score if it maps to a higher tier than the model
    // suggested — the rule engine must never receive a score lower than what
    // the raw threat signal warrants (e.g. input.score=90 must reach CRITICAL
    // even when the model under-classifies the event).
    bool model_usable = result.fast.parse_ok ||
                        (result.heavy.has_value() && result.heavy->parse_ok);
    int score_for_rule_engine = (!model_usable || input.score > advisory_score)
                                  ? input.score
                                  : advisory_score;

    auto rule_result = rule_engine_.evaluate_threat_score(score_for_rule_engine,
                                                           "ai_triage");

    // The rule engine's current tier is ground truth.  When fired==false the
    // state machine did not transition, but it may already sit above the model
    // suggestion (e.g. prior events pushed it to CRITICAL).  Take the higher of
    // the two so final_tier never under-reports the live threat level.
    threat::ThreatTier engine_tier = rule_engine_.current_tier();
    result.final_tier = static_cast<int>(engine_tier) >= static_cast<int>(result.model_suggested_tier)
                          ? engine_tier
                          : result.model_suggested_tier;
    result.rule_engine_overrode = (result.final_tier != result.model_suggested_tier);

    // ------------------------------------------------------------------
    // 5. Audit entry
    // ------------------------------------------------------------------
    std::ostringstream payload;
    payload << "event_type=" << input.event_type
            << " score=" << input.score
            << " fast_route=" << result.fast.route
            << " fast_severity=" << result.fast.severity_hint
            << " fast_confidence=" << result.fast.confidence
            << " fast_model=" << result.fast.model_used
            << " heavy_ran=" << (result.heavy.has_value() ? "true" : "false");
    if (result.heavy.has_value()) {
        payload << " heavy_severity=" << result.heavy->severity
                << " heavy_model=" << result.heavy->model_used
                << " mitre=" << result.heavy->mitre_technique;
    }
    payload << " model_suggested=" << static_cast<int>(result.model_suggested_tier)
            << " final_tier=" << static_cast<int>(result.final_tier)
            << " overrode=" << (result.rule_engine_overrode ? "true" : "false");

    result.audit_entry_id = audit_adder_("ai_triage", payload.str());

    return result;
}

} // namespace ai
} // namespace astartis

// Made with Bob
