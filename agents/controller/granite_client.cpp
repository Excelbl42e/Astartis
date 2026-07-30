// granite_client.cpp -- Local IBM Granite client implementation (Astartis v3.0)
//
// Uses raw WinSock2 HTTP POST to /api/chat (same pattern as ai_triage.cpp).
// WSAStartup called ONCE in constructor; WSACleanup in destructor.
//
// ORCHESTRATOR tier: prepends ORCHESTRATOR_PROMPT_PREFIX to the agent's
// system prompt at dispatch time. Same physical model as ACCURACY.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#pragma warning(push)
#pragma warning(disable: 4706 4127 4244)
#include "nlohmann/json.hpp"
#pragma warning(pop)

#include "agents/controller/granite_client.h"
#include "agents/controller/orchestrator_context.h"

#include <future>
#include <thread>
#include <chrono>
#include <sstream>
#include <stdexcept>
#include <array>
#include <iostream>

using json = nlohmann::json;

namespace astartis {
namespace agents {

// All four allowed model tags.
// ACCURACY and ORCHESTRATOR share the same physical model binary.
static const std::string ALLOWED_MODELS[] = {
    GraniteClient::FAST_MODEL_TAG,
    GraniteClient::HEAVY_MODEL_TAG,
    GraniteClient::ACCURACY_MODEL_TAG
    // ORCHESTRATOR_MODEL_TAG is identical to ACCURACY_MODEL_TAG — deduplicated.
};

GraniteClient::GraniteClient(
    std::function<std::string(const std::string&, const std::string&)> audit_adder,
    const std::string& host,
    uint16_t           port)
    : audit_adder_(std::move(audit_adder))
    , host_(host)
    , port_(port)
{
    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);
}

GraniteClient::~GraniteClient()
{
    stop_keep_alive();
    // S2.2: warn if async tasks are still in flight at destruction time
    int in_flight = inflight_async_.load();
    if (in_flight > 0) {
        std::cerr << "[GraniteClient] WARNING: destroyed with " << in_flight
                  << " async task(s) still in flight — possible dangling this ptr.\n";
    }
    WSACleanup();
}

void GraniteClient::increment_inflight(GraniteModel m) const {
    switch (m) {
        case GraniteModel::FAST:         ++inflight_fast_;     break;
        case GraniteModel::HEAVY:        ++inflight_heavy_;    break;
        case GraniteModel::ACCURACY:
        case GraniteModel::ORCHESTRATOR: ++inflight_accuracy_; break;
        default: break;
    }
}

void GraniteClient::decrement_inflight(GraniteModel m) const {
    switch (m) {
        case GraniteModel::FAST:         --inflight_fast_;     break;
        case GraniteModel::HEAVY:        --inflight_heavy_;    break;
        case GraniteModel::ACCURACY:
        case GraniteModel::ORCHESTRATOR: --inflight_accuracy_; break;
        default: break;
    }
}

bool GraniteClient::is_allowed_model(const std::string& tag)
{
    for (const auto& m : ALLOWED_MODELS) {
        if (m == tag) return true;
    }
    return false;
}

bool GraniteClient::ping() const
{
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    std::string port_str = std::to_string(port_);
    if (getaddrinfo(host_.c_str(), port_str.c_str(), &hints, &res) != 0) return false;
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

std::string GraniteClient::call_ollama_api(const std::string& model_tag,
                                            const std::string& system_prompt,
                                            const std::string& user_prompt,
                                            int                max_tokens,
                                            double             temperature,
                                            int                timeout_ms) const
{
    // S3.1: total wall-clock budget = timeout_ms; checked each recv iteration.
    // S3.1: max response body size = 8 MB to prevent memory exhaustion.
    static constexpr size_t MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(timeout_ms);

    // Build /api/chat request
    json req_body = {
        {"model",  model_tag},
        {"stream", false},
        {"options", {
            {"num_predict",  max_tokens},
            {"temperature",  temperature}
        }},
        {"messages", json::array({
            {{"role", "system"}, {"content", system_prompt}},
            {{"role", "user"},   {"content", user_prompt}}
        })}
    };
    std::string body = req_body.dump();

    std::ostringstream req;
    req << "POST /api/chat HTTP/1.0\r\n"
        << "Host: " << host_ << ":" << port_ << "\r\n"
        << "Content-Type: application/json\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Connection: close\r\n"
        << "\r\n"
        << body;
    std::string request_str = req.str();

    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    std::string port_str = std::to_string(port_);
    if (getaddrinfo(host_.c_str(), port_str.c_str(), &hints, &res) != 0) return "";

    SOCKET sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == INVALID_SOCKET) { freeaddrinfo(res); return ""; }

    u_long mode = 1; ioctlsocket(sock, FIONBIO, &mode);
    connect(sock, res->ai_addr, static_cast<int>(res->ai_addrlen));
    freeaddrinfo(res);

    fd_set wfds; FD_ZERO(&wfds); FD_SET(sock, &wfds);
    timeval tv_connect{5, 0};
    if (select(0, nullptr, &wfds, nullptr, &tv_connect) <= 0) {
        closesocket(sock); return "";
    }
    int err = 0, errlen = sizeof(err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &errlen);
    if (err != 0) { closesocket(sock); return ""; }

    mode = 0; ioctlsocket(sock, FIONBIO, &mode);
    // Per-recv timeout = 2s chunks; total budget enforced by deadline check below.
    // SO_SNDTIMEO set alongside SO_RCVTIMEO so a blocking send() cannot hang
    // past the tier timeout either (Bug 4 fix).
    DWORD rcv_timeout = 2000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&rcv_timeout), sizeof(rcv_timeout));
    DWORD snd_timeout = 2000;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
               reinterpret_cast<const char*>(&snd_timeout), sizeof(snd_timeout));

    const char* ptr = request_str.data();
    int remaining = static_cast<int>(request_str.size());
    while (remaining > 0) {
        if (std::chrono::steady_clock::now() >= deadline) {
            // Deadline fired during send — return DEADLINE sentinel so generate()
            // classifies this as a timeout, not "unavailable" (Bug 5 fix).
            // Use the same sentinel format as the recv-loop deadline path.
            closesocket(sock);
            return std::string(1, '\0') + "DEADLINE";
        }
        int sent = send(sock, ptr, remaining, 0);
        if (sent <= 0) { closesocket(sock); return ""; }
        ptr += sent; remaining -= sent;
    }

    // S3.2: distinguish truncated vs parse error via sentinel suffix
    std::string response;
    bool size_exceeded = false;
    char buf[4096];
    while (true) {
        // S3.1: check total wall-clock deadline
        if (std::chrono::steady_clock::now() >= deadline) {
            // Mark as truncated — distinct from a clean disconnect
            size_exceeded = false;  // deadline hit
            response += "\x00" "DEADLINE";  // sentinel for caller (string concat avoids greedy hex parse)
            break;
        }
        int n = recv(sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;
        buf[n] = '\0';
        response.append(buf, static_cast<size_t>(n));
        // S3.1: max size cap
        if (response.size() > MAX_RESPONSE_BYTES) {
            size_exceeded = true;
            break;
        }
    }
    closesocket(sock);

    if (size_exceeded) {
        // S3.2: return a sentinel that generate() will turn into "truncated_response"
        return "\x00" "TRUNCATED";   // string concat avoids greedy \x00TRU... hex escape
    }

    auto pos = response.find("\r\n\r\n");
    if (pos == std::string::npos) return "";
    return response.substr(pos + 4);
}

GraniteResponse GraniteClient::generate(GraniteModel       model,
                                         const std::string& system_prompt,
                                         const std::string& user_prompt,
                                         int                max_tokens,
                                         double             temperature)
{
    GraniteResponse resp;

    // Determine model tag and timeout based on tier
    const char* tag;
    int timeout;
    switch (model) {
        case GraniteModel::FAST:
            tag     = FAST_MODEL_TAG;
            timeout = FAST_TIMEOUT_MS;
            break;
        case GraniteModel::HEAVY:
            tag     = HEAVY_MODEL_TAG;
            timeout = HEAVY_TIMEOUT_MS;
            break;
        case GraniteModel::ACCURACY:
            tag     = ACCURACY_MODEL_TAG;
            timeout = ACCURACY_TIMEOUT_MS;
            break;
        case GraniteModel::ORCHESTRATOR:
            tag     = ORCHESTRATOR_MODEL_TAG;
            timeout = ORCHESTRATOR_TIMEOUT_MS;
            break;
        default:
            tag     = HEAVY_MODEL_TAG;
            timeout = HEAVY_TIMEOUT_MS;
            break;
    }

    // Zero API cost enforcement: reject any non-local model tag
    if (!is_allowed_model(tag)) {
        audit_adder_("ai_model_rejected",
                     std::string("requested=") + tag + " reason=not_local_granite");
        resp.ok         = false;
        resp.model_used = "rejected";
        return resp;
    }

    // S2.3: mark this tier as in-flight so keep-alive skips it
    increment_inflight(model);

    // For ORCHESTRATOR tier: prepend the orchestrator coordination prefix
    std::string effective_system_prompt;
    if (model == GraniteModel::ORCHESTRATOR) {
        effective_system_prompt = astartis::ORCHESTRATOR_PROMPT_PREFIX;
        effective_system_prompt += system_prompt;
        audit_adder_("orchestrator_prefix_injected",
                     "agent_prompt_len=" + std::to_string(system_prompt.size()));
    } else {
        effective_system_prompt = system_prompt;
    }

    std::string raw = call_ollama_api(tag, effective_system_prompt, user_prompt,
                                      max_tokens, temperature, timeout);
    if (raw.empty()) {
        resp.ok         = false;
        resp.model_used = "unavailable";
        return resp;
    }
    // S3.2: sentinel check — distinguish truncated/deadline from parse_error
    if (raw.find("\x00" "TRUNCATED") != std::string::npos) {
        resp.ok         = false;
        resp.model_used = "truncated_response";
        audit_adder_("ollama_response_truncated",
                     "model=" + std::string(tag) + " reason=max_size_exceeded");
        return resp;
    }
    if (raw.find("\x00" "DEADLINE") != std::string::npos) {
        resp.ok         = false;
        resp.model_used = "timeout";
        audit_adder_("ollama_response_timeout",
                     "model=" + std::string(tag));
        return resp;
    }

    try {
        auto j = json::parse(raw);

        // Check for Ollama error response (e.g. model not found)
        if (j.contains("error")) {
            resp.ok         = false;
            resp.model_used = "unavailable";
            decrement_inflight(model);
            return resp;
        }

        // /api/chat response: {"message":{"role":"assistant","content":"..."}}
        if (j.contains("message") && j["message"].contains("content")) {
            resp.text = j["message"]["content"].get<std::string>();
        } else if (j.contains("response")) {
            resp.text = j["response"].get<std::string>();
        }

        // If we got no usable content, treat as unavailable
        if (resp.text.empty()) {
            resp.ok         = false;
            resp.model_used = "unavailable";
            decrement_inflight(model);
            return resp;
        }

        resp.ok          = true;
        resp.model_used  = tag;
        resp.tokens_used = j.value("eval_count", 0);
    } catch (...) {
        resp.ok         = false;
        resp.model_used = "parse_error";
    }
    decrement_inflight(model);
    return resp;
}

std::future<GraniteResponse> GraniteClient::generateAsync(GraniteModel       model,
                                                           const std::string& system_prompt,
                                                           const std::string& user_prompt,
                                                           int                max_tokens,
                                                           double             temperature)
{
    // S2.2 fix: track in-flight async count so destructor can warn if
    // the client is destroyed while an async task is still running.
    // Callers must ensure the GraniteClient outlives all futures they hold.
    ++inflight_async_;
    return std::async(std::launch::async,
                      [this, model, system_prompt, user_prompt, max_tokens, temperature]() {
                          auto result = generate(model, system_prompt, user_prompt,
                                                 max_tokens, temperature);
                          --inflight_async_;
                          return result;
                      });
}

void GraniteClient::start_keep_alive(int interval_ms)
{
    keep_alive_interval_ms_ = interval_ms;
    if (keep_alive_running_.exchange(true)) return;  // already running

    keep_alive_thread_ = std::thread([this]() {
        while (keep_alive_running_.load()) {
            // S2.3 fix: skip keep-alive ping for a model tier if that tier
            // currently has an in-flight real inference request.
            // Prevents keep-alive from stealing GPU/CPU from live triage tasks.
            struct { const char* tag; std::atomic<int>& counter; } tiers[] = {
                { FAST_MODEL_TAG,     inflight_fast_     },
                { HEAVY_MODEL_TAG,    inflight_heavy_    },
                { ACCURACY_MODEL_TAG, inflight_accuracy_ },
            };
            for (auto& t : tiers) {
                if (!keep_alive_running_.load()) break;
                if (t.counter.load() > 0) {
                    // Real inference in progress — skip this tier's keep-alive
                    std::cerr << "[KeepAlive] Skipping " << t.tag
                              << " — real inference in flight\n";
                    continue;
                }
                call_ollama_api(t.tag, "keep-alive", "ok", 1, 0.0, 10000);
            }
            // Sleep in small chunks so we can exit quickly on stop()
            int steps = keep_alive_interval_ms_ / 100;
            for (int i = 0; i < steps; ++i) {
                if (!keep_alive_running_.load()) break;
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    });
}

void GraniteClient::stop_keep_alive()
{
    if (!keep_alive_running_.exchange(false)) return;
    if (keep_alive_thread_.joinable()) {
        keep_alive_thread_.join();
    }
}

// S3.6: route_and_generate deleted — confirmed dead code in production.
// AgentController::execute_task calls generate() directly with the persona's
// preferred_model. The only caller was test_granite_client.cpp (test only).
// Test updated to call generate() with explicit GraniteModel::FAST instead.

} // namespace agents
} // namespace astartis

// Made with Bob
