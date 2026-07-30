// granite_client.h -- Local IBM Granite AI client (Astartis v3.0)
//
// Zero API cost policy: ONLY these four model tags are allowed (all local Ollama):
//   granite3.1-moe:3b      (FAST)        — latency-critical tasks
//   granite3.1-dense:8b    (HEAVY)       — standard reasoning, analysis
//   granite4.1-8b-q5_K_M   (ACCURACY)    — highest precision, forensics, crypto
//   granite4.1-8b-q5_K_M   (ORCHESTRATOR)— same binary as ACCURACY; prefix injected
//
// Any attempt to call a non-allowed model is rejected with an audit entry.
// No cloud endpoints. No OpenAI. No Anthropic. Local Ollama only.

#ifndef ASTARTIS_GRANITE_CLIENT_H
#define ASTARTIS_GRANITE_CLIENT_H

#include <string>
#include <functional>
#include <future>
#include <thread>
#include <atomic>
#include <cstdint>

namespace astartis {
namespace agents {

// Which Granite model tier to use
enum class GraniteModel {
    FAST,         ///< granite3.1-moe:3b       — ultra-low latency, high throughput
    HEAVY,        ///< granite3.1-dense:8b     — standard reasoning, analysis
    ACCURACY,     ///< granite4.1-8b-q5_K_M   — deep reasoning, highest precision
    ORCHESTRATOR  ///< granite4.1-8b-q5_K_M   — same model, ORCHESTRATOR prefix injected
};

struct GraniteResponse {
    bool        ok;           ///< false = timeout / Ollama unavailable / model rejected
    std::string text;         ///< raw model response text
    std::string model_used;   ///< actual model tag or "rejected"/"timeout"/"unavailable"
    int         tokens_used;  ///< approximate token count (from Ollama metadata)
};

class GraniteClient {
public:
    // Model tags — FAST and HEAVY are the existing granite3.1 models.
    // ACCURACY and ORCHESTRATOR both point to the same granite4.1 binary;
    // the difference is the system prompt prefix injected by generate().
    static constexpr const char* FAST_MODEL_TAG         = "granite3.1-moe:3b";
    static constexpr const char* HEAVY_MODEL_TAG        = "granite3.1-dense:8b";
    static constexpr const char* ACCURACY_MODEL_TAG     = "ibm/granite4.1:8b-q5_K_M";
    static constexpr const char* ORCHESTRATOR_MODEL_TAG = "ibm/granite4.1:8b-q5_K_M";

    static constexpr const char* DEFAULT_HOST = "127.0.0.1";
    static constexpr uint16_t    DEFAULT_PORT = 11434;

    // Per-tier timeouts (milliseconds)
    // ACCURACY and ORCHESTRATOR both run ibm/granite4.1:8b-q5_K_M on CPU.
    // Measured on Kgosi's laptop: ~520ms/token. 256 tokens ≈ 133s warm.
    // 360s gives comfortable headroom for cold-load and token variance.
    static constexpr int FAST_TIMEOUT_MS         = 30000;
    static constexpr int HEAVY_TIMEOUT_MS        = 60000;
    static constexpr int ACCURACY_TIMEOUT_MS     = 360000;
    static constexpr int ORCHESTRATOR_TIMEOUT_MS = 360000;

    /**
     * @param audit_adder  Callable for audit logging.
     * @param host         Ollama host (default 127.0.0.1).
     * @param port         Ollama port (default 11434).
     */
    explicit GraniteClient(
        std::function<std::string(const std::string&, const std::string&)> audit_adder,
        const std::string& host = DEFAULT_HOST,
        uint16_t           port = DEFAULT_PORT
    );

    ~GraniteClient();

    GraniteClient(const GraniteClient&)            = delete;
    GraniteClient& operator=(const GraniteClient&) = delete;

    /**
     * @brief Generate text from the specified Granite model tier.
     *
     * For GraniteModel::ORCHESTRATOR, the ORCHESTRATOR_PROMPT_PREFIX is
     * prepended to system_prompt before sending to Ollama.
     * Returns GraniteResponse with ok=false on any error.
     */
    GraniteResponse generate(GraniteModel       model,
                             const std::string& system_prompt,
                             const std::string& user_prompt,
                             int                max_tokens   = 256,
                             double             temperature  = 0.3);

    /**
     * @brief Async version of generate(). Returns a future that resolves
     *        when Ollama responds. The HTTP call runs on a separate thread.
     */
    std::future<GraniteResponse> generateAsync(GraniteModel       model,
                                               const std::string& system_prompt,
                                               const std::string& user_prompt,
                                               int                max_tokens   = 256,
                                               double             temperature  = 0.3);

    /**
     * @brief Check that Ollama is reachable (GET /api/tags).
     */
    bool ping() const;

    const std::string& host() const { return host_; }
    uint16_t           port() const { return port_; }

    /**
     * @brief Start a background thread that pings each loaded model
     *        every interval_ms to keep them warm in Ollama's cache.
     *        Default: 60 seconds.
     */
    void start_keep_alive(int interval_ms = 60000);

    /**
     * @brief Stop the keep-alive background thread.
     */
    void stop_keep_alive();

private:
    // S2.3: increment the right in-flight counter for a given model tier
    void increment_inflight(GraniteModel m) const;
    void decrement_inflight(GraniteModel m) const;

    std::string call_ollama_api(const std::string& model_tag,
                                const std::string& system_prompt,
                                const std::string& user_prompt,
                                int                max_tokens,
                                double             temperature,
                                int                timeout_ms) const;

    static bool is_allowed_model(const std::string& tag);

    std::function<std::string(const std::string&, const std::string&)> audit_adder_;
    std::string              host_;
    uint16_t                 port_;
    std::thread              keep_alive_thread_;
    std::atomic<bool>        keep_alive_running_{false};
    int                      keep_alive_interval_ms_ = 60000;

    // S2.2: in-flight async counter — destructor warns if non-zero
    mutable std::atomic<int> inflight_async_{0};

    // S2.3: per-tier in-flight counters — keep-alive skips busy tiers
    mutable std::atomic<int> inflight_fast_{0};
    mutable std::atomic<int> inflight_heavy_{0};
    mutable std::atomic<int> inflight_accuracy_{0};
};

} // namespace agents
} // namespace astartis

#endif // ASTARTIS_GRANITE_CLIENT_H

// Made with Bob
