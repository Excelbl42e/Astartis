#ifndef ASTARTIS_PACKET_SENSOR_H
#define ASTARTIS_PACKET_SENSOR_H

/*
 * Step 5 — Packet Capture Entropy Detection
 *
 * Primary path : live Npcap capture via pcap_dispatch() on the first
 *                available non-loopback adapter.
 * Fallback path: SyntheticInjector — only activated when pcap_findalldevs()
 *                finds no usable adapter (e.g. a CI environment with no NIC).
 *                It is NOT the primary path.
 *
 * Per-packet:
 *   Compute per-byte Shannon entropy of the captured payload.
 *   Entropy is in [0, 8] bits.  Threat score is (entropy / 8) * 100:
 *     - Near-random / encrypted traffic → high entropy → high score
 *     - Structured plaintext            → low entropy  → lower score
 *   This models OMIDAX Layer 1's concern: unexpectedly high entropy on a
 *   port/protocol where you'd normally see structured text (HTTP, DNS, SMTP)
 *   is a strong indicator of encrypted C2 or exfiltration tunnelling.
 *
 * Window accumulation:
 *   EntropyWindow aggregates WINDOW_SIZE packets and emits a result
 *   (mean / max / min entropy, derived threat score) via callback.
 *   Every window result is also written to the AuditChain.
 *
 * Anomaly flag:
 *   If mean entropy > ANOMALY_ENTROPY_THRESHOLD the window is flagged
 *   anomalous — this is the signal that Step 7's rule engine watches to
 *   trigger the WORM lockdown independently of a full breach.
 */

// Suppress Windows min/max macros so std::min / std::max compile correctly.
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <thread>
#include <mutex>
#include <cstdint>

// Forward-declare pcap_pkthdr in global scope so the static callback
// signature compiles without pulling all of pcap.h into user headers.
// The .cpp includes pcap.h which provides the real definition.
struct pcap_pkthdr;

namespace astartis {
namespace sensor {

// ---------------------------------------------------------------------------
// Entropy window result
// ---------------------------------------------------------------------------

/**
 * @brief Result of accumulating WINDOW_SIZE captured packets.
 */
struct EntropyWindow {
    uint64_t    window_index;       ///< monotonically increasing sequence number
    size_t      packet_count;       ///< packets in this window (≤ WINDOW_SIZE)
    double      mean_entropy_bits;  ///< mean Shannon entropy across all packets
    double      max_entropy_bits;   ///< highest single-packet entropy
    double      min_entropy_bits;   ///< lowest single-packet entropy
    int         threat_score;       ///< 0–100, derived from mean_entropy_bits
    bool        anomalous;          ///< true if mean_entropy > ANOMALY_THRESHOLD
    bool        synthetic;          ///< true if produced by the fallback injector
    std::string adapter_name;       ///< pcap device name (or "synthetic" for fallback)
};

// ---------------------------------------------------------------------------
// Entropy calculation (pure, no pcap dependency)
// ---------------------------------------------------------------------------

/**
 * @brief Compute Shannon entropy of a byte buffer in bits (0–8).
 *
 * @param data  Pointer to raw bytes.
 * @param len   Number of bytes.  Returns 0.0 for empty input.
 */
double compute_entropy(const uint8_t* data, size_t len);

/** Convert entropy bits to a 0–100 threat score. */
int entropy_to_threat_score(double entropy_bits);

// ---------------------------------------------------------------------------
// PacketSensor — primary capture path
// ---------------------------------------------------------------------------

/**
 * @brief Live Npcap packet capture with per-window entropy reporting.
 *
 * Opens the first non-loopback pcap adapter, runs a background capture
 * thread, and calls the window_callback every WINDOW_SIZE packets.
 *
 * If no adapter is found at open(), is_synthetic() returns true and the
 * SyntheticInjector is used transparently — the callback interface is
 * identical either way so callers never need to branch.
 */
class PacketSensor {
public:
    static constexpr size_t DEFAULT_WINDOW_SIZE       = 50;   ///< packets per window (production)
    static constexpr double ANOMALY_ENTROPY_THRESHOLD = 7.2;  ///< bits; above → anomalous

    // Kept for backward compatibility with any code using PacketSensor::WINDOW_SIZE.
    static constexpr size_t WINDOW_SIZE = DEFAULT_WINDOW_SIZE;

    /**
     * @param window_callback  Called on the capture thread each time a
     *                         full window of `window_size` packets is complete.
     * @param audit_adder      Callable (event_type, payload) -> entry_id,
     *                         wired to AuditChain::add_entry.
     * @param iface_hint       Optional: preferred adapter name.  Empty = auto-select.
     * @param window_size      Packets per entropy window.  Default 50 (production).
     *                         Tests may set this lower (e.g. 10) to complete quickly.
     */
    explicit PacketSensor(
        std::function<void(const EntropyWindow&)> window_callback,
        std::function<std::string(const std::string&, const std::string&)> audit_adder,
        const std::string& iface_hint = "",
        size_t window_size = DEFAULT_WINDOW_SIZE
    );

    ~PacketSensor();

    // Non-copyable.
    PacketSensor(const PacketSensor&)            = delete;
    PacketSensor& operator=(const PacketSensor&) = delete;

    /**
     * @brief Start the background capture thread.
     *
     * If no Npcap adapter is available, silently starts the synthetic
     * injector thread instead and sets is_synthetic() = true.
     *
     * @return true if a real adapter was opened, false if fallback.
     * @throws std::runtime_error if both real and synthetic start fail.
     */
    bool start();

    /**
     * @brief Stop the background thread and close the pcap handle.
     * Safe to call even if start() was never called or already stopped.
     */
    void stop();

    /** True if running in synthetic (fallback) mode. */
    bool is_synthetic() const { return synthetic_mode_; }

    /** True if the background thread is running. */
    bool is_running() const { return running_; }

    /** Adapter name used (or "synthetic"). */
    std::string adapter_name() const { return adapter_name_; }

    /** Total windows emitted since start(). */
    uint64_t windows_emitted() const { return window_index_.load(); }

private:
    // Real capture thread body — calls pcap_dispatch in a loop.
    void capture_loop();

    // Synthetic injector thread body — generates pseudo-random frames.
    void synthetic_loop();

    // Called by the pcap callback (static trampoline → instance method).
    void on_packet(const uint8_t* data, uint32_t len);

    // Emit and reset the accumulator when it reaches WINDOW_SIZE.
    // flush_window()        acquires window_mutex_ then calls flush_window_locked().
    // flush_window_locked() must be called with window_mutex_ already held.
    void flush_window(bool force = false);
    void flush_window_locked();

    // Static pcap callback — user_data is `this`.
    static void pcap_callback(uint8_t* user_data,
                              const struct pcap_pkthdr* header,
                              const uint8_t* packet);

    // Attempt to open the best available real adapter.
    // Returns nullptr (and sets adapter_name_ = "") on failure.
    void* open_best_adapter(const std::string& hint);

    std::function<void(const EntropyWindow&)>                           window_cb_;
    std::function<std::string(const std::string&, const std::string&)>  audit_adder_;
    std::string                                                          iface_hint_;
    size_t                                                               window_size_;

    void*       pcap_handle_  = nullptr;  // pcap_t* — opaque to keep pcap.h out of this header
    std::string adapter_name_;

    std::atomic<bool>     running_       {false};
    std::atomic<bool>     synthetic_mode_{false};
    std::atomic<uint64_t> window_index_  {0};

    std::thread capture_thread_;
    mutable std::mutex window_mutex_;

    // Window accumulator — protected by window_mutex_
    std::vector<double> entropy_accum_;   // per-packet entropy values in current window
};

// ---------------------------------------------------------------------------
// SyntheticInjector — fallback / test helper
// ---------------------------------------------------------------------------

/**
 * @brief Generates synthetic packet frames for entropy testing without Npcap.
 *
 * Used ONLY when no real adapter is available (CI environments, VMs
 * without a NIC driver).  Not the primary path.
 *
 * Frame categories generated in rotation:
 *   1. Near-random (high entropy)  — simulates encrypted/tunnelled traffic
 *   2. Structured ASCII            — simulates plaintext HTTP/DNS
 *   3. Repetitive pattern          — simulates ARP / keep-alive spam
 *
 * Consumers receive the same EntropyWindow callback as with real capture.
 */
class SyntheticInjector {
public:
    static constexpr size_t DEFAULT_PACKET_SIZE = 128;

    /**
     * @brief Generate one synthetic packet of the given category.
     *
     * @param category  0 = near-random, 1 = structured, 2 = repetitive
     * @param out       Buffer to fill (resized to DEFAULT_PACKET_SIZE)
     */
    static void make_packet(int category, std::vector<uint8_t>& out);

    /**
     * @brief Generate `count` packets cycling through all categories.
     *        Useful in unit tests for exercising the entropy calculator.
     */
    static std::vector<std::vector<uint8_t>> make_batch(size_t count);
};

} // namespace sensor
} // namespace astartis

#endif // ASTARTIS_PACKET_SENSOR_H

// Made with Bob
