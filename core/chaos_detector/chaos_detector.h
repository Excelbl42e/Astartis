#ifndef ASTARTIS_CHAOS_DETECTOR_H
#define ASTARTIS_CHAOS_DETECTOR_H

/*
 * Step 12 -- Chaos-Theoretic Precursor Detection (OMIDAX Layer 1 extension)
 *
 * Implements the Gottwald-Melbourne 0-1 test for chaos on a scalar time
 * series (inter-packet arrival times from Npcap, or any scalar sensor feed).
 *
 * Algorithm summary (0-1 test, Gottwald & Melbourne 2004/2009):
 *   Given a time series phi(n), n=1..N:
 *     1. For a set of random-phase values c in (0, pi):
 *        p_c(n) = sum_{j=1}^{n} phi(j) * cos(j*c)
 *        q_c(n) = sum_{j=1}^{n} phi(j) * sin(j*c)
 *     2. Compute the mean-square displacement:
 *        M_c(n) = lim_{N->inf} (1/N) * sum_{j=1}^{N} [ (p(j+n)-p(j))^2 +
 *                                                       (q(j+n)-q(j))^2 ]
 *     3. K_c = corr(n, M_c(n))  (Pearson correlation over n = 1..N/10)
 *     4. K = median(K_c over all c values)
 *        K near 0 => regular (periodic/quasiperiodic)
 *        K near 1 => chaotic
 *
 * Properties relevant here:
 *   - O(n) per window -- fits bounded-loop, no dynamic allocation in hot path
 *   - No embedding dimension to tune (unlike Lyapunov exponent methods)
 *   - Works on raw inter-arrival time deltas directly
 *
 * Stretch goal: Rosenstein's Lyapunov exponent estimate (lambda_1) is also
 * computed and reported alongside K, but only K drives RULE-05.
 *
 * Integration:
 *   PacketSensor calls ChaosDetector::push() for each packet's arrival-time
 *   delta. ChaosDetector::flush_window() is called when the window is full.
 *   The result (ChaosWindow) is passed to RuleEngine::evaluate_chaos_score(),
 *   which implements RULE-05.
 */

#include <string>
#include <vector>
#include <functional>
#include <cstdint>
#include <cstddef>

namespace astartis {
namespace chaos {

// ---------------------------------------------------------------------------
// Window result
// ---------------------------------------------------------------------------

struct ChaosWindow {
    uint64_t window_index;      ///< Monotonically increasing sequence number
    size_t   sample_count;      ///< Samples in this window
    double   K;                 ///< 0-1 test chaos score: 0=regular, 1=chaotic
    double   lambda1;           ///< Rosenstein Lyapunov exponent (stretch goal;
                                ///< NaN if not computed or insufficient data)
    bool     anomalous;         ///< true when K > CHAOS_THRESHOLD
    bool     synthetic;         ///< true if samples came from a synthetic source
};

// ---------------------------------------------------------------------------
// ChaosDetector
// ---------------------------------------------------------------------------

class ChaosDetector {
public:
    static constexpr size_t WINDOW_SIZE    = 256;  ///< Samples per window
    static constexpr double CHAOS_THRESHOLD = 0.7; ///< K above this => anomalous

    // Number of random-phase values used in the 0-1 test.
    // Fixed set for reproducibility (no true randomness in the algorithm).
    static constexpr int N_PHASES = 20;

    /**
     * @param window_callback  Called each time a full window is complete.
     * @param audit_adder      Callable (event_type, payload) -> entry_id.
     * @param window_size      Override for tests (default WINDOW_SIZE).
     */
    explicit ChaosDetector(
        std::function<void(const ChaosWindow&)> window_callback,
        std::function<std::string(const std::string&, const std::string&)> audit_adder,
        size_t window_size = WINDOW_SIZE
    );

    ~ChaosDetector() = default;

    ChaosDetector(const ChaosDetector&)            = delete;
    ChaosDetector& operator=(const ChaosDetector&) = delete;

    /**
     * @brief Push one scalar sample into the current window.
     *
     * For packet data: pass the inter-arrival time delta in nanoseconds
     * (difference between consecutive pcap_pkthdr timestamps).
     * When the window is full, flush_window() is called automatically.
     *
     * @param value     The scalar sample value.
     * @param synthetic True if this sample was generated synthetically.
     */
    void push(double value, bool synthetic = false);

    /**
     * @brief Force-flush the current (possibly partial) window.
     *
     * Called automatically when the window fills. Can also be called
     * explicitly to get a result on a partial window (used in tests).
     * No-op if fewer than 10 samples are available.
     */
    void flush_window(bool force = false);

    /** Total windows emitted since construction. */
    uint64_t windows_emitted() const { return window_index_; }

    /** Samples accumulated in the current (incomplete) window. */
    size_t pending_samples() const { return samples_.size(); }

    // -----------------------------------------------------------------------
    // Pure signal algorithms (public for unit testing)
    // -----------------------------------------------------------------------

    /**
     * @brief Compute the 0-1 chaos score K for a given time series.
     *
     * @param series  Input scalar time series (at least 10 samples).
     * @param phases  The c-values to use (radians, in (0, pi)).
     *                If empty, uses the built-in fixed phase set.
     * @return K in [0, 1].  Returns 0.0 on insufficient data.
     */
    static double compute_K(const std::vector<double>& series,
                             const std::vector<double>& phases = {});

    /**
     * @brief Compute Rosenstein's largest Lyapunov exponent estimate.
     *
     * Uses nearest-neighbour divergence averaged over the series.
     * Requires at least 2*embed_dim samples.
     * Returns NaN on insufficient data.
     *
     * @param series    Input scalar time series.
     * @param embed_dim Embedding dimension (default 3).
     * @param tau       Time delay (default 1).
     */
    static double compute_lyapunov(const std::vector<double>& series,
                                    int embed_dim = 3,
                                    int tau       = 1);

    /** The fixed phase set used when no phases are supplied. */
    static std::vector<double> default_phases();

private:
    // Compute mean-square displacement M_c(n) for a single phase c.
    static std::vector<double> compute_msd(const std::vector<double>& series,
                                            double c, int n_max);

    // Pearson correlation coefficient between two equal-length vectors.
    static double pearson(const std::vector<double>& x,
                          const std::vector<double>& y);

    // Median of a vector (modifies a copy).
    static double median(std::vector<double> v);

    std::function<void(const ChaosWindow&)>                           window_cb_;
    std::function<std::string(const std::string&, const std::string&)> audit_adder_;
    size_t   window_size_;
    uint64_t window_index_ = 0;

    std::vector<double> samples_;
    bool any_synthetic_ = false;
};

} // namespace chaos
} // namespace astartis

#endif // ASTARTIS_CHAOS_DETECTOR_H

// Made with Bob
