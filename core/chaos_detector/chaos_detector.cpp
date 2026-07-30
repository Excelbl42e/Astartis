#include "chaos_detector.h"

#include <cmath>
#include <numeric>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <limits>
#include <stdexcept>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

namespace astartis {
namespace chaos {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

ChaosDetector::ChaosDetector(
    std::function<void(const ChaosWindow&)> window_callback,
    std::function<std::string(const std::string&, const std::string&)> audit_adder,
    size_t window_size)
    : window_cb_(std::move(window_callback))
    , audit_adder_(std::move(audit_adder))
    , window_size_(window_size)
{
    samples_.reserve(window_size_);
}

// ---------------------------------------------------------------------------
// push / flush_window
// ---------------------------------------------------------------------------

void ChaosDetector::push(double value, bool synthetic)
{
    samples_.push_back(value);
    if (synthetic) any_synthetic_ = true;
    if (samples_.size() >= window_size_) {
        flush_window(false);
    }
}

void ChaosDetector::flush_window(bool force)
{
    if (samples_.size() < 10 && !force) return;
    if (samples_.empty()) return;

    double K       = compute_K(samples_);
    double lambda1 = compute_lyapunov(samples_);

    ChaosWindow w;
    w.window_index  = window_index_++;
    w.sample_count  = samples_.size();
    w.K             = K;
    w.lambda1       = lambda1;
    w.anomalous     = (K > CHAOS_THRESHOLD);
    w.synthetic     = any_synthetic_;

    // Write audit entry
    std::ostringstream p;
    p << "window=" << w.window_index
      << " samples=" << w.sample_count
      << " K=" << std::fixed << std::setprecision(4) << w.K
      << " lambda1=";
    if (std::isnan(w.lambda1)) p << "nan";
    else p << std::fixed << std::setprecision(4) << w.lambda1;
    p << " anomalous=" << (w.anomalous ? "true" : "false")
      << " synthetic=" << (w.synthetic ? "true" : "false");
    audit_adder_("chaos_window", p.str());

    window_cb_(w);

    samples_.clear();
    any_synthetic_ = false;
}

// ---------------------------------------------------------------------------
// default_phases
// Fixed set of N_PHASES c values evenly spaced in (0, pi).
// Using a fixed set guarantees reproducibility -- the 0-1 test is
// deterministic given the same series and phases.
// ---------------------------------------------------------------------------

std::vector<double> ChaosDetector::default_phases()
{
    std::vector<double> phases;
    phases.reserve(N_PHASES);
    for (int i = 0; i < N_PHASES; ++i) {
        // Space phases in (0, pi), excluding the endpoints
        phases.push_back(M_PI * (i + 1.0) / (N_PHASES + 1.0));
    }
    return phases;
}

// ---------------------------------------------------------------------------
// compute_msd
// Mean-square displacement of the (p, q) orbit for a single phase c.
// M_c(n) = (1/N) * sum_{j=1}^{N} [(p(j+n)-p(j))^2 + (q(j+n)-q(j))^2]
// We compute this for n = 1 .. n_max.
// ---------------------------------------------------------------------------

std::vector<double> ChaosDetector::compute_msd(const std::vector<double>& series,
                                                 double c,
                                                 int n_max)
{
    int N = static_cast<int>(series.size());

    // Build the p, q running-sum vectors
    std::vector<double> p(N + 1, 0.0), q(N + 1, 0.0);
    for (int j = 0; j < N; ++j) {
        p[j + 1] = p[j] + series[j] * std::cos((j + 1) * c);
        q[j + 1] = q[j] + series[j] * std::sin((j + 1) * c);
    }

    // Compute M_c(n) for n = 1 .. n_max
    std::vector<double> M(n_max, 0.0);
    for (int n = 1; n <= n_max; ++n) {
        double sum = 0.0;
        int count = N - n;
        if (count <= 0) { M[n - 1] = 0.0; continue; }
        for (int j = 1; j <= count; ++j) {
            double dp = p[j + n] - p[j];
            double dq = q[j + n] - q[j];
            sum += dp * dp + dq * dq;
        }
        M[n - 1] = sum / count;
    }
    return M;
}

// ---------------------------------------------------------------------------
// pearson
// ---------------------------------------------------------------------------

double ChaosDetector::pearson(const std::vector<double>& x,
                               const std::vector<double>& y)
{
    size_t n = x.size();
    if (n < 2 || n != y.size()) return 0.0;

    double mx = std::accumulate(x.begin(), x.end(), 0.0) / n;
    double my = std::accumulate(y.begin(), y.end(), 0.0) / n;

    double num = 0.0, dx2 = 0.0, dy2 = 0.0;
    for (size_t i = 0; i < n; ++i) {
        double xi = x[i] - mx, yi = y[i] - my;
        num += xi * yi;
        dx2 += xi * xi;
        dy2 += yi * yi;
    }
    double denom = std::sqrt(dx2 * dy2);
    return (denom < 1e-12) ? 0.0 : num / denom;
}

// ---------------------------------------------------------------------------
// median
// ---------------------------------------------------------------------------

double ChaosDetector::median(std::vector<double> v)
{
    if (v.empty()) return 0.0;
    size_t mid = v.size() / 2;
    std::nth_element(v.begin(), v.begin() + mid, v.end());
    if (v.size() % 2 == 1) return v[mid];
    double hi = v[mid];
    std::nth_element(v.begin(), v.begin() + mid - 1, v.end());
    return (v[mid - 1] + hi) / 2.0;
}

// ---------------------------------------------------------------------------
// compute_K  (0-1 test for chaos, Gottwald & Melbourne)
// ---------------------------------------------------------------------------

double ChaosDetector::compute_K(const std::vector<double>& series,
                                  const std::vector<double>& phases_in)
{
    int N = static_cast<int>(series.size());
    if (N < 10) return 0.0;

    const std::vector<double>& phases =
        phases_in.empty() ? default_phases() : phases_in;

    // Use the first N/10 values of n for the regression (standard choice)
    int n_max = std::max(5, N / 10);

    // Build the n-vector (1, 2, ..., n_max) as doubles
    std::vector<double> n_vec(n_max);
    for (int i = 0; i < n_max; ++i) n_vec[i] = static_cast<double>(i + 1);

    // For each phase c, compute K_c = Pearson(n_vec, M_c)
    std::vector<double> K_vals;
    K_vals.reserve(phases.size());
    for (double c : phases) {
        auto M = compute_msd(series, c, n_max);
        double Kc = pearson(n_vec, M);
        K_vals.push_back(Kc);
    }

    // K = median of K_c values, clamped to [0, 1]
    double K = median(K_vals);
    if (K < 0.0) K = 0.0;
    if (K > 1.0) K = 1.0;
    return K;
}

// ---------------------------------------------------------------------------
// compute_lyapunov  (Rosenstein's method, stretch goal)
//
// Estimates the largest Lyapunov exponent lambda_1 from a scalar time series
// using the Rosenstein et al. (1993) nearest-neighbour divergence method.
//
// Steps:
//   1. Embed the series in embed_dim dimensions with delay tau.
//   2. For each point, find its nearest neighbour (excluding temporal
//      neighbours within a minimum separation).
//   3. Track the log-divergence of nearest-neighbour pairs over time.
//   4. lambda_1 = slope of the average log-divergence curve.
//
// Returns NaN on insufficient data.
// ---------------------------------------------------------------------------

double ChaosDetector::compute_lyapunov(const std::vector<double>& series,
                                         int embed_dim,
                                         int tau)
{
    int N = static_cast<int>(series.size());
    int M = N - (embed_dim - 1) * tau;  // number of embedded vectors
    if (M < 2 * embed_dim) {
        return std::numeric_limits<double>::quiet_NaN();
    }

    // Build embedded vectors
    // v[i] = { series[i], series[i+tau], ..., series[i+(embed_dim-1)*tau] }
    std::vector<std::vector<double>> V(M, std::vector<double>(embed_dim));
    for (int i = 0; i < M; ++i) {
        for (int d = 0; d < embed_dim; ++d) {
            V[i][d] = series[i + d * tau];
        }
    }

    // Euclidean distance between two embedded vectors
    auto dist = [&](int a, int b) {
        double s = 0.0;
        for (int d = 0; d < embed_dim; ++d) {
            double diff = V[a][d] - V[b][d];
            s += diff * diff;
        }
        return std::sqrt(s);
    };

    // Minimum temporal separation to avoid trivially close neighbours.
    // Use embed_dim as the separation window (Rosenstein standard choice).
    int min_sep = embed_dim;

    // For each point find its nearest neighbour (excluding min_sep window)
    std::vector<int> nn(M, -1);
    for (int i = 0; i < M; ++i) {
        double best = std::numeric_limits<double>::max();
        for (int j = 0; j < M; ++j) {
            if (std::abs(i - j) <= min_sep) continue;
            double d = dist(i, j);
            if (d < best) { best = d; nn[i] = j; }
        }
    }

    // Track average log-divergence for steps 1..max_steps
    int max_steps = std::min(20, M / 4);
    if (max_steps < 2) return std::numeric_limits<double>::quiet_NaN();

    std::vector<double> avg_log(max_steps, 0.0);
    std::vector<int>    count(max_steps, 0);

    for (int i = 0; i < M; ++i) {
        if (nn[i] < 0) continue;
        for (int s = 1; s <= max_steps; ++s) {
            int a = i + s, b = nn[i] + s;
            if (a >= M || b >= M) break;
            double d = dist(a, b);
            if (d > 1e-12) {
                avg_log[s - 1] += std::log(d);
                count[s - 1]++;
            }
        }
    }

    // Compute the slope of avg_log[s] vs s using linear regression
    std::vector<double> x_vals, y_vals;
    for (int s = 0; s < max_steps; ++s) {
        if (count[s] > 0) {
            x_vals.push_back(static_cast<double>(s + 1));
            y_vals.push_back(avg_log[s] / count[s]);
        }
    }
    if (x_vals.size() < 2) return std::numeric_limits<double>::quiet_NaN();

    // Linear regression slope = Cov(x,y) / Var(x)
    double n  = static_cast<double>(x_vals.size());
    double mx = std::accumulate(x_vals.begin(), x_vals.end(), 0.0) / n;
    double my = std::accumulate(y_vals.begin(), y_vals.end(), 0.0) / n;
    double cov = 0.0, var = 0.0;
    for (size_t i = 0; i < x_vals.size(); ++i) {
        cov += (x_vals[i] - mx) * (y_vals[i] - my);
        var += (x_vals[i] - mx) * (x_vals[i] - mx);
    }
    if (var < 1e-12) return std::numeric_limits<double>::quiet_NaN();
    return cov / var;
}

} // namespace chaos
} // namespace astartis

// Made with Bob
