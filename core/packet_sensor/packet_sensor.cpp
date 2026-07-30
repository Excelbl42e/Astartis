/*
 * Step 5 — Packet Capture Entropy Detection
 * packet_sensor.cpp
 *
 * Requires: wpcap.lib (Npcap SDK, C:\npcap-sdk)
 *           wpcap.dll at runtime (installed by Npcap, WinPcap-compat mode)
 *
 * HAVE_REMOTE, WIN32_LEAN_AND_MEAN, and NOMINMAX are set via CMake
 * compile definitions — do NOT redefine them here.
 */

// Winsock2 must come before any Windows.h / pcap.h include.
#include <winsock2.h>
#include <windows.h>

#include "packet_sensor.h"

// pcap.h is included AFTER packet_sensor.h so the global pcap_pkthdr
// forward declaration in the header is satisfied by the full definition here.
#include <pcap.h>

#include <cmath>
#include <cstring>
#include <array>
#include <random>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <algorithm>
#include <chrono>
#include <thread>

namespace astartis {
namespace sensor {

// ===========================================================================
// Entropy helpers
// ===========================================================================

double compute_entropy(const uint8_t* data, size_t len) {
    if (len == 0) return 0.0;

    // Count byte frequencies.
    std::array<uint64_t, 256> freq{};
    freq.fill(0);
    for (size_t i = 0; i < len; ++i) {
        ++freq[data[i]];
    }

    double entropy = 0.0;
    for (int b = 0; b < 256; ++b) {
        if (freq[b] == 0) continue;
        double p = static_cast<double>(freq[b]) / static_cast<double>(len);
        entropy -= p * std::log2(p);
    }
    return entropy; // [0, 8] bits
}

int entropy_to_threat_score(double entropy_bits) {
    // Clamp to [0, 8], then map linearly to [0, 100].
    double clamped = std::max(0.0, std::min(8.0, entropy_bits));
    return static_cast<int>(std::round((clamped / 8.0) * 100.0));
}

// ===========================================================================
// SyntheticInjector
// ===========================================================================

void SyntheticInjector::make_packet(int category, std::vector<uint8_t>& out) {
    out.resize(DEFAULT_PACKET_SIZE);

    static std::mt19937 rng{std::random_device{}()};

    switch (category % 3) {
        case 0: {
            // Near-random: fill with uniform random bytes (high entropy ~7.9–8.0 bits)
            std::uniform_int_distribution<int> d(0, 255);
            for (auto& b : out) b = static_cast<uint8_t>(d(rng));
            break;
        }
        case 1: {
            // Structured ASCII: simulate HTTP GET header (low-medium entropy ~3.5–4.5 bits)
            const char tmpl[] =
                "GET /index.html HTTP/1.1\r\n"
                "Host: server.example.local\r\n"
                "User-Agent: Astartis/1.0\r\n"
                "Accept: text/html\r\n"
                "\r\n";
            size_t tlen = std::strlen(tmpl);
            for (size_t i = 0; i < DEFAULT_PACKET_SIZE; ++i) {
                out[i] = static_cast<uint8_t>(tmpl[i % tlen]);
            }
            break;
        }
        case 2: {
            // Repetitive pattern: ARP-style (very low entropy ~1.0–2.0 bits)
            // ARP header pattern repeated: FF FF FF FF FF FF + zeros
            const uint8_t arp_pat[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                        0x00, 0x00, 0x08, 0x06, 0x00, 0x01};
            for (size_t i = 0; i < DEFAULT_PACKET_SIZE; ++i) {
                out[i] = arp_pat[i % sizeof(arp_pat)];
            }
            break;
        }
    }
}

std::vector<std::vector<uint8_t>> SyntheticInjector::make_batch(size_t count) {
    std::vector<std::vector<uint8_t>> batch;
    batch.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        std::vector<uint8_t> pkt;
        make_packet(static_cast<int>(i), pkt);
        batch.push_back(std::move(pkt));
    }
    return batch;
}

// ===========================================================================
// PacketSensor — construction / destruction
// ===========================================================================

PacketSensor::PacketSensor(
    std::function<void(const EntropyWindow&)> window_callback,
    std::function<std::string(const std::string&, const std::string&)> audit_adder,
    const std::string& iface_hint,
    size_t window_size)
    : window_cb_(std::move(window_callback))
    , audit_adder_(std::move(audit_adder))
    , iface_hint_(iface_hint)
    , window_size_(window_size > 0 ? window_size : DEFAULT_WINDOW_SIZE)
{
    entropy_accum_.reserve(window_size_);
}

PacketSensor::~PacketSensor() {
    stop();
}

// ===========================================================================
// PacketSensor — start / stop
// ===========================================================================

bool PacketSensor::start() {
    if (running_.load()) return !synthetic_mode_.load();

    // Attempt to open a real adapter.
    pcap_handle_ = open_best_adapter(iface_hint_);

    if (pcap_handle_ != nullptr) {
        // Real capture path.
        synthetic_mode_.store(false);
        running_.store(true);
        capture_thread_ = std::thread(&PacketSensor::capture_loop, this);
        return true;
    } else {
        // Fallback: synthetic injector.
        synthetic_mode_.store(true);
        adapter_name_ = "synthetic";
        running_.store(true);
        capture_thread_ = std::thread(&PacketSensor::synthetic_loop, this);
        return false;  // signals "fallback active" to caller
    }
}

void PacketSensor::stop() {
    if (!running_.exchange(false)) return;  // already stopped

    if (capture_thread_.joinable()) {
        // For real capture: pcap_breakloop wakes up the dispatch loop.
        if (pcap_handle_ != nullptr) {
            pcap_breakloop(static_cast<pcap_t*>(pcap_handle_));
        }
        capture_thread_.join();
    }

    if (pcap_handle_ != nullptr) {
        pcap_close(static_cast<pcap_t*>(pcap_handle_));
        pcap_handle_ = nullptr;
    }

    // Flush any partial window.
    flush_window(/*force=*/true);
}

// ===========================================================================
// PacketSensor — adapter selection
// ===========================================================================

void* PacketSensor::open_best_adapter(const std::string& hint) {
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_if_t* all_devs = nullptr;

    if (pcap_findalldevs(&all_devs, errbuf) == -1 || all_devs == nullptr) {
        // No adapters found — caller will activate synthetic fallback.
        if (all_devs) pcap_freealldevs(all_devs);
        return nullptr;
    }

    // Pick the preferred device: exact name match if hint given, else first
    // non-loopback device with PCAP_IF_UP.
    //
    // If a non-empty hint is supplied and no adapter with that exact name is
    // found, return nullptr so the caller activates the synthetic fallback.
    // This allows unit tests to force synthetic mode with a bogus adapter name.
    pcap_if_t* chosen = nullptr;
    bool hint_matched = false;
    for (pcap_if_t* dev = all_devs; dev != nullptr; dev = dev->next) {
        if (!hint.empty() && hint == dev->name) {
            chosen = dev;
            hint_matched = true;
            break;
        }
        // Auto-select only when no hint was given.
        if (hint.empty()) {
            bool is_loopback = (dev->flags & PCAP_IF_LOOPBACK) != 0;
            bool is_up       = (dev->flags & PCAP_IF_UP) != 0;
            if (!is_loopback && is_up && chosen == nullptr) {
                chosen = dev;
            }
        }
    }

    // A hint was given but matched nothing — force synthetic fallback.
    if (!hint.empty() && !hint_matched) {
        pcap_freealldevs(all_devs);
        return nullptr;
    }

    if (chosen == nullptr) {
        // No suitable non-loopback adapter.
        pcap_freealldevs(all_devs);
        return nullptr;
    }

    // Open in promiscuous mode, 65535 snaplen, 100 ms timeout.
    pcap_t* handle = pcap_open_live(chosen->name,
                                    65535,   // snaplen
                                    1,       // promiscuous
                                    100,     // read timeout ms
                                    errbuf);

    if (handle == nullptr) {
        pcap_freealldevs(all_devs);
        return nullptr;
    }

    adapter_name_ = chosen->name;

    // Set non-blocking so stop() can interrupt cleanly via pcap_breakloop.
    // (pcap_breakloop alone is sufficient for the dispatch loop below, but
    // non-blocking prevents the 100 ms read timeout from delaying stop().)
    pcap_setnonblock(handle, 1, errbuf);

    pcap_freealldevs(all_devs);
    return static_cast<void*>(handle);
}

// ===========================================================================
// PacketSensor — real capture loop
// ===========================================================================

// Static trampoline: pcap hands us a raw uint8_t* user_data == this.
void PacketSensor::pcap_callback(uint8_t* user_data,
                                  const struct pcap_pkthdr* header,
                                  const uint8_t* packet) {
    auto* self = reinterpret_cast<PacketSensor*>(user_data);
    if (header->caplen > 0) {
        self->on_packet(packet, header->caplen);
    }
}

void PacketSensor::capture_loop() {
    pcap_t* handle = static_cast<pcap_t*>(pcap_handle_);

    while (running_.load()) {
        // -1 = unlimited packet count per call (returns on read timeout or breakloop).
        // We set a 100 ms read timeout at open time, so this wakes up at least
        // every 100 ms even when the interface is idle, keeping stop() responsive.
        int rc = pcap_dispatch(handle,
                               -1,
                               PacketSensor::pcap_callback,
                               reinterpret_cast<uint8_t*>(this));
        if (rc == PCAP_ERROR_BREAK) break;   // pcap_breakloop() was called
        if (rc == PCAP_ERROR)       break;   // fatal error — exit loop
        if (rc == 0) {
            // Timeout with no packets — yield briefly to avoid spinning
            // in the nonblocking case (should not occur with 100 ms timeout,
            // but defensive).
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
}

// ===========================================================================
// PacketSensor — synthetic fallback loop
// ===========================================================================

void PacketSensor::synthetic_loop() {
    size_t category = 0;

    while (running_.load()) {
        std::vector<uint8_t> pkt;
        SyntheticInjector::make_packet(static_cast<int>(category++), pkt);
        on_packet(pkt.data(), static_cast<uint32_t>(pkt.size()));

        // Inject at ~1000 packets/second to avoid busy-spinning,
        // but yield promptly so stop() can interrupt.
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

// ===========================================================================
// PacketSensor — per-packet processing
// ===========================================================================

void PacketSensor::on_packet(const uint8_t* data, uint32_t len) {
    double e = compute_entropy(data, static_cast<size_t>(len));

    std::lock_guard<std::mutex> lk(window_mutex_);
    entropy_accum_.push_back(e);

    if (entropy_accum_.size() >= window_size_) {
        flush_window_locked();
    }
}

// Internal: must be called with window_mutex_ held.
// Extracted to avoid duplicating the flush logic.
void PacketSensor::flush_window_locked() {
    if (entropy_accum_.empty()) return;

    double sum = 0.0, mx = 0.0, mn = 8.0;
    for (double v : entropy_accum_) {
        sum += v;
        if (v > mx) mx = v;
        if (v < mn) mn = v;
    }
    double mean = sum / static_cast<double>(entropy_accum_.size());

    EntropyWindow w;
    w.window_index      = window_index_.fetch_add(1);
    w.packet_count      = entropy_accum_.size();
    w.mean_entropy_bits = mean;
    w.max_entropy_bits  = mx;
    w.min_entropy_bits  = mn;
    w.threat_score      = entropy_to_threat_score(mean);
    w.anomalous         = (mean >= ANOMALY_ENTROPY_THRESHOLD);
    w.synthetic         = synthetic_mode_.load();
    w.adapter_name      = adapter_name_;

    entropy_accum_.clear();

    // Write to audit chain before firing callback (audit chain is thread-safe).
    if (audit_adder_) {
        std::ostringstream oss;
        oss << std::fixed << std::setprecision(3)
            << "window=" << w.window_index
            << " packets=" << w.packet_count
            << " mean_entropy=" << w.mean_entropy_bits
            << " score=" << w.threat_score
            << " anomalous=" << (w.anomalous ? "true" : "false")
            << " adapter=" << w.adapter_name;
        audit_adder_("packet_entropy", oss.str());
    }

    // Fire callback — hold mutex to prevent partial flush during stop().
    if (window_cb_) window_cb_(w);
}

void PacketSensor::flush_window(bool force) {
    std::lock_guard<std::mutex> lk(window_mutex_);
    if (force || entropy_accum_.size() >= window_size_) {
        flush_window_locked();
    }
}

} // namespace sensor
} // namespace astartis

// Made with Bob
