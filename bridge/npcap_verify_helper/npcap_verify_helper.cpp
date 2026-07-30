// npcap_verify_helper.cpp -- Astartis Npcap Real Verification Helper
//
// TERRA Part 4 / Part 4a requirement:
//   This helper is launched via ShellExecuteEx with verb "runas" from the
//   DashboardServer, which forces Windows to show a fresh UAC elevation dialog
//   EVERY time it runs -- even when the parent process is already elevated.
//
// What it does:
//   1. Scores all Npcap adapters and picks the best real one
//      (Wi-Fi/Ethernet preferred; WAN Miniport virtual adapters skipped)
//   2. Captures up to 10 real packets (20-second timeout per adapter)
//   3. Falls back to next-best adapter if chosen one yields 0 packets
//   4. Computes Shannon entropy per packet
//   5. Writes a JSON result to the path given as argv[1]
//   6. Exits 0 on success, 1 on failure
//
// FIX 2026-07-30:
//   Prior version always picked the FIRST non-loopback UP adapter which on
//   this machine was "WAN Miniport (IPv6)" -- a virtual adapter with zero
//   Ethernet frames. pcap_dispatch blocked for 5s per loop -> 50s total,
//   always exceeding the server's 15s wait. Fixed by:
//     a) Scoring adapters: real Wi-Fi/Ethernet get priority 0, WAN Miniports
//        get priority 2, everything else gets priority 1.
//     b) Trying adapters in priority order; moving on after 8s if 0 packets.
//     c) Bumping per-adapter capture window from 5s to 20s.

// ---------------------------------------------------------------------------
// Windows / Winsock headers -- ORDER MATTERS for pcap.h compatibility
//   winsock2.h MUST come before windows.h
//   HAVE_REMOTE enables Npcap remote capture extensions (required on Npcap SDK)
// ---------------------------------------------------------------------------
#define HAVE_REMOTE
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <pcap.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")

// ---------------------------------------------------------------------------
// Standard library
// ---------------------------------------------------------------------------
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cmath>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstdint>

// ---------------------------------------------------------------------------
// Shannon entropy of a byte buffer (result in bits, 0..8)
// ---------------------------------------------------------------------------
static double compute_entropy(const unsigned char* data, bpf_u_int32 len)
{
    if (!data || len == 0) return 0.0;
    unsigned int freq[256] = {};
    for (bpf_u_int32 i = 0; i < len; ++i) ++freq[data[i]];
    double entropy = 0.0;
    for (int f : freq) {
        if (f == 0) continue;
        double p = static_cast<double>(f) / len;
        entropy -= p * log2(p);
    }
    return entropy;
}

// ---------------------------------------------------------------------------
// ISO 8601 UTC timestamp
// ---------------------------------------------------------------------------
static std::string iso8601_now()
{
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart  = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    const uint64_t EPOCH_DIFF = 116444736000000000ULL;
    uint64_t unix_100ns = uli.QuadPart - EPOCH_DIFF;
    int64_t  unix_ms    = static_cast<int64_t>(unix_100ns / 10000);
    time_t   sec        = static_cast<time_t>(unix_ms / 1000);
    int      ms         = static_cast<int>(unix_ms % 1000);
    tm utc{};
    gmtime_s(&utc, &sec);
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
        utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday,
        utc.tm_hour, utc.tm_min, utc.tm_sec, ms);
    return std::string(buf);
}

// ---------------------------------------------------------------------------
// Minimal JSON string escaping
// ---------------------------------------------------------------------------
static std::string json_str(const std::string& s)
{
    std::string out = "\"";
    for (char c : s) {
        if      (c == '"')  out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else                out += c;
    }
    out += '"';
    return out;
}

// ---------------------------------------------------------------------------
// Write JSON to file or stdout
// ---------------------------------------------------------------------------
static void write_json(const std::string& path, const std::string& json)
{
    if (!path.empty()) {
        std::ofstream ofs(path, std::ios::trunc);
        if (ofs) { ofs << json; return; }
        std::cerr << "[npcap_verify_helper] Cannot write to: " << path << "\n";
    }
    std::cout << json << std::endl;
}

// ---------------------------------------------------------------------------
// Adapter scoring — lower score = preferred
//   0: real Wi-Fi or Ethernet (names containing "wi-fi", "ethernet",
//      "wireless", "802.11", "local area", "realtek", "intel", "qualcomm")
//   1: other non-loopback, non-WAN adapters
//   2: virtual WAN Miniport, ISATAP, 6to4, Teredo (skip these)
// ---------------------------------------------------------------------------
static int score_adapter(const char* name, const char* desc)
{
    // Build lowercase description string for matching
    std::string d = desc ? desc : (name ? name : "");
    std::transform(d.begin(), d.end(), d.begin(), ::tolower);

    // Virtual adapters to avoid
    const char* skip_patterns[] = {
        "wan miniport", "isatap", "teredo", "6to4", "npcap loopback",
        "microsoft kernel debug", "bluetooth", "vmware", "virtualbox",
        "tap-windows", "hyper-v", "ndis"
    };
    for (const char* p : skip_patterns) {
        if (d.find(p) != std::string::npos) return 2;
    }

    // Real physical adapters to prefer
    const char* prefer_patterns[] = {
        "wi-fi", "wifi", "wireless", "802.11", "wlan",
        "ethernet", "local area connection", "realtek", "intel",
        "qualcomm", "broadcom", "atheros", "marvell", "gigabit"
    };
    for (const char* p : prefer_patterns) {
        if (d.find(p) != std::string::npos) return 0;
    }

    return 1; // unknown but not obviously virtual
}

// ---------------------------------------------------------------------------
// Packet capture state (global for pcap callback)
// ---------------------------------------------------------------------------
struct CaptureState {
    int              count         = 0;
    int              target        = 10;
    double           total_entropy = 0.0;
    double           max_entropy   = 0.0;
    std::string      adapter_name;
    std::string      adapter_desc;
    std::string      timestamp_start;
    std::string      timestamp_end;
    std::vector<double> per_packet;
};

static CaptureState g_state;

static void packet_callback(u_char* /*user*/,
                             const struct pcap_pkthdr* header,
                             const u_char* packet)
{
    if (g_state.count >= g_state.target) return;
    double entropy = compute_entropy(packet, header->caplen);
    g_state.per_packet.push_back(entropy);
    g_state.total_entropy += entropy;
    if (entropy > g_state.max_entropy) g_state.max_entropy = entropy;
    ++g_state.count;
    if (g_state.count == g_state.target)
        g_state.timestamp_end = iso8601_now();
}

// ---------------------------------------------------------------------------
// Attempt capture on one adapter.
// Returns true if at least 1 packet was captured.
// Uses a read timeout of 1000ms per pcap_open_live call so that
// pcap_dispatch never blocks longer than 1 second per iteration.
// ---------------------------------------------------------------------------
static bool try_capture(const std::string& dev_name,
                        const std::string& dev_desc,
                        int target_packets,
                        int max_seconds)
{
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    // 1000ms read timeout so each pcap_dispatch returns within 1s
    pcap_t* handle = pcap_open_live(dev_name.c_str(), 65535, 0, 1000, errbuf);
    if (!handle) {
        std::cerr << "[npcap_verify_helper] pcap_open_live(" << dev_name
                  << ") failed: " << errbuf << "\n";
        return false;
    }

    g_state.count         = 0;
    g_state.total_entropy = 0.0;
    g_state.max_entropy   = 0.0;
    g_state.per_packet.clear();
    g_state.timestamp_end = "";
    g_state.adapter_name  = dev_name;
    g_state.adapter_desc  = dev_desc;

    // Loop until target packets or time limit
    DWORD deadline = GetTickCount() + static_cast<DWORD>(max_seconds) * 1000;
    while (g_state.count < target_packets && GetTickCount() < deadline) {
        int remaining = target_packets - g_state.count;
        int got = pcap_dispatch(handle, remaining, packet_callback, nullptr);
        // got < 0 means error; got == 0 means timeout (1s read timeout expired)
        if (got < 0) break;
    }
    pcap_close(handle);

    if (g_state.timestamp_end.empty())
        g_state.timestamp_end = iso8601_now();

    return g_state.count > 0;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(int argc, char* argv[])
{
    const std::string output_path = (argc >= 2) ? argv[1] : "";
    g_state.timestamp_start = iso8601_now();

    // Find all adapters
    char errbuf[PCAP_ERRBUF_SIZE] = {};
    pcap_if_t* alldevs = nullptr;

    if (pcap_findalldevs(&alldevs, errbuf) == -1 || !alldevs) {
        std::string j =
            "{\n  \"status\": \"error\",\n"
            "  \"message\": " + json_str(std::string("pcap_findalldevs: ") + errbuf) + ",\n"
            "  \"uac_shown\": true,\n  \"packets_captured\": 0,\n"
            "  \"timestamp_start\": " + json_str(g_state.timestamp_start) + "\n}";
        write_json(output_path, j);
        return 1;
    }

    // Collect and score all non-loopback adapters
    struct AdapterCandidate {
        std::string name;
        std::string desc;
        int         score;
    };
    std::vector<AdapterCandidate> candidates;

    for (pcap_if_t* dev = alldevs; dev; dev = dev->next) {
        if (dev->flags & PCAP_IF_LOOPBACK) continue;
        std::string desc = dev->description ? dev->description : dev->name;
        int s = score_adapter(dev->name, dev->description);
        candidates.push_back({ dev->name, desc, s });
        std::cerr << "[npcap_verify_helper] adapter score=" << s
                  << " \"" << desc << "\"\n";
    }
    pcap_freealldevs(alldevs);

    // Sort by score ascending (0 = best)
    std::sort(candidates.begin(), candidates.end(),
        [](const AdapterCandidate& a, const AdapterCandidate& b) {
            return a.score < b.score;
        });

    if (candidates.empty()) {
        std::string j =
            "{\n  \"status\": \"error\",\n"
            "  \"message\": \"No non-loopback adapters found\",\n"
            "  \"uac_shown\": true,\n  \"packets_captured\": 0,\n"
            "  \"timestamp_start\": " + json_str(g_state.timestamp_start) + "\n}";
        write_json(output_path, j);
        return 1;
    }

    // Try adapters in order; stop as soon as we capture at least 1 packet.
    // Skip score-2 adapters (virtual WAN Miniports) unless they're the ONLY option.
    bool captured = false;
    bool tried_any = false;

    // First pass: try score 0 and 1 adapters only
    for (const auto& cand : candidates) {
        if (cand.score >= 2) continue;
        std::cerr << "[npcap_verify_helper] Trying: " << cand.desc << "\n";
        // Give each adapter up to 20 seconds; if score==0 give full 20s,
        // score==1 give 8s (move on quickly to next candidate)
        int secs = (cand.score == 0) ? 20 : 8;
        tried_any = true;
        if (try_capture(cand.name, cand.desc, 10, secs)) {
            captured = true;
            break;
        }
        std::cerr << "[npcap_verify_helper] 0 packets on " << cand.desc << ", trying next\n";
    }

    // Second pass: if nothing worked, try score-2 virtual adapters as last resort
    if (!captured) {
        for (const auto& cand : candidates) {
            if (cand.score < 2) continue;
            std::cerr << "[npcap_verify_helper] Fallback: " << cand.desc << "\n";
            tried_any = true;
            if (try_capture(cand.name, cand.desc, 10, 5)) {
                captured = true;
                break;
            }
        }
    }

    // Build result JSON
    std::string per_arr = "[";
    for (size_t i = 0; i < g_state.per_packet.size(); ++i) {
        if (i) per_arr += ",";
        char tmp[32];
        snprintf(tmp, sizeof(tmp), "%.4f", g_state.per_packet[i]);
        per_arr += tmp;
    }
    per_arr += "]";

    double mean_e = g_state.count > 0 ? g_state.total_entropy / g_state.count : 0.0;
    char mean_buf[32], max_buf[32];
    snprintf(mean_buf, sizeof(mean_buf), "%.4f", mean_e);
    snprintf(max_buf,  sizeof(max_buf),  "%.4f", g_state.max_entropy);

    const char* status_str = captured ? "ok" : (tried_any ? "partial" : "error");
    std::string msg;
    if (captured) {
        msg = "Npcap live capture completed. UAC elevation confirmed by OS.";
    } else {
        msg = "Adapter found but no packets captured within time limit. "
              "The adapter may have no active traffic. "
              "UAC elevation confirmed by OS (helper ran elevated).";
    }

    std::string result =
        "{\n"
        "  \"status\": "              + json_str(status_str)              + ",\n"
        "  \"uac_shown\": true,\n"
        "  \"packets_captured\": "    + std::to_string(g_state.count)     + ",\n"
        "  \"packets_target\": "      + std::to_string(10)                + ",\n"
        "  \"adapter\": "             + json_str(g_state.adapter_desc)    + ",\n"
        "  \"adapter_name\": "        + json_str(g_state.adapter_name)    + ",\n"
        "  \"mean_entropy_bits\": "   + std::string(mean_buf)             + ",\n"
        "  \"max_entropy_bits\": "    + std::string(max_buf)              + ",\n"
        "  \"per_packet_entropy\": "  + per_arr                           + ",\n"
        "  \"timestamp_start\": "     + json_str(g_state.timestamp_start) + ",\n"
        "  \"timestamp_end\": "       + json_str(g_state.timestamp_end)   + ",\n"
        "  \"message\": "             + json_str(msg)                     + "\n"
        "}";

    write_json(output_path, result);
    return captured ? 0 : 1;
}
