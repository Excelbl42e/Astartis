// dashboard_writer.cpp -- DashboardWriter implementation (Astartis v3.2)
//
// Uses Windows FILETIME (w32tm-synced) for sub-second UTC timestamps.
// PDH queries provide live CPU/memory/disk metrics from Windows performance counters.
// Re-added in Phase 4 rebuild. No functional change from v3.2.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <pdh.h>
#include <winreg.h>
#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "ws2_32.lib")

#pragma warning(push)
#pragma warning(disable: 4706 4127 4244)
#include "nlohmann/json.hpp"
#pragma warning(pop)

#include "dashboard_writer.h"
#include <fstream>
#include <chrono>
#include <thread>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <cstdint>

namespace astartis {
namespace dashboard {

using json = nlohmann::json;

// ---------------------------------------------------------------------------
// Time — use Windows FILETIME for sub-second UTC precision.
// w32tm keeps the system clock NTP-synced; no additional NTP socket needed.
// ---------------------------------------------------------------------------

static std::string iso8601_now()
{
    FILETIME ft{};
#if defined(NTDDI_WIN8) && (NTDDI_VERSION >= NTDDI_WIN8)
    GetSystemTimePreciseAsFileTime(&ft);
#else
    GetSystemTimeAsFileTime(&ft);
#endif

    ULARGE_INTEGER uli;
    uli.LowPart  = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    constexpr uint64_t EPOCH_DIFF_100NS = 116444736000000000ULL;
    uint64_t unix_100ns = uli.QuadPart - EPOCH_DIFF_100NS;
    int64_t  unix_ms    = static_cast<int64_t>(unix_100ns / 10000);

    time_t sec = static_cast<time_t>(unix_ms / 1000);
    int    ms  = static_cast<int>(unix_ms % 1000);
    tm utc{};
    gmtime_s(&utc, &sec);
    char buf[64];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
        utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday,
        utc.tm_hour, utc.tm_min, utc.tm_sec, ms);
    return std::string(buf);
}

// ---------------------------------------------------------------------------
// System Health — real Windows API checks
// ---------------------------------------------------------------------------

static bool tcp_probe(const char* ip, uint16_t port, int timeout_ms = 1000)
{
    WSADATA wsaData{};
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return false;
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) { WSACleanup(); return false; }
    u_long nonblock = 1;
    ioctlsocket(sock, FIONBIO, &nonblock);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);
    connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    timeval tv{ timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    bool ok = (select(0, nullptr, &fdset, nullptr, &tv) > 0 && FD_ISSET(sock, &fdset));
    closesocket(sock);
    WSACleanup();
    return ok;
}

static bool check_npcap()
{
    bool dll_exists =
        (GetFileAttributesA("C:\\Windows\\System32\\Npcap\\wpcap.dll")   != INVALID_FILE_ATTRIBUTES) ||
        (GetFileAttributesA("C:\\Windows\\SysWOW64\\Npcap\\wpcap.dll") != INVALID_FILE_ATTRIBUTES);
    bool service_running = false;
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE svc = OpenServiceA(scm, "npcap", SERVICE_QUERY_STATUS);
        if (svc) {
            SERVICE_STATUS status{};
            if (QueryServiceStatus(svc, &status))
                service_running = (status.dwCurrentState == SERVICE_RUNNING);
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }
    return dll_exists && service_running;
}

static bool check_admin_elevation()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION elevation{};
    DWORD size = sizeof(elevation);
    BOOL ok = GetTokenInformation(token, TokenElevation, &elevation, size, &size);
    CloseHandle(token);
    return ok && elevation.TokenIsElevated != 0;
}

// Query Ollama version via HTTP GET /api/version
static std::string query_ollama_version()
{
    WSADATA wsaData{};
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return "";
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) { WSACleanup(); return ""; }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(11434);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    DWORD to = 1500;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&to), sizeof(to));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&to), sizeof(to));
    if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock); WSACleanup(); return "";
    }
    const char* req = "GET /api/version HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n";
    send(sock, req, static_cast<int>(strlen(req)), 0);
    char buf[512] = {};
    recv(sock, buf, sizeof(buf) - 1, 0);
    closesocket(sock); WSACleanup();
    // Parse {"version":"0.x.y"} from body
    std::string resp(buf);
    auto vpos = resp.find("\"version\"");
    if (vpos == std::string::npos) return "";
    auto q1 = resp.find('"', vpos + 9);
    if (q1 == std::string::npos) return "";
    ++q1;
    auto q2 = resp.find('"', q1);
    if (q2 == std::string::npos) return "";
    return resp.substr(q1, q2 - q1);
}

// Query ClamAV version via VERSION command to clamd
static std::string query_clamd_version()
{
    WSADATA wsaData{};
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return "";
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) { WSACleanup(); return ""; }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(3310);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    DWORD to = 1500;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&to), sizeof(to));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&to), sizeof(to));
    if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock); WSACleanup(); return "";
    }
    const char* cmd = "VERSION\n";
    send(sock, cmd, static_cast<int>(strlen(cmd)), 0);
    char buf[128] = {};
    recv(sock, buf, sizeof(buf) - 1, 0);
    closesocket(sock); WSACleanup();
    // Response: "ClamAV 1.0.0/26345/..." — return first token after "ClamAV "
    std::string resp(buf);
    if (resp.rfind("ClamAV ", 0) == 0) {
        auto sp = resp.find(' ', 7);
        if (sp != std::string::npos) return resp.substr(7, sp - 7);
        return resp.substr(7);
    }
    return "";
}

// Query Npcap version from registry
static std::string query_npcap_version()
{
    HKEY key = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Npcap", 0, KEY_READ, &key) != ERROR_SUCCESS) {
        // Try WOW64 node
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Npcap", 0, KEY_READ, &key) != ERROR_SUCCESS)
            return "";
    }
    char buf[64] = {};
    DWORD size = sizeof(buf);
    DWORD type = REG_SZ;
    RegQueryValueExA(key, "Version", nullptr, &type, reinterpret_cast<BYTE*>(buf), &size);
    RegCloseKey(key);
    return std::string(buf);
}

SystemHealth query_system_health()
{
    SystemHealth h;
    h.ollama_online         = tcp_probe("127.0.0.1", 11434, 1000);
    h.clamd_online          = tcp_probe("127.0.0.1",  3310, 1000);
    h.npcap_installed       = check_npcap();
    h.npcap_service_running = h.npcap_installed;
    h.is_admin              = check_admin_elevation();

    // Dependency version info (TERRA Part 3 — dependency status panel)
    std::string now_ts = iso8601_now();

    h.dep_ollama.name    = "Ollama";
    h.dep_ollama.version = h.ollama_online ? query_ollama_version() : "";
    h.dep_ollama.status  = h.ollama_online ? "connected" : "missing";
    h.dep_ollama.verified_at = now_ts;

    h.dep_npcap.name    = "Npcap (WinPcap)";
    h.dep_npcap.version = query_npcap_version();
    h.dep_npcap.status  = h.npcap_installed
                          ? (h.npcap_service_running ? "running" : "installed-stopped")
                          : "missing";
    h.dep_npcap.verified_at = now_ts;

    h.dep_clamd.name    = "ClamAV (clamd)";
    h.dep_clamd.version = h.clamd_online ? query_clamd_version() : "";
    h.dep_clamd.status  = h.clamd_online ? "connected" : "missing";
    h.dep_clamd.verified_at = now_ts;

    h.dep_granite_fast.name    = "IBM Granite 3.1 MoE 3B";
    h.dep_granite_fast.version = "granite3.1-moe:3b";
    h.dep_granite_fast.status  = h.ollama_online ? "connected" : "missing";
    h.dep_granite_fast.verified_at = now_ts;

    h.dep_granite_heavy.name    = "IBM Granite 3.1 Dense 8B";
    h.dep_granite_heavy.version = "granite3.1-dense:8b";
    h.dep_granite_heavy.status  = h.ollama_online ? "connected" : "missing";
    h.dep_granite_heavy.verified_at = now_ts;

    h.dep_granite_acc.name    = "IBM Granite 4.1 8B Q5";
    h.dep_granite_acc.version = "ibm/granite4.1:8b-q5_K_M";
    h.dep_granite_acc.status  = h.ollama_online ? "connected" : "missing";
    h.dep_granite_acc.verified_at = now_ts;

    return h;
}

// ---------------------------------------------------------------------------
// Windows PDH: live CPU/memory/disk/network metrics
// ---------------------------------------------------------------------------

SystemMetrics query_windows_metrics()
{
    SystemMetrics m;
    PDH_HQUERY query = nullptr;
    PDH_HCOUNTER counter = nullptr;
    if (PdhOpenQuery(nullptr, 0, &query) == ERROR_SUCCESS) {
        if (PdhAddCounterA(query, "\\Processor Information(_Total)\\% Processor Time",
                           0, &counter) == ERROR_SUCCESS) {
            PdhCollectQueryData(query);
            Sleep(100);
            PdhCollectQueryData(query);
            PDH_FMT_COUNTERVALUE value{};
            if (PdhGetFormattedCounterValue(counter, PDH_FMT_DOUBLE, nullptr, &value) == ERROR_SUCCESS)
                m.cpu_percent = value.doubleValue;
        }
        PdhCloseQuery(query);
    }
    MEMORYSTATUSEX memStatus{};
    memStatus.dwLength = sizeof(memStatus);
    if (GlobalMemoryStatusEx(&memStatus)) {
        m.memory_percent  = static_cast<double>(memStatus.ullTotalPhys - memStatus.ullAvailPhys)
                            / memStatus.ullTotalPhys * 100.0;
        m.memory_used_gb  = (memStatus.ullTotalPhys - memStatus.ullAvailPhys) / (1024.0*1024.0*1024.0);
        m.memory_total_gb = memStatus.ullTotalPhys / (1024.0*1024.0*1024.0);
    }
    ULARGE_INTEGER freeBytes{}, totalBytes{};
    if (GetDiskFreeSpaceExA("C:\\", &freeBytes, &totalBytes, nullptr)) {
        double totalGB = totalBytes.QuadPart / (1024.0*1024.0*1024.0);
        double freeGB  = freeBytes.QuadPart  / (1024.0*1024.0*1024.0);
        m.disk_free_gb  = freeGB;
        m.disk_percent  = (totalGB - freeGB) / totalGB * 100.0;
    }
    SYSTEM_INFO sysInfo{};
    GetSystemInfo(&sysInfo);
    m.cpu_cores = static_cast<int>(sysInfo.dwNumberOfProcessors);
    m.ollama_online = tcp_probe("127.0.0.1", 11434, 500);
    return m;
}

// ---------------------------------------------------------------------------
// DashboardWriter: background write loop
// ---------------------------------------------------------------------------

DashboardWriter::DashboardWriter(const std::string& output_dir)
    : output_dir_(output_dir)
    , json_path_(output_dir + "/dashboard_data.json")
{}

DashboardWriter::~DashboardWriter() { stop(); }

void DashboardWriter::set_data_provider(DataProvider provider)
{
    provider_ = std::move(provider);
}

void DashboardWriter::start(int interval_seconds)
{
    if (running_.exchange(true)) return;
    thread_ = std::thread(&DashboardWriter::write_loop, this, interval_seconds);
}

void DashboardWriter::stop()
{
    if (!running_.exchange(false)) return;
    if (thread_.joinable()) thread_.join();
}

void DashboardWriter::write_loop(int interval_seconds)
{
    while (running_.load()) {
        if (provider_) {
            try {
                auto data = provider_();
                if (data.system_metrics.cpu_percent == 0.0)
                    data.system_metrics = query_windows_metrics();
                // Always refresh health on every write cycle so dep status panel
                // and connectivity indicators stay current (not just when offline)
                data.health = query_system_health();
                write_json(data);
            } catch (const std::exception& e) {
                std::cerr << "[DashboardWriter] ERROR: " << e.what() << "\n";
            } catch (...) {
                std::cerr << "[DashboardWriter] UNKNOWN ERROR in provider/write\n";
            }
        }
        int steps = interval_seconds * 10;
        for (int i = 0; i < steps && running_.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void DashboardWriter::write_json(const DashboardData& data)
{
    json j;
    // FIX BUG-01-A: version was "3.0.0" — correct to "3.2.0"
    j["system"] = {
        {"mode",      data.system_mode},
        {"status",    data.system_status},
        {"version",   "3.2.0"},
        {"timestamp", iso8601_now()}
    };
    j["kpi"] = {
        {"active_agents",   data.active_agents},
        {"queue_depth",     data.queue_depth},
        {"threat_level",    data.threat_level},
        {"threat_score",    data.threat_score},
        {"alerts_24h",      data.alerts_24h},
        {"critical_alerts", data.critical_alerts}
    };

    // Agents
    json agents_arr = json::array();
    for (const auto& a : data.agents)
        agents_arr.push_back({{"name",a.name},{"tier",a.tier},{"model",a.model},
                               {"status",a.status},{"tasks_completed",a.tasks_completed},
                               {"last_active",a.last_active}});
    j["agents"] = agents_arr;

    // Alerts
    json alerts_arr = json::array();
    for (const auto& a : data.alerts)
        alerts_arr.push_back({{"timestamp",a.timestamp},{"severity",a.severity},
                               {"agent_name",a.agent_name},{"message",a.message}});
    j["alerts"] = alerts_arr;

    // Logs
    json logs_arr = json::array();
    for (const auto& l : data.new_logs)
        logs_arr.push_back({{"timestamp",l.timestamp},{"level",l.level},{"message",l.message}});
    j["new_logs"] = logs_arr;

    // System metrics + history
    j["system_metrics"] = {
        {"cpu_percent",     data.system_metrics.cpu_percent},
        {"memory_percent",  data.system_metrics.memory_percent},
        {"memory_used_gb",  data.system_metrics.memory_used_gb},
        {"memory_total_gb", data.system_metrics.memory_total_gb},
        {"disk_percent",    data.system_metrics.disk_percent},
        {"disk_free_gb",    data.system_metrics.disk_free_gb},
        {"network_mbps",    data.system_metrics.network_mbps},
        {"cpu_cores",       data.system_metrics.cpu_cores},
        {"ollama_online",   data.system_metrics.ollama_online}
    };
    j["cpu_history"]  = data.cpu_history;
    j["mem_history"]  = data.mem_history;
    j["disk_history"] = data.disk_history;
    j["net_history"]  = data.net_history;

    // Firewall
    json fw_arr = json::array();
    for (const auto& f : data.firewall_blocks)
        fw_arr.push_back({{"ip",f.ip},{"rule_name_in",f.rule_name_in},
                           {"blocked_at_ms",f.blocked_at_ms},{"expires_at_ms",f.expires_at_ms}});
    j["firewall_blocks"] = fw_arr;

    // Quarantine
    json qtn_arr = json::array();
    for (const auto& q : data.quarantine_entries)
        qtn_arr.push_back({{"entry_id",q.entry_id},{"virus_name",q.virus_name},
                            {"quarantined_at_ms",q.quarantined_at_ms}});
    j["quarantine_entries"] = qtn_arr;

    // Decoy events
    json decoy_arr = json::array();
    for (const auto& d : data.decoy_events)
        decoy_arr.push_back({{"attacker_tag",d.attacker_tag},{"poison_type",d.poison_type},
                              {"action",d.action},{"timestamp_ms",d.timestamp_ms}});
    j["decoy_events"] = decoy_arr;

    // Zero Trust
    json zt_arr = json::array();
    for (const auto& z : data.zerotrust_decisions)
        zt_arr.push_back({{"user_id",z.user_id},{"decision",z.decision},
                           {"trust_score",z.trust_score},{"resource",z.resource},
                           {"timestamp",z.timestamp}});
    j["zerotrust_decisions"] = zt_arr;

    // Entropy windows
    json ew_arr = json::array();
    for (const auto& e : data.entropy_windows)
        ew_arr.push_back({{"mean_entropy_bits",e.mean_entropy_bits},
                           {"max_entropy_bits",e.max_entropy_bits},
                           {"anomalous",e.anomalous},{"window_index",e.window_index}});
    j["entropy_windows"] = ew_arr;

    // Chaos windows
    json cw_arr = json::array();
    for (const auto& c : data.chaos_windows)
        cw_arr.push_back({{"K",c.K},{"anomalous",c.anomalous},{"window_index",c.window_index}});
    j["chaos_windows"] = cw_arr;

    // Sandbox
    json sb_arr = json::array();
    for (const auto& s : data.sandbox_entries)
        sb_arr.push_back({{"rel_path",s.rel_path},{"type",s.type},
                           {"locked",s.locked},{"version",s.version}});
    j["sandbox_entries"] = sb_arr;

    // Audit
    json au_arr = json::array();
    for (const auto& a : data.audit_entries)
        au_arr.push_back({{"entry_id",a.entry_id},{"event_type",a.event_type},
                           {"timestamp",a.timestamp},{"chain_valid",a.chain_valid}});
    j["audit_entries"]    = au_arr;
    j["audit_chain_valid"]= data.audit_chain_valid;
    j["worm_is_locked"]   = data.worm_is_locked;

    // Health
    j["health"] = {
        {"ollama_online",         data.health.ollama_online},
        {"npcap_installed",       data.health.npcap_installed},
        {"npcap_service_running", data.health.npcap_service_running},
        {"clamd_online",          data.health.clamd_online},
        {"is_admin",              data.health.is_admin}
    };

    // Dependency status panel (TERRA Part 3)
    auto dep_to_json = [](const DepInfo& d) -> json {
        return json{
            {"name",        d.name},
            {"version",     d.version.empty() ? "unknown" : d.version},
            {"status",      d.status},
            {"verified_at", d.verified_at}
        };
    };
    j["deps"] = {
        {"ollama",         dep_to_json(data.health.dep_ollama)},
        {"npcap",          dep_to_json(data.health.dep_npcap)},
        {"clamd",          dep_to_json(data.health.dep_clamd)},
        {"granite_fast",   dep_to_json(data.health.dep_granite_fast)},
        {"granite_heavy",  dep_to_json(data.health.dep_granite_heavy)},
        {"granite_acc",    dep_to_json(data.health.dep_granite_acc)}
    };

    std::string json_str = j.dump(2);
    std::ofstream ofs(json_path_, std::ios::trunc);
    if (ofs) ofs << json_str;
}

} // namespace dashboard
} // namespace astartis

// Made with Bob
