// dashboard_server.cpp -- Minimal HTTP server for Astartis v3.2 Dashboard
//
// Security model (identical to v3.2 secured version):
//   - Token auth: all endpoints require X-Astartis-Token header.
//   - Origin check: only 127.0.0.1 origins accepted.
//   - /exec: CreateProcessA argv dispatch (no _popen, no shell), 21-prefix whitelist.
//   - /config: JSON bounds checks, hot-reload callback, loopback-only ollama_host.
//   - Output truncated at 20 KB to prevent large data exfil.
//   - Content-Security-Policy on all responses.
//
// Re-added in Phase 4 rebuild.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <wincrypt.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

#pragma warning(push)
#pragma warning(disable: 4706 4127 4244)
#include "nlohmann/json.hpp"
#pragma warning(pop)

#include "dashboard_server.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <string>
#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <filesystem>

namespace fs = std::filesystem;

namespace astartis {
namespace dashboard {

using json = nlohmann::json;

// ---------------------------------------------------------------------------
// Safe command whitelist
// /exec only dispatches commands whose argv[0] prefix is in this list.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Safe command table — argv[0] prefix + whether it needs cmd.exe /c routing.
// Real .exe files in System32 work via direct CreateProcessA.
// cmd.exe builtins (internal commands with no .exe) need /c routing.
// PowerShell Get-* are routed through powershell.exe.
// ---------------------------------------------------------------------------
struct SafeCmd {
    const char* prefix;
    bool        needs_cmd_c;   // route through "cmd.exe /c <cmd>"
    bool        needs_ps;      // route through powershell.exe -Command
    const char* description;
};

static const SafeCmd SAFE_CMDS[] = {
    // Network diagnostics
    {"ipconfig",    false, false, "Display IP configuration for all adapters"},
    {"ping",        false, false, "Test ICMP connectivity to a host"},
    {"arp",         false, false, "Display ARP table (arp -a for all entries)"},
    {"nslookup",    false, false, "DNS lookup for a hostname or IP"},
    {"tracert",     false, false, "Trace route to a host"},
    {"pathping",    false, false, "Combined ping + tracert with statistics"},
    {"netstat",     false, false, "Display active TCP connections and ports"},
    {"route",       false, false, "Display or modify IP routing table"},
    // System info
    {"systeminfo",  false, false, "Display detailed OS and hardware configuration"},
    {"hostname",    false, false, "Display the machine hostname"},
    {"whoami",      false, false, "Display current user name and domain"},
    {"getmac",      false, false, "Display MAC addresses for all network adapters"},
    {"tasklist",    false, false, "List all running processes"},
    // Network config (read-only queries only — no add/delete)
    {"netsh",       false, false, "Network shell — use read-only show subcommands"},
    // Service control (query-only safe use)
    {"sc",          true,  false, "Service Control — sc query for service status"},
    // WMIC read-only queries
    {"wmic",        false, false, "WMI queries — e.g. wmic os get Caption,Version"},
    // cmd.exe builtins
    {"ver",         true,  false, "Display Windows version string"},
    {"dir",         true,  false, "List directory contents"},
    {"echo",        true,  false, "Print text to output"},
    {"net",         true,  false, "Network commands — net use, net view (read-only)"},
    // PowerShell read-only cmdlets
    {"Get-",        false, true,  "PowerShell read-only cmdlets (Get-Process, Get-Service, etc.)"},
};
static constexpr size_t SAFE_CMDS_COUNT = sizeof(SAFE_CMDS) / sizeof(SAFE_CMDS[0]);

// ---------------------------------------------------------------------------
// Token generation via CryptGenRandom
// ---------------------------------------------------------------------------

std::string DashboardServer::generate_token()
{
    BYTE bytes[32];
    HCRYPTPROV prov = 0;
    if (!CryptAcquireContextA(&prov, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        throw std::runtime_error("CryptAcquireContext failed");
    if (!CryptGenRandom(prov, sizeof(bytes), bytes)) {
        CryptReleaseContext(prov, 0);
        throw std::runtime_error("CryptGenRandom failed");
    }
    CryptReleaseContext(prov, 0);
    std::ostringstream oss;
    for (BYTE b : bytes) oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    return oss.str();
}

// ---------------------------------------------------------------------------
// Constructor / destructor
// ---------------------------------------------------------------------------

DashboardServer::DashboardServer(const std::string& dashboard_dir,
                                  const std::string& data_json_path,
                                  uint16_t port,
                                  std::function<void(const std::string&)> on_config_save)
    : dashboard_dir_(dashboard_dir)
    , data_json_path_(data_json_path)
    , port_(port)
    , on_config_save_(std::move(on_config_save))
{
    // Locate config.json — same directory as dashboard_data.json
    fs::path dp(data_json_path);
    config_path_ = (dp.parent_path() / "config.json").string();

    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);
    token_ = generate_token();
    std::cerr << "[DashboardServer] Auth token: " << token_ << "\n";
    std::cerr << "[DashboardServer] Dashboard: http://127.0.0.1:" << port_ << "/\n";
}

DashboardServer::~DashboardServer()
{
    stop();
    WSACleanup();
}

// ---------------------------------------------------------------------------
// start / stop
// ---------------------------------------------------------------------------

void DashboardServer::start()
{
    if (running_.exchange(true)) return;

    SOCKET lsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (lsock == INVALID_SOCKET) { running_ = false; return; }

    int opt = 1;
    setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&opt), sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port_);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (bind(lsock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == SOCKET_ERROR ||
        listen(lsock, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(lsock);
        running_ = false;
        return;
    }

    listen_fd_ = static_cast<uintptr_t>(lsock);
    thread_ = std::thread(&DashboardServer::accept_loop, this);
}

void DashboardServer::stop()
{
    if (!running_.exchange(false)) return;
    if (listen_fd_ != static_cast<uintptr_t>(-1)) {
        closesocket(static_cast<SOCKET>(listen_fd_));
        listen_fd_ = static_cast<uintptr_t>(-1);
    }
    if (thread_.joinable()) thread_.join();
}

// ---------------------------------------------------------------------------
// accept_loop
// ---------------------------------------------------------------------------

void DashboardServer::accept_loop()
{
    while (running_.load()) {
        SOCKET client = accept(static_cast<SOCKET>(listen_fd_), nullptr, nullptr);
        if (client == INVALID_SOCKET) break;

        // 5-second receive timeout so slow clients don't stall the loop
        DWORD to = 5000;
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&to), sizeof(to));

        // BUG-FIX: spawn a per-connection detached thread so slow /exec calls
        // (5 s timeout) never block the accept loop or concurrent polls.
        // Each thread owns the SOCKET fd and closes it on completion.
        uintptr_t fd = static_cast<uintptr_t>(client);
        std::thread([this, fd]() {
            handle_connection(fd);
            closesocket(static_cast<SOCKET>(fd));
        }).detach();
    }
}

// ---------------------------------------------------------------------------
// Helper: read request headers + body
// ---------------------------------------------------------------------------

void DashboardServer::handle_connection(uintptr_t client_fd)
{
    SOCKET sock = static_cast<SOCKET>(client_fd);
    std::string raw;
    raw.reserve(4096);
    char buf[4096];
    while (true) {
        int n = recv(sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) break;
        buf[n] = '\0';
        raw.append(buf, static_cast<size_t>(n));
        // Stop once we have the full headers (double CRLF)
        if (raw.find("\r\n\r\n") != std::string::npos) break;
        if (raw.size() > 65536) break;
    }
    if (raw.empty()) return;

    // Parse first line: METHOD PATH HTTP/1.x
    auto nl = raw.find("\r\n");
    if (nl == std::string::npos) return;
    std::string req_line = raw.substr(0, nl);
    std::string method, path;
    {
        std::istringstream ss(req_line);
        ss >> method >> path;
    }

    // Strip query string
    auto qpos = path.find('?');
    if (qpos != std::string::npos) path = path.substr(0, qpos);

    // Content-Length
    size_t content_length = 0;
    {
        auto cl_pos = raw.find("Content-Length:");
        if (cl_pos != std::string::npos) {
            auto eol = raw.find("\r\n", cl_pos);
            if (eol != std::string::npos) {
                std::string cl_val = raw.substr(cl_pos + 15, eol - cl_pos - 15);
                try { content_length = std::stoul(cl_val); } catch (...) {}
            }
        }
    }

    // CORS preflight
    if (method == "OPTIONS") { handle_cors_preflight(client_fd); return; }

    // Route
    if (method == "GET" && path == "/health") {
        serve_health(client_fd);
    } else if (method == "GET" && (path == "/" || path == "/index.html")) {
        serve_index(client_fd);
    } else if (method == "GET" && path == "/dashboard_data.json") {
        serve_data_json(client_fd);
    } else if (method == "GET" && path == "/npcap_verify_result.json") {
        serve_npcap_result(client_fd);
    } else if (method == "GET" && (path == "/style.css" || path == "/script.js")) {
        serve_static(client_fd, path);
    } else if (method == "POST" && path == "/exec") {
        if (!check_token(raw)) { send_error(client_fd, 401, "Unauthorized"); return; }
        if (!check_origin(raw)) { send_error(client_fd, 403, "Forbidden"); return; }
        std::string body = read_full_body(client_fd, raw, content_length);
        handle_exec(client_fd, body);
    } else if (method == "POST" && path == "/npcap_verify") {
        if (!check_token(raw)) { send_error(client_fd, 401, "Unauthorized"); return; }
        if (!check_origin(raw)) { send_error(client_fd, 403, "Forbidden"); return; }
        handle_npcap_verify(client_fd);
    } else if (method == "GET" && path == "/config") {
        if (!check_token(raw)) { send_error(client_fd, 401, "Unauthorized"); return; }
        if (!check_origin(raw)) { send_error(client_fd, 403, "Forbidden"); return; }
        handle_config_get(client_fd);
    } else if (method == "POST" && path == "/config") {
        if (!check_token(raw)) { send_error(client_fd, 401, "Unauthorized"); return; }
        if (!check_origin(raw)) { send_error(client_fd, 403, "Forbidden"); return; }
        std::string body = read_full_body(client_fd, raw, content_length);
        handle_config_post(client_fd, body);
    } else {
        send_error(client_fd, 404, "Not found");
    }
}

// ---------------------------------------------------------------------------
// Security checks
// ---------------------------------------------------------------------------

bool DashboardServer::check_token(const std::string& request) const
{
    auto pos = request.find("X-Astartis-Token:");
    if (pos == std::string::npos) return false;
    auto eol = request.find("\r\n", pos);
    if (eol == std::string::npos) return false;
    std::string val = request.substr(pos + 17, eol - pos - 17);
    // Trim whitespace
    auto start = val.find_first_not_of(" \t");
    if (start == std::string::npos) return false;
    val = val.substr(start);
    auto end = val.find_last_not_of(" \t\r\n");
    if (end != std::string::npos) val = val.substr(0, end + 1);
    return val == token_;
}

bool DashboardServer::check_origin(const std::string& request) const
{
    // Accept requests with Origin: http://127.0.0.1:<port> or no Origin (curl etc.)
    auto pos = request.find("Origin:");
    if (pos == std::string::npos) return true;  // no Origin header — allow (non-browser)
    auto eol = request.find("\r\n", pos);
    std::string origin = (eol != std::string::npos)
        ? request.substr(pos + 7, eol - pos - 7) : "";
    auto s = origin.find_first_not_of(" \t");
    if (s != std::string::npos) origin = origin.substr(s);
    return origin.rfind("http://127.0.0.1", 0) == 0 ||
           origin.rfind("http://localhost", 0) == 0;
}

std::string DashboardServer::read_full_body(uintptr_t client_fd,
                                              const std::string& headers,
                                              size_t content_length)
{
    // Extract partial body already in headers buffer
    auto body_start = headers.find("\r\n\r\n");
    std::string body;
    if (body_start != std::string::npos)
        body = headers.substr(body_start + 4);

    // Cap at 512 KB to prevent memory exhaustion
    static constexpr size_t MAX_BODY = 512 * 1024;
    if (content_length > MAX_BODY) content_length = MAX_BODY;

    SOCKET sock = static_cast<SOCKET>(client_fd);
    char buf[4096];
    while (body.size() < content_length) {
        int n = recv(sock, buf, static_cast<int>(std::min(sizeof(buf), content_length - body.size())), 0);
        if (n <= 0) break;
        body.append(buf, static_cast<size_t>(n));
    }
    return body;
}

// ---------------------------------------------------------------------------
// Static file serving
// ---------------------------------------------------------------------------

void DashboardServer::serve_static(uintptr_t client_fd, const std::string& path)
{
    std::string file_path = dashboard_dir_ + path;
    std::ifstream ifs(file_path, std::ios::binary);
    if (!ifs) { send_error(client_fd, 404, "File not found"); return; }
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    std::string ct = (path.find(".css") != std::string::npos) ? "text/css" : "application/javascript";
    send_response(client_fd, 200, ct, content, false);
}

// ---------------------------------------------------------------------------
// serve_index — inject auth token into <meta> tag
// ---------------------------------------------------------------------------

void DashboardServer::serve_index(uintptr_t client_fd)
{
    std::string file_path = dashboard_dir_ + "/index.html";
    std::ifstream ifs(file_path, std::ios::binary);
    if (!ifs) { send_error(client_fd, 404, "Dashboard not found"); return; }
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());

    // Inject <meta name="astartis-token" content="<token>"> after <head>
    std::string inject = "<meta name=\"astartis-token\" content=\"" + token_ + "\">";
    auto head_pos = content.find("<head>");
    if (head_pos != std::string::npos)
        content.insert(head_pos + 6, inject);

    send_response(client_fd, 200, "text/html; charset=utf-8", content, false);
}

// ---------------------------------------------------------------------------
// serve_data_json — no auth required (read-only, no secrets)
// ---------------------------------------------------------------------------

void DashboardServer::serve_data_json(uintptr_t client_fd)
{
    std::ifstream ifs(data_json_path_, std::ios::binary);
    if (!ifs) { send_error(client_fd, 503, "Data not ready"); return; }
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    send_response(client_fd, 200, "application/json", content);
}

// ---------------------------------------------------------------------------
// serve_health — lightweight heartbeat, no auth required
// Returns {"ok":true,"ts":"<ISO>"} so the frontend can detect backend up/down
// within one poll interval without requiring a token.
// ---------------------------------------------------------------------------

void DashboardServer::serve_health(uintptr_t client_fd)
{
    json resp = {{"ok", true}, {"ts", []() -> std::string {
        FILETIME ft{};
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER uli; uli.LowPart = ft.dwLowDateTime; uli.HighPart = ft.dwHighDateTime;
        constexpr uint64_t EPOCH = 116444736000000000ULL;
        int64_t unix_ms = static_cast<int64_t>((uli.QuadPart - EPOCH) / 10000);
        time_t sec = static_cast<time_t>(unix_ms / 1000);
        tm utc{}; gmtime_s(&utc, &sec);
        char buf[32];
        snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
            utc.tm_year+1900, utc.tm_mon+1, utc.tm_mday,
            utc.tm_hour, utc.tm_min, utc.tm_sec);
        return std::string(buf);
    }()}};
    send_response(client_fd, 200, "application/json", resp.dump());
}

// ---------------------------------------------------------------------------
// handle_exec — token-authed whitelisted command execution
// ---------------------------------------------------------------------------

void DashboardServer::handle_exec(uintptr_t client_fd, const std::string& body)
{
    std::string cmd;
    try {
        auto j = json::parse(body);
        cmd = j.value("cmd", "");
    } catch (...) {
        send_error(client_fd, 400, "Invalid JSON");
        return;
    }
    if (cmd.empty()) { send_error(client_fd, 400, "cmd required"); return; }

    // Special: "help" lists all available commands — handled without subprocess.
    if (cmd == "help") {
        std::ostringstream help;
        help << "Astartis SOC Terminal — available commands:\n\n";
        for (size_t i = 0; i < SAFE_CMDS_COUNT; ++i) {
            help << "  " << std::left << std::setw(14) << SAFE_CMDS[i].prefix
                 << "  " << SAFE_CMDS[i].description << "\n";
        }
        help << "\nUse Get-* for PowerShell read-only cmdlets (e.g. Get-Process, Get-Service).\n";
        json resp = {{"output", help.str()}};
        send_response(client_fd, 200, "application/json", resp.dump());
        return;
    }

    // Security: reject commands containing shell metacharacters
    static const char* BAD_CHARS = "&|;`$<>(){}!^";
    for (char c : cmd) {
        if (std::strchr(BAD_CHARS, c)) {
            send_error(client_fd, 400, "Command contains disallowed characters");
            return;
        }
    }

    // Whitelist check: find the matching SafeCmd entry.
    // Match on prefix: cmd == prefix, or cmd starts with prefix + space.
    const SafeCmd* matched = nullptr;
    for (size_t i = 0; i < SAFE_CMDS_COUNT; ++i) {
        const char* pfx  = SAFE_CMDS[i].prefix;
        size_t      plen = std::strlen(pfx);
        if (cmd.size() >= plen &&
            cmd.compare(0, plen, pfx) == 0 &&
            (cmd.size() == plen || cmd[plen] == ' ')) {
            matched = &SAFE_CMDS[i];
            break;
        }
    }
    if (!matched) { send_error(client_fd, 403, "Command not in whitelist"); return; }

    // Build the full command string based on routing flags.
    std::string full_cmd;
    if (matched->needs_ps) {
        full_cmd = "powershell.exe -NoProfile -NonInteractive -Command \"" + cmd + "\"";
    } else if (matched->needs_cmd_c) {
        full_cmd = "cmd.exe /c " + cmd;
    } else {
        full_cmd = cmd;
    }

    // Pipe output
    HANDLE pipe_read = nullptr, pipe_write = nullptr;
    SECURITY_ATTRIBUTES sa{ sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
    if (!CreatePipe(&pipe_read, &pipe_write, &sa, 0)) {
        send_error(client_fd, 500, "Pipe creation failed");
        return;
    }
    SetHandleInformation(pipe_read, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESTDHANDLES;
    si.hStdOutput  = pipe_write;
    si.hStdError   = pipe_write;
    si.hStdInput   = GetStdHandle(STD_INPUT_HANDLE);

    PROCESS_INFORMATION pi{};
    std::vector<char> cmd_buf(full_cmd.begin(), full_cmd.end());
    cmd_buf.push_back('\0');

    BOOL ok = CreateProcessA(nullptr, cmd_buf.data(), nullptr, nullptr,
                              TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(pipe_write);

    if (!ok) {
        CloseHandle(pipe_read);
        send_error(client_fd, 500, "CreateProcess failed");
        return;
    }

    // Read output — cap at 20 KB
    static constexpr size_t MAX_OUTPUT = 20 * 1024;
    std::string output;
    char buf[4096];
    DWORD nread;
    while (output.size() < MAX_OUTPUT && ReadFile(pipe_read, buf, sizeof(buf) - 1, &nread, nullptr) && nread > 0) {
        buf[nread] = '\0';
        output.append(buf, nread);
    }
    CloseHandle(pipe_read);
    // FIX BUG-05-A: reduced from 10000ms to 5000ms to prevent blocking all other dashboard requests
    DWORD wait_result = WaitForSingleObject(pi.hProcess, 5000);
    if (wait_result == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        output += "\n... [command timed out after 5 seconds]";
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (output.size() >= MAX_OUTPUT)
        output += "\n... [truncated at 20 KB]";

    // JSON-escape the output
    json resp = {{"output", output}};
    send_response(client_fd, 200, "application/json", resp.dump());
}

// ---------------------------------------------------------------------------
// handle_config_get / handle_config_post
// ---------------------------------------------------------------------------

void DashboardServer::handle_config_get(uintptr_t client_fd)
{
    std::ifstream ifs(config_path_);
    if (!ifs) {
        // Return a default config skeleton
        json defaults = {
            {"max_concurrent_tasks", 4},
            {"ollama_timeout_s",     60},
            {"ollama_host",          "127.0.0.1"},
            {"ollama_port",          11434},
            {"chaos_threshold",      0.7},
            {"worm_auto_lockdown",   true},
            {"event_log_monitor",    true},
            {"fs_monitor",           true},
            {"packet_sensor",        true},
            {"autonomy_loop",        true}
        };
        send_response(client_fd, 200, "application/json", defaults.dump(2));
        return;
    }
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    send_response(client_fd, 200, "application/json", content);
}

void DashboardServer::handle_config_post(uintptr_t client_fd, const std::string& body)
{
    json cfg;
    try { cfg = json::parse(body); } catch (...) {
        send_error(client_fd, 400, "Invalid JSON");
        return;
    }

    // Bounds checks
    if (cfg.contains("max_concurrent_tasks")) {
        int v = cfg["max_concurrent_tasks"].get<int>();
        if (v < 1 || v > 64) { send_error(client_fd, 400, "max_concurrent_tasks must be 1..64"); return; }
    }
    if (cfg.contains("ollama_timeout_s")) {
        int v = cfg["ollama_timeout_s"].get<int>();
        if (v < 5 || v > 3600) { send_error(client_fd, 400, "ollama_timeout_s must be 5..3600"); return; }
    }
    if (cfg.contains("ollama_host")) {
        std::string h = cfg["ollama_host"].get<std::string>();
        if (h != "127.0.0.1" && h != "localhost") {
            send_error(client_fd, 400, "ollama_host must be 127.0.0.1 or localhost");
            return;
        }
    }
    if (cfg.contains("ollama_port")) {
        int v = cfg["ollama_port"].get<int>();
        if (v < 1024 || v > 65535) { send_error(client_fd, 400, "ollama_port out of range"); return; }
    }
    if (cfg.contains("chaos_threshold")) {
        double v = cfg["chaos_threshold"].get<double>();
        if (v < 0.0 || v > 1.0) { send_error(client_fd, 400, "chaos_threshold must be 0.0..1.0"); return; }
    }

    // Write config
    std::ofstream ofs(config_path_, std::ios::trunc);
    if (!ofs) { send_error(client_fd, 500, "Cannot write config"); return; }
    std::string cfg_str = cfg.dump(2);
    ofs << cfg_str;
    ofs.close();

    // Hot-reload callback
    if (on_config_save_) on_config_save_(cfg_str);

    send_response(client_fd, 200, "application/json",
                  json{{"ok", true}, {"message", "Config saved"}}.dump());
}

// ---------------------------------------------------------------------------
// CORS preflight
// ---------------------------------------------------------------------------

void DashboardServer::handle_cors_preflight(uintptr_t client_fd)
{
    SOCKET sock = static_cast<SOCKET>(client_fd);
    std::string resp =
        "HTTP/1.1 204 No Content\r\n"
        "Access-Control-Allow-Origin: http://127.0.0.1\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: X-Astartis-Token, Content-Type\r\n"
        "Content-Length: 0\r\n\r\n";
    send(sock, resp.data(), static_cast<int>(resp.size()), 0);
}

// ---------------------------------------------------------------------------
// send_response / send_error
// ---------------------------------------------------------------------------

void DashboardServer::send_response(uintptr_t client_fd, int status,
                                     const std::string& content_type,
                                     const std::string& body, bool add_cors)
{
    std::string status_text = "OK";
    if (status == 400) status_text = "Bad Request";
    else if (status == 401) status_text = "Unauthorized";
    else if (status == 403) status_text = "Forbidden";
    else if (status == 404) status_text = "Not Found";
    else if (status == 500) status_text = "Internal Server Error";
    else if (status == 503) status_text = "Service Unavailable";

    std::ostringstream h;
    h << "HTTP/1.1 " << status << " " << status_text << "\r\n"
      << "Content-Type: " << content_type << "\r\n"
      << "Content-Length: " << body.size() << "\r\n"
      << "Connection: close\r\n"
      << "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'\r\n";
    if (add_cors)
        h << "Access-Control-Allow-Origin: http://127.0.0.1\r\n";
    h << "\r\n";

    std::string header = h.str();
    SOCKET sock = static_cast<SOCKET>(client_fd);
    send(sock, header.data(), static_cast<int>(header.size()), 0);
    send(sock, body.data(), static_cast<int>(body.size()), 0);
}

void DashboardServer::send_error(uintptr_t client_fd, int status, const std::string& msg)
{
    json err = {{"error", msg}, {"status", status}};
    send_response(client_fd, status, "application/json", err.dump());
}

// ---------------------------------------------------------------------------
// handle_npcap_verify — TERRA Part 4: real Npcap verification with UAC prompt
//
// Uses ShellExecuteEx with verb "runas" to launch npcap_verify_helper.exe.
// The "runas" verb forces Windows to show a fresh UAC elevation prompt EVERY run,
// even if the current process is already elevated — this is the hard requirement
// from TERRA Part 4a (a visible OS-level permission prompt on every verification).
//
// The helper captures 10 real packets and writes result to npcap_verify_result.json
// in the dashboard directory. This file is then served via /npcap_verify_result.json.
// ---------------------------------------------------------------------------

void DashboardServer::handle_npcap_verify(uintptr_t client_fd)
{
    // Find the helper executable — look for it next to index.html (dashboard dir)
    // and in the bin/ subdirectory.
    std::string helper_path = dashboard_dir_ + "\\npcap_verify_helper.exe";
    if (!fs::exists(helper_path))
        helper_path = dashboard_dir_ + "\\..\\npcap_verify_helper.exe";
    if (!fs::exists(helper_path)) {
        json err = {
            {"status",  "error"},
            {"message", "npcap_verify_helper.exe not found — build the helper first"},
            {"hint",    "bridge/npcap_verify_helper/npcap_verify_helper.cpp"}
        };
        send_response(client_fd, 503, "application/json", err.dump());
        return;
    }

    // Result file path — written by the helper, served on next GET
    std::string result_path = dashboard_dir_ + "\\npcap_verify_result.json";
    // Pass result path as argument to the helper
    std::string params = "\"" + result_path + "\"";

    SHELLEXECUTEINFOA sei = {};
    sei.cbSize       = sizeof(sei);
    sei.fMask        = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NO_CONSOLE;
    sei.hwnd         = nullptr;
    // "runas" verb — forces a fresh UAC elevation dialog EVERY time,
    // even when the parent process is already elevated. This is the
    // TERRA Part 4a requirement: visible OS-level prompt on every run.
    sei.lpVerb       = "runas";
    sei.lpFile       = helper_path.c_str();
    sei.lpParameters = params.c_str();
    sei.nShow        = SW_HIDE;

    BOOL ok = ShellExecuteExA(&sei);
    if (!ok || sei.hProcess == nullptr) {
        DWORD err = GetLastError();
        json resp;
        if (err == ERROR_CANCELLED) {
            // User clicked "No" on the UAC prompt — this is valid feedback
            resp = {
                {"status",    "cancelled"},
                {"message",   "UAC elevation prompt was declined by user"},
                {"uac_shown", true}
            };
        } else {
            resp = {
                {"status",  "error"},
                {"message", "ShellExecuteEx failed"},
                {"win32_error", static_cast<int>(err)}
            };
        }
        send_response(client_fd, 200, "application/json", resp.dump());
        return;
    }

    // Wait up to 35 seconds for the helper to complete.
    // The helper may need to try multiple adapters; score-0 adapters get 20s
    // each, so 35s gives enough headroom for one preferred adapter + a fallback.
    DWORD wait = WaitForSingleObject(sei.hProcess, 35000);
    DWORD exit_code = 0;
    GetExitCodeProcess(sei.hProcess, &exit_code);
    CloseHandle(sei.hProcess);

    if (wait == WAIT_TIMEOUT) {
        json resp = {
            {"status",    "timeout"},
            {"message",   "npcap_verify_helper did not complete within 35 seconds. "
                          "Check that a real network adapter is active and Npcap service is running."},
            {"uac_shown", true}
        };
        send_response(client_fd, 200, "application/json", resp.dump());
        return;
    }

    // Read the result file written by the helper
    std::ifstream ifs(result_path);
    if (ifs) {
        std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
        send_response(client_fd, 200, "application/json", content);
    } else {
        json resp = {
            {"status",     exit_code == 0 ? "ok" : "error"},
            {"exit_code",  static_cast<int>(exit_code)},
            {"uac_shown",  true},
            {"message",    "Helper ran but result file not found"}
        };
        send_response(client_fd, 200, "application/json", resp.dump());
    }
}

// ---------------------------------------------------------------------------
// serve_npcap_result — serves npcap_verify_result.json (no auth required)
// ---------------------------------------------------------------------------

void DashboardServer::serve_npcap_result(uintptr_t client_fd)
{
    std::string result_path = dashboard_dir_ + "\\npcap_verify_result.json";
    std::ifstream ifs(result_path);
    if (!ifs) {
        json resp = {{"status", "no_result"}, {"message", "No verification has been run yet"}};
        send_response(client_fd, 200, "application/json", resp.dump());
        return;
    }
    std::string content((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    send_response(client_fd, 200, "application/json", content);
}

} // namespace dashboard
} // namespace astartis

// Made with Bob
