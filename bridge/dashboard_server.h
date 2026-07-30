// dashboard_server.h -- Minimal HTTP server for Astartis v3.2 Dashboard
//
// Listens on 127.0.0.1:9876 only (loopback — not exposed to network).
// Per-connection thread pool: each accepted connection is handled in a
// detached std::thread so slow /exec calls never block polls or other requests.
//
// Security (v3.2 secured version):
//   - All endpoints require X-Astartis-Token header (random 32-byte hex, CryptGenRandom).
//   - CORS locked to 127.0.0.1 origin only.
//   - /exec: CreateProcessA argv dispatch with 21-prefix whitelist. No shell metacharacters.
//   - /config GET/POST: 20+ bounds checks, hot-reload callback, loopback-only ollama_host.
//   - All responses include Content-Security-Policy header.
//   - /health: unauthenticated lightweight heartbeat; returns {"ok":true} for frontend ping.
//
// Re-added in Phase 4 rebuild. Identical interface to v3.2 with no security regressions.

#ifndef DASHBOARD_SERVER_H
#define DASHBOARD_SERVER_H

// shellapi.h needed for SHELLEXECUTEINFOA (handle_npcap_verify)
// Included here so dashboard_server.cpp gets the definition without include ordering issues.
// #include <shellapi.h> is included in dashboard_server.cpp where the implementation lives.

#include <string>
#include <thread>
#include <atomic>
#include <functional>

namespace astartis {
namespace dashboard {

class DashboardServer {
public:
    // dashboard_dir: path to directory containing index.html, style.css, script.js
    // data_json_path: path to dashboard_data.json (written by DashboardWriter)
    // port: TCP port to listen on (default 9876)
    // on_config_save: called when POST /config succeeds; receives the validated config JSON string
    explicit DashboardServer(const std::string& dashboard_dir,
                              const std::string& data_json_path,
                              uint16_t port = 9876,
                              std::function<void(const std::string&)> on_config_save = nullptr);
    ~DashboardServer();

    DashboardServer(const DashboardServer&)            = delete;
    DashboardServer& operator=(const DashboardServer&) = delete;

    void start();
    void stop();
    bool is_running() const { return running_.load(); }

    // Returns the auth token (printed to stderr at startup so the operator can read it).
    // The dashboard HTML reads it from the <meta name="astartis-token"> tag injected by
    // serve_index().
    const std::string& token() const { return token_; }

private:
    void accept_loop();
    void handle_connection(uintptr_t client_fd);
    void serve_static(uintptr_t client_fd, const std::string& path);
    void serve_index(uintptr_t client_fd);
    void serve_data_json(uintptr_t client_fd);
    void serve_health(uintptr_t client_fd);
    void handle_exec(uintptr_t client_fd, const std::string& body);
    void handle_config_get(uintptr_t client_fd);
    void handle_config_post(uintptr_t client_fd, const std::string& body);
    void handle_cors_preflight(uintptr_t client_fd);
    // TERRA Part 4: Npcap verification with UAC prompt every run
    void handle_npcap_verify(uintptr_t client_fd);
    void serve_npcap_result(uintptr_t client_fd);

    bool check_token(const std::string& request) const;
    bool check_origin(const std::string& request) const;
    std::string read_full_body(uintptr_t client_fd, const std::string& headers, size_t content_length);
    void send_response(uintptr_t client_fd, int status, const std::string& content_type,
                       const std::string& body, bool add_cors = true);
    void send_error(uintptr_t client_fd, int status, const std::string& msg);

    static std::string generate_token();
    static std::string html_escape(const std::string& s);

    std::string dashboard_dir_;
    std::string data_json_path_;
    std::string config_path_;
    uint16_t    port_;
    std::string token_;
    std::function<void(const std::string&)> on_config_save_;

    std::atomic<bool> running_{false};
    std::thread       thread_;
    uintptr_t         listen_fd_{static_cast<uintptr_t>(-1)};
};

} // namespace dashboard
} // namespace astartis

#endif // DASHBOARD_SERVER_H
