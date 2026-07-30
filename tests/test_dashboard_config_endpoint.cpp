// test_dashboard_config_endpoint.cpp
// Phase 4 — DashboardServer /config GET/POST tests (10 assertions)
//
// Tests: GET returns config, POST saves valid config, bounds checks,
//        token auth, invalid JSON.
//
// Starts the server on port 19877.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cassert>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <filesystem>

#include "dashboard_server.h"
#include "dashboard_writer.h"

namespace fs = std::filesystem;

static int g_pass = 0, g_fail = 0;

#define TEST(name, cond) \
    do { \
        if (cond) { std::cout << "PASS: " << name << "\n"; ++g_pass; } \
        else      { std::cerr << "FAIL: " << name << "\n"; ++g_fail; } \
    } while(0)

static std::string http_request(const std::string& req, uint16_t port)
{
    WSADATA wsa{};
    WSAStartup(MAKEWORD(2,2), &wsa);
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        closesocket(s); WSACleanup(); return "";
    }
    send(s, req.data(), static_cast<int>(req.size()), 0);
    std::string resp;
    char buf[8192];
    int n;
    DWORD to = 3000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&to), sizeof(to));
    while ((n = recv(s, buf, sizeof(buf)-1, 0)) > 0) {
        buf[n] = '\0'; resp.append(buf, n);
        if (resp.size() > 65536) break;
    }
    closesocket(s); WSACleanup();
    return resp;
}

static std::string get_config(const std::string& token, uint16_t port)
{
    std::string req =
        "GET /config HTTP/1.0\r\n"
        "Host: 127.0.0.1\r\n"
        "X-Astartis-Token: " + token + "\r\n\r\n";
    return http_request(req, port);
}

static std::string post_config(const std::string& token, const std::string& body, uint16_t port)
{
    std::string req =
        "POST /config HTTP/1.0\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "X-Astartis-Token: " + token + "\r\n\r\n" + body;
    return http_request(req, port);
}

int main()
{
    std::cout << "=== DashboardConfigEndpointTest ===\n";

    fs::path tmp_dir = fs::temp_directory_path() / "astartis_test_cfg";
    fs::create_directories(tmp_dir);
    std::string data_path = (tmp_dir / "dashboard_data.json").string();

    bool config_save_called = false;
    std::string saved_config;

    astartis::dashboard::DashboardServer server(
        tmp_dir.string(), data_path, 19877,
        [&](const std::string& cfg) {
            config_save_called = true;
            saved_config = cfg;
        });
    server.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    const std::string token = server.token();
    const uint16_t port = 19877;

    // 1. GET /config without token → 401
    {
        std::string req = "GET /config HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n";
        auto resp = http_request(req, port);
        TEST("GET config without token returns 401", resp.find("401") != std::string::npos);
    }

    // 2. GET /config with valid token → 200 with JSON body
    {
        auto resp = get_config(token, port);
        bool ok = resp.find("200") != std::string::npos &&
                  resp.find("max_concurrent_tasks") != std::string::npos;
        TEST("GET config returns 200 with defaults", ok);
    }

    // 3. POST valid config → 200 and hot-reload callback called
    {
        std::string body = "{\"max_concurrent_tasks\":8,\"ollama_timeout_s\":120,\"ollama_host\":\"127.0.0.1\",\"ollama_port\":11434}";
        auto resp = post_config(token, body, port);
        bool ok = resp.find("200") != std::string::npos && config_save_called;
        TEST("POST valid config returns 200 and calls hot-reload", ok);
    }

    // 4. POST max_concurrent_tasks out of range → 400
    {
        auto resp = post_config(token, "{\"max_concurrent_tasks\":999}", port);
        TEST("max_concurrent_tasks=999 returns 400", resp.find("400") != std::string::npos);
    }

    // 5. POST max_concurrent_tasks=0 → 400
    {
        auto resp = post_config(token, "{\"max_concurrent_tasks\":0}", port);
        TEST("max_concurrent_tasks=0 returns 400", resp.find("400") != std::string::npos);
    }

    // 6. POST ollama_timeout_s=3600 (max) → 200
    {
        auto resp = post_config(token, "{\"ollama_timeout_s\":3600}", port);
        TEST("ollama_timeout_s=3600 (max valid) returns 200", resp.find("200") != std::string::npos);
    }

    // 7. POST ollama_timeout_s=3601 → 400
    {
        auto resp = post_config(token, "{\"ollama_timeout_s\":3601}", port);
        TEST("ollama_timeout_s=3601 returns 400", resp.find("400") != std::string::npos);
    }

    // 8. POST ollama_host=non-loopback → 400
    {
        auto resp = post_config(token, "{\"ollama_host\":\"8.8.8.8\"}", port);
        TEST("ollama_host=8.8.8.8 rejected with 400", resp.find("400") != std::string::npos);
    }

    // 9. POST without token → 401
    {
        std::string body = "{\"max_concurrent_tasks\":4}";
        std::string req =
            "POST /config HTTP/1.0\r\n"
            "Host: 127.0.0.1\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
        auto resp = http_request(req, port);
        TEST("POST config without token returns 401", resp.find("401") != std::string::npos);
    }

    // 10. POST invalid JSON → 400
    {
        auto resp = post_config(token, "this is not json", port);
        TEST("POST invalid JSON returns 400", resp.find("400") != std::string::npos);
    }

    server.stop();
    fs::remove_all(tmp_dir);

    std::cout << "\nResults: " << g_pass << "/" << (g_pass + g_fail)
              << " PASS, " << g_fail << " FAIL\n";
    return g_fail > 0 ? 1 : 0;
}

// Made with Bob
