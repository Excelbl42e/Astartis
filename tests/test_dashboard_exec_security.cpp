// test_dashboard_exec_security.cpp
// Phase 4 — DashboardServer /exec security tests (16 assertions)
//
// Tests: token auth, metacharacter rejection, whitelist enforcement,
//        origin spoofing rejection, valid command execution.
//
// Starts the server on port 19876 to avoid conflicts with :9876.

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
    char buf[4096];
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

static std::string post_exec(const std::string& token, const std::string& cmd,
                               const std::string& origin, uint16_t port)
{
    std::string body = "{\"cmd\":\"" + cmd + "\"}";
    std::string req =
        "POST /exec HTTP/1.0\r\n"
        "Host: 127.0.0.1\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "X-Astartis-Token: " + token + "\r\n" +
        (origin.empty() ? "" : "Origin: " + origin + "\r\n") +
        "\r\n" + body;
    return http_request(req, port);
}

int main()
{
    std::cout << "=== DashboardExecSecurityTest ===\n";

    // Create a temp dashboard dir
    fs::path tmp_dir = fs::temp_directory_path() / "astartis_test_exec_sec";
    fs::create_directories(tmp_dir);
    std::string data_path = (tmp_dir / "dashboard_data.json").string();

    astartis::dashboard::DashboardServer server(
        tmp_dir.string(), data_path, 19876);
    server.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    const std::string token = server.token();
    const uint16_t port = 19876;

    // 1. Missing token → 401
    {
        std::string body = "{\"cmd\":\"hostname\"}";
        std::string req =
            "POST /exec HTTP/1.0\r\nHost: 127.0.0.1\r\n"
            "Content-Type: application/json\r\nContent-Length: " +
            std::to_string(body.size()) + "\r\n\r\n" + body;
        auto resp = http_request(req, port);
        TEST("Missing token returns 401", resp.find("401") != std::string::npos);
    }

    // 2. Wrong token → 401
    {
        auto resp = post_exec("deadbeefdeadbeef", "hostname", "", port);
        TEST("Wrong token returns 401", resp.find("401") != std::string::npos);
    }

    // 3. Valid token, no origin → 200 (no-Origin allowed for curl/cli)
    {
        auto resp = post_exec(token, "hostname", "", port);
        TEST("Valid token no origin returns 200", resp.find("200") != std::string::npos);
    }

    // 4. Valid token, loopback origin → 200
    {
        auto resp = post_exec(token, "hostname", "http://127.0.0.1:19876", port);
        TEST("Loopback origin accepted", resp.find("200") != std::string::npos);
    }

    // 5. Valid token, external origin → 403
    {
        auto resp = post_exec(token, "hostname", "http://evil.com", port);
        TEST("External origin rejected with 403", resp.find("403") != std::string::npos);
    }

    // 6. Metacharacter '&' → 400
    {
        auto resp = post_exec(token, "hostname & whoami", "http://127.0.0.1:19876", port);
        TEST("Metachar & rejected with 400", resp.find("400") != std::string::npos);
    }

    // 7. Metacharacter '|' → 400
    {
        auto resp = post_exec(token, "hostname | net user", "http://127.0.0.1:19876", port);
        TEST("Metachar | rejected with 400", resp.find("400") != std::string::npos);
    }

    // 8. Metacharacter ';' → 400
    {
        auto resp = post_exec(token, "hostname; whoami", "http://127.0.0.1:19876", port);
        TEST("Metachar ; rejected with 400", resp.find("400") != std::string::npos);
    }

    // 9. Backtick → 400
    {
        auto resp = post_exec(token, "hostname`whoami", "http://127.0.0.1:19876", port);
        TEST("Backtick rejected with 400", resp.find("400") != std::string::npos);
    }

    // 10. Not-in-whitelist command → 403
    {
        auto resp = post_exec(token, "shutdown /s /t 0", "http://127.0.0.1:19876", port);
        TEST("Non-whitelisted cmd rejected with 403", resp.find("403") != std::string::npos);
    }

    // 11. 'del' not in whitelist → 403
    // Use a path with forward slashes to avoid JSON parse failure on raw backslashes.
    {
        auto resp = post_exec(token, "del important_file.txt", "http://127.0.0.1:19876", port);
        TEST("del not in whitelist → 403", resp.find("403") != std::string::npos);
    }

    // 12. whitelisted 'ver' → 200 with output
    {
        auto resp = post_exec(token, "ver", "http://127.0.0.1:19876", port);
        TEST("whitelisted ver returns 200", resp.find("200") != std::string::npos);
    }

    // 13. whitelisted 'hostname' → 200 with non-empty output field
    {
        auto resp = post_exec(token, "hostname", "http://127.0.0.1:19876", port);
        bool has_output = resp.find("\"output\"") != std::string::npos;
        TEST("hostname returns output field", has_output);
    }

    // 14. Content-Security-Policy present on response
    {
        auto resp = post_exec(token, "ver", "http://127.0.0.1:19876", port);
        TEST("CSP header present", resp.find("Content-Security-Policy") != std::string::npos);
    }

    // 15. Empty cmd → 400
    {
        auto resp = post_exec(token, "", "http://127.0.0.1:19876", port);
        TEST("Empty cmd returns 400", resp.find("400") != std::string::npos);
    }

    // 16. Invalid JSON body → 400
    {
        std::string bad_body = "not json at all";
        std::string req =
            "POST /exec HTTP/1.0\r\nHost: 127.0.0.1\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: " + std::to_string(bad_body.size()) + "\r\n"
            "X-Astartis-Token: " + token + "\r\n\r\n" + bad_body;
        auto resp = http_request(req, port);
        TEST("Invalid JSON body returns 400", resp.find("400") != std::string::npos);
    }

    server.stop();
    fs::remove_all(tmp_dir);

    std::cout << "\nResults: " << g_pass << "/" << (g_pass + g_fail)
              << " PASS, " << g_fail << " FAIL\n";
    return g_fail > 0 ? 1 : 0;
}

// Made with Bob
