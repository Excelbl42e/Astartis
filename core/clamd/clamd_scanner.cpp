// Step 14 -- ClamAV integration (DIBANET Layer 5)
// clamd_scanner.cpp
//
// TCP INSTREAM scan against a locally running clamd (Windows localhost:3310).

// Winsock2 must precede any windows.h include
#include <winsock2.h>
#include <ws2tcpip.h>
// Do NOT include <windows.h> separately -- winsock2.h already pulls it in
// and windows.h would re-include winsock.h causing redefinition errors.

#include "clamd_scanner.h"

#include <fstream>
#include <sstream>
#include <chrono>
#include <cstring>
#include <algorithm>
#include <vector>

namespace astartis {
namespace clamd {

// ---------------------------------------------------------------------------
// Helpers (file-scope)
// ---------------------------------------------------------------------------

namespace {

// Big-endian 32-bit encode
inline uint32_t be32(uint32_t v) { return htonl(v); }

} // anonymous namespace

// ---------------------------------------------------------------------------
// scan_status_name
// ---------------------------------------------------------------------------

const char* scan_status_name(ScanStatus s)
{
    switch (s) {
        case ScanStatus::SCAN_CLEAN:    return "CLEAN";
        case ScanStatus::SCAN_INFECTED: return "INFECTED";
        case ScanStatus::SCAN_ERROR:    return "ERROR";
    }
    return "UNKNOWN";
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

ClamdScanner::ClamdScanner(
    std::function<std::string(const std::string&, const std::string&)> audit_adder,
    const std::string& host,
    uint16_t port)
    : host_(host)
    , port_(port)
    , audit_adder_(std::move(audit_adder))
{
    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);
}

// ---------------------------------------------------------------------------
// connect_to_clamd
// ---------------------------------------------------------------------------

uintptr_t ClamdScanner::connect_to_clamd() const
{
    struct addrinfo hints{};
    struct addrinfo* res = nullptr;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    std::string port_str = std::to_string(port_);
    if (getaddrinfo(host_.c_str(), port_str.c_str(), &hints, &res) != 0)
        return static_cast<uintptr_t>(INVALID_SOCKET);

    SOCKET s = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) {
        freeaddrinfo(res);
        return static_cast<uintptr_t>(INVALID_SOCKET);
    }

    // Non-blocking connect with 5-second select timeout
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    ::connect(s, res->ai_addr, static_cast<int>(res->ai_addrlen));
    freeaddrinfo(res);

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(s, &wfds);
    struct timeval tv{ 5, 0 };
    int sel = ::select(0, nullptr, &wfds, nullptr, &tv);
    if (sel <= 0) {
        closesocket(s);
        return static_cast<uintptr_t>(INVALID_SOCKET);
    }

    nb = 0;
    ioctlsocket(s, FIONBIO, &nb);
    return static_cast<uintptr_t>(s);
}

// ---------------------------------------------------------------------------
// send_all
// ---------------------------------------------------------------------------

bool ClamdScanner::send_all(uintptr_t sock, const void* buf, size_t len)
{
    const char* ptr = static_cast<const char*>(buf);
    size_t rem = len;
    while (rem > 0) {
        int n = ::send(static_cast<SOCKET>(sock), ptr, static_cast<int>(rem), 0);
        if (n <= 0) return false;
        ptr += n;
        rem -= static_cast<size_t>(n);
    }
    return true;
}

// ---------------------------------------------------------------------------
// recv_line
// ---------------------------------------------------------------------------

std::string ClamdScanner::recv_line(uintptr_t sock)
{
    std::string line;
    char ch = 0;
    while (true) {
        int r = ::recv(static_cast<SOCKET>(sock), &ch, 1, 0);
        if (r <= 0) break;
        if (ch == '\n') break;
        line += ch;
    }
    if (!line.empty() && line.back() == '\r') line.pop_back();
    return line;
}

// ---------------------------------------------------------------------------
// do_instream — zINSTREAM\0 protocol
// ---------------------------------------------------------------------------

std::string ClamdScanner::do_instream(uintptr_t sock,
                                      const uint8_t* data, size_t size)
{
    // "zINSTREAM\0" — null-terminated command (10 bytes)
    const char cmd[] = { 'z','I','N','S','T','R','E','A','M','\0' };
    if (!send_all(sock, cmd, 10)) return "";

    static const size_t CHUNK = 4096;
    size_t offset = 0;
    while (offset < size) {
        size_t csz = std::min(CHUNK, size - offset);
        uint32_t belen = be32(static_cast<uint32_t>(csz));
        if (!send_all(sock, &belen, 4))              return "";
        if (!send_all(sock, data + offset, csz))     return "";
        offset += csz;
    }
    uint32_t zero = 0;
    if (!send_all(sock, &zero, 4)) return "";

    return recv_line(sock);
}

// ---------------------------------------------------------------------------
// parse_response
// ---------------------------------------------------------------------------

ScanResult ClamdScanner::parse_response(const std::string& raw,
                                        const std::string& path,
                                        int64_t duration_ms)
{
    ScanResult r;
    r.raw_response = raw;
    r.file_path    = path;
    r.duration_ms  = duration_ms;

    if (raw.empty()) {
        r.status = ScanStatus::SCAN_ERROR;
        return r;
    }

    if (raw.find(" FOUND") != std::string::npos) {
        r.status = ScanStatus::SCAN_INFECTED;
        auto colon = raw.find(": ");
        auto found = raw.rfind(" FOUND");
        if (colon != std::string::npos && found != std::string::npos)
            r.virus_name = raw.substr(colon + 2, found - (colon + 2));
    } else if (raw.find(" OK") != std::string::npos) {
        r.status = ScanStatus::SCAN_CLEAN;
    } else if (raw.find("ERROR") != std::string::npos) {
        r.status = ScanStatus::SCAN_ERROR;
    } else {
        r.status = ScanStatus::SCAN_ERROR;
    }
    return r;
}

// ---------------------------------------------------------------------------
// audit helper
// ---------------------------------------------------------------------------

void ClamdScanner::audit(ScanResult& r) const
{
    std::ostringstream p;
    p << "path="        << r.file_path
      << " status="     << scan_status_name(r.status)
      << " virus="      << r.virus_name
      << " duration_ms="<< r.duration_ms
      << " response="   << r.raw_response;
    r.audit_entry_id = audit_adder_("clamd_scan", p.str());
}

// ---------------------------------------------------------------------------
// ping
// ---------------------------------------------------------------------------

bool ClamdScanner::ping()
{
    uintptr_t sock = connect_to_clamd();
    if (sock == static_cast<uintptr_t>(INVALID_SOCKET)) return false;

    const char cmd[] = { 'z','P','I','N','G','\0' };
    bool ok = send_all(sock, cmd, 6);
    if (ok) {
        std::string resp = recv_line(sock);
        // clamd may respond "PONG" or "PONG " — accept either
        ok = (resp.find("PONG") != std::string::npos);
    }
    closesocket(static_cast<SOCKET>(sock));
    return ok;
}

// ---------------------------------------------------------------------------
// scan_buffer
// ---------------------------------------------------------------------------

ScanResult ClamdScanner::scan_buffer(const uint8_t* data, size_t size,
                                     const std::string& label)
{
    auto t0 = std::chrono::steady_clock::now();
    ScanResult r;
    r.file_path = label;

    uintptr_t sock = connect_to_clamd();
    if (sock == static_cast<uintptr_t>(INVALID_SOCKET)) {
        r.status       = ScanStatus::SCAN_ERROR;
        r.raw_response = "connection_failed";
        r.duration_ms  = 0;
    } else {
        std::string raw = do_instream(sock, data, size);
        closesocket(static_cast<SOCKET>(sock));
        int64_t ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();
        r = parse_response(raw, label, ms);
    }

    audit(r);
    return r;
}

// ---------------------------------------------------------------------------
// scan_file
// ---------------------------------------------------------------------------

ScanResult ClamdScanner::scan_file(const std::string& file_path)
{
    std::ifstream f(file_path, std::ios::binary);
    if (!f) {
        ScanResult r;
        r.file_path    = file_path;
        r.status       = ScanStatus::SCAN_ERROR;
        r.raw_response = "file_open_failed";
        r.duration_ms  = 0;
        audit(r);
        return r;
    }

    std::vector<uint8_t> buf(
        (std::istreambuf_iterator<char>(f)),
         std::istreambuf_iterator<char>());

    return scan_buffer(buf.data(), buf.size(), file_path);
}

} // namespace clamd
} // namespace astartis

// Made with Bob
