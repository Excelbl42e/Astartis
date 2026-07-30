#ifndef ASTARTIS_CLAMD_SCANNER_H
#define ASTARTIS_CLAMD_SCANNER_H

// Step 14 -- ClamAV integration (DIBANET Layer 5)
//
// Connects to a running clamd daemon via TCP (Windows: localhost:3310).
// Streams file content using the INSTREAM command so no Unix socket path
// or clamd-side file access is required.
//
// Every scan result is written to the AuditChain regardless of outcome.
//
// Thread-safe: each scan opens its own TCP connection.

#include <string>
#include <functional>
#include <cstdint>

namespace astartis {
namespace clamd {

// ---------------------------------------------------------------------------
// Scan result
//
// Note: avoid naming enum values ERROR, CLEAN, FOUND — ERROR is a Windows
// macro (winerror.h, value 0) and would be silently redefined.
// ---------------------------------------------------------------------------

enum class ScanStatus {
    SCAN_CLEAN,     ///< clamd returned "OK"
    SCAN_INFECTED,  ///< clamd returned a virus name
    SCAN_ERROR,     ///< scan failed (connection error, timeout, etc.)
};

const char* scan_status_name(ScanStatus s);

struct ScanResult {
    ScanStatus  status;
    std::string virus_name;     ///< populated when status == SCAN_INFECTED
    std::string raw_response;   ///< full clamd response line
    std::string file_path;      ///< absolute path that was scanned
    int64_t     duration_ms;    ///< wall-clock time for the scan
    std::string audit_entry_id; ///< AuditChain entry written on completion
};

// ---------------------------------------------------------------------------
// ClamdScanner
// ---------------------------------------------------------------------------

class ClamdScanner {
public:
    /**
     * @param audit_adder  callable (event_type, payload) -> entry_id
     * @param host         clamd host (default "127.0.0.1")
     * @param port         clamd TCP port (default 3310)
     */
    explicit ClamdScanner(
        std::function<std::string(const std::string&, const std::string&)> audit_adder,
        const std::string& host = "127.0.0.1",
        uint16_t           port = 3310
    );

    ~ClamdScanner() = default;
    ClamdScanner(const ClamdScanner&)            = delete;
    ClamdScanner& operator=(const ClamdScanner&) = delete;

    /**
     * @brief Scan a file by streaming its content to clamd via INSTREAM.
     *
     * Reads the file, connects to clamd, sends "zINSTREAM\0" followed by
     * 4-byte big-endian length-prefixed chunks, then a zero-length terminator.
     * Reads the single response line and classifies it.
     *
     * Writes a "clamd_scan" audit entry on every call.
     *
     * @param file_path  Absolute path of the file to scan.
     */
    ScanResult scan_file(const std::string& file_path);

    /**
     * @brief Scan an in-memory buffer (no file needed).
     *
     * @param data   Buffer to scan.
     * @param size   Buffer length in bytes.
     * @param label  Identifier for the audit entry.
     */
    ScanResult scan_buffer(const uint8_t* data, size_t size,
                           const std::string& label);

    /**
     * @brief Send "PING" to clamd and verify it responds "PONG".
     * @return true if clamd is reachable and healthy.
     */
    bool ping();

    const std::string& host() const { return host_; }
    uint16_t           port() const { return port_; }

private:
    // Open a TCP socket to host_:port_.
    // Returns INVALID_SOCKET value (cast to uintptr_t) on failure.
    uintptr_t connect_to_clamd() const;

    // Send exactly `len` bytes; returns false on failure.
    static bool send_all(uintptr_t sock, const void* buf, size_t len);

    // Receive until '\n' or connection closed.
    static std::string recv_line(uintptr_t sock);

    // Send INSTREAM chunks from data/size, return clamd response line.
    static std::string do_instream(uintptr_t sock,
                                   const uint8_t* data, size_t size);

    // Parse a raw clamd response into a ScanResult.
    static ScanResult parse_response(const std::string& raw,
                                     const std::string& path,
                                     int64_t duration_ms);

    // Write a clamd_scan audit entry and store its ID in result.
    void audit(ScanResult& result) const;

    std::string host_;
    uint16_t    port_;
    std::function<std::string(const std::string&, const std::string&)> audit_adder_;
};

} // namespace clamd
} // namespace astartis

#endif // ASTARTIS_CLAMD_SCANNER_H

// Made with Bob
