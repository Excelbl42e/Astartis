#ifndef ASTARTIS_FIREWALL_BLOCKER_H
#define ASTARTIS_FIREWALL_BLOCKER_H

// Step 16 ST-4 -- TTL-bound firewall blocking
//
// Adds inbound + outbound netsh advfirewall rules for a source IP, tracks
// active blocks, and auto-removes them on expiry via a background thread.
//
// Key design points:
//  - Every block has a TTL (default 15 min / 900 s) and self-heals on expiry.
//  - An allowlist (loopback, ::1, 0.0.0.0, plus runtime-detected gateway and
//    DNS IPs) is checked BEFORE calling netsh — blocked entry is refused, not
//    silently ignored.
//  - Rule names follow the pattern "Astartis-Block-<ip>-<epoch_ms>" so they
//    are unique and grep-able via netsh show rule.
//  - Every block and every expiry writes a firewall_block / firewall_unblock
//    audit chain entry.
//  - The whole module is Windows-only; it uses CreateProcess to invoke netsh.
//  - Requires an elevated process to add/remove firewall rules.

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <mutex>
#include <thread>
#include <atomic>
#include <cstdint>

namespace astartis {
namespace firewall {

// ---------------------------------------------------------------------------
// BlockResult
// ---------------------------------------------------------------------------

struct BlockResult {
    bool        blocked;        ///< true = rule(s) were added
    std::string reason;         ///< human-readable status / error
    std::string rule_name_in;   ///< "Astartis-Block-<ip>-<ms>-in"
    std::string rule_name_out;  ///< "Astartis-Block-<ip>-<ms>-out"
};

// ---------------------------------------------------------------------------
// ActiveBlock — internal record for one blocked IP
// ---------------------------------------------------------------------------

struct ActiveBlock {
    std::string ip;
    std::string rule_name_in;
    std::string rule_name_out;
    int64_t     blocked_at_ms;
    int64_t     expires_at_ms;
    std::string audit_entry_id;
};

// ---------------------------------------------------------------------------
// FirewallBlocker
// ---------------------------------------------------------------------------

class FirewallBlocker {
public:
    static constexpr int DEFAULT_TTL_SECONDS = 900; // 15 minutes

    /**
     * @param audit_adder      Callable (event_type, payload) -> entry_id.
     * @param default_ttl_s    TTL for blocks when caller doesn't specify one.
     * @param extra_allowlist  Additional IPs to never block (merged with the
     *                         built-in loopback set).
     */
    explicit FirewallBlocker(
        std::function<std::string(const std::string&, const std::string&)> audit_adder,
        int default_ttl_s = DEFAULT_TTL_SECONDS,
        std::vector<std::string> extra_allowlist = {}
    );

    // Stops the background expiry thread and removes all active rules.
    ~FirewallBlocker();

    FirewallBlocker(const FirewallBlocker&)            = delete;
    FirewallBlocker& operator=(const FirewallBlocker&) = delete;

    /**
     * @brief Add inbound + outbound block rules for ip.
     *
     * Returns immediately with blocked=false if ip is in the allowlist.
     * Returns blocked=false if ip is already blocked.
     * Writes a firewall_block audit entry on success.
     *
     * @param ip       IPv4 address string (e.g. "240.0.0.1")
     * @param ttl_s    Seconds until auto-expiry (0 = use default_ttl_s)
     */
    BlockResult block(const std::string& ip, int ttl_s = 0);

    /**
     * @brief Remove block rules for ip immediately (before TTL).
     *
     * Writes a firewall_unblock audit entry.
     * Returns false if ip was not blocked.
     */
    bool unblock(const std::string& ip);

    /** True if ip currently has an active block rule. */
    bool is_blocked(const std::string& ip) const;

    /** Snapshot of all currently active blocks. */
    std::vector<ActiveBlock> active_blocks() const;

    /**
     * @brief Confirm the process can actually run netsh advfirewall commands.
     *
     * Runs "netsh advfirewall show currentprofile" (harmless read-only
     * command) and returns true if the exit code is 0.
     * A non-zero exit code means the process is not elevated.
     */
    static bool ping_elevation_check();

private:
    // Build a unique rule name stem for this IP at this moment
    static std::string make_rule_stem(const std::string& ip);

    // Run netsh with the given arguments; return the process exit code.
    // Output is discarded (only the exit code matters for pass/fail).
    static int run_netsh(const std::string& args);

    // Add one netsh advfirewall rule; return true on exit-code 0.
    static bool add_rule(const std::string& name,
                         const std::string& ip,
                         const std::string& dir);   // "in" or "out"

    // Delete one netsh advfirewall rule by name; return true on exit-code 0.
    static bool delete_rule(const std::string& name);

    // Background thread: wake every 30 s, expire old blocks.
    void expiry_loop();

    // Remove block rules and audit entry — caller must hold mutex_.
    void do_unblock_locked(std::map<std::string, ActiveBlock>::iterator it);

    // Build the runtime allowlist (static entries + gateway/DNS detection).
    void build_allowlist(const std::vector<std::string>& extra);

    std::function<std::string(const std::string&, const std::string&)> audit_adder_;
    int default_ttl_s_;

    mutable std::mutex               mutex_;
    std::map<std::string, ActiveBlock> blocks_; // key = IP

    std::vector<std::string> allowlist_; // IPs we must never block

    std::atomic<bool> running_{true};
    std::thread       expiry_thread_;
};

} // namespace firewall
} // namespace astartis

#endif // ASTARTIS_FIREWALL_BLOCKER_H

// Made with Bob
