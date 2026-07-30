#ifndef ASTARTIS_ACTIVE_RESPONSE_H
#define ASTARTIS_ACTIVE_RESPONSE_H

// Step 11 -- DIBANET Layer 3: Legal Active Response
//
// Throttled/degraded responses, granular forensic logging,
// and IOC correlation -- all within the sandbox.

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <mutex>
#include <cstdint>

namespace astartis {
namespace active_response {

// ---------------------------------------------------------------------------
// IOC types
// ---------------------------------------------------------------------------

enum class IocType { IOC_IP, IOC_DOMAIN, IOC_HASH };

const char* ioc_type_name(IocType t);

struct IocEntry {
    IocType     type;
    std::string indicator;
    std::string description;
    std::string source;
};

struct IocMatch {
    bool     matched;
    IocEntry entry;
};

// ---------------------------------------------------------------------------
// Response event (forensic log entry)
// ---------------------------------------------------------------------------

struct ResponseEvent {
    int64_t     timestamp_ms;
    std::string session_id;
    std::string resource;
    int         response_tier;  // 0-3
    std::string response_body;
    bool        ioc_match;
    std::string ioc_indicator;
};

// ---------------------------------------------------------------------------
// ActiveResponse
// ---------------------------------------------------------------------------

class ActiveResponse {
public:
    explicit ActiveResponse(
        std::function<std::string(const std::string&, const std::string&)> audit_adder
    );

    ~ActiveResponse() = default;
    ActiveResponse(const ActiveResponse&)            = delete;
    ActiveResponse& operator=(const ActiveResponse&) = delete;

    // Serve a throttled/degraded synthetic response to the attacker session.
    // ioc_hint: optional IP/domain to check against IOC list.
    ResponseEvent serve(const std::string& session_id,
                        const std::string& resource,
                        const std::string& ioc_hint = "");

    // Check an indicator against the local IOC list.
    IocMatch check_ioc(const std::string& indicator);

    // Full forensic log, oldest first.
    std::vector<ResponseEvent> forensic_log() const;

    // Number of interactions logged for a given session.
    int session_interaction_count(const std::string& session_id) const;

    // Response tier for a given interaction count.
    //   0-2  -> tier 0 (full synthetic)
    //   3-5  -> tier 1 (slightly degraded)
    //   6-9  -> tier 2 (heavily degraded)
    //   10+  -> tier 3 (honeypot loop)
    static int response_tier(int interaction_count);

    const std::vector<IocEntry>& ioc_list() const { return ioc_list_; }

private:
    static std::string build_response(int tier,
                                      const std::string& resource,
                                      int interaction_num);

    std::function<std::string(const std::string&, const std::string&)> audit_adder_;
    std::map<std::string, int>  session_counts_;
    std::vector<ResponseEvent>  forensic_log_;
    std::vector<IocEntry>       ioc_list_;
    mutable std::mutex          mutex_;
};

} // namespace active_response
} // namespace astartis

#endif // ASTARTIS_ACTIVE_RESPONSE_H

// Made with Bob
