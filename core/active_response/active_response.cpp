#include "active_response.h"
#include <chrono>
#include <sstream>
#include <algorithm>

namespace astartis { namespace active_response {

const char* ioc_type_name(IocType t) {
    switch (t) {
        case IocType::IOC_IP:     return "IOC_IP";
        case IocType::IOC_DOMAIN:         return "IOC_DOMAIN";
        case IocType::IOC_HASH: return "IOC_HASH";
    }
    return "UNKNOWN";
}

static int64_t now_ms_ar() {
    auto tp = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(tp).count();
}

static const IocEntry kSampleIocs[] = {
    { IocType::IOC_IP, "185.220.101.45",
      "Tor exit node used in credential stuffing (example)", "CISA AA22-040A" },
    { IocType::IOC_IP, "45.142.212.100",
      "C2 Cobalt Strike beacon (example)", "AlienVault OTX example" },
    { IocType::IOC_IP, "194.165.16.11",
      "Ransomware staging LockBit 3.0 (example)", "FBI Flash example" },
    { IocType::IOC_IP, "10.0.0.55",
      "Internal pivot source observed in auth.log", "Internal detection" },
    { IocType::IOC_DOMAIN, "update-service.corp-helpdesk.com",
      "Phishing domain impersonating IT helpdesk (example)", "PhishTank example" },
    { IocType::IOC_DOMAIN, "cdn-delivery.staticfiles.net",
      "Malware payload staging domain (example)", "URLHaus example" },
    { IocType::IOC_DOMAIN, "exfil.darkcomet-c2.xyz",
      "C2 domain for DarkComet RAT (example)", "OpenPhish example" },
    { IocType::IOC_HASH,
      "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
      "Mimikatz variant credential dumping tool (example)", "Sigma rule example" },
};

ActiveResponse::ActiveResponse(
    std::function<std::string(const std::string&, const std::string&)> audit_adder)
    : audit_adder_(std::move(audit_adder))
{
    for (const auto& ioc : kSampleIocs) ioc_list_.push_back(ioc);
}

int ActiveResponse::response_tier(int count) {
    if (count < 3)  return 0;
    if (count < 6)  return 1;
    if (count < 10) return 2;
    return 3;
}

std::string ActiveResponse::build_response(int tier,
                                            const std::string& resource,
                                            int n) {
    std::ostringstream r;
    r << "SYNTHETIC [tier=" << tier << " n=" << n << "]\n";
    switch (tier) {
        case 0:
            r << "HTTP/1.1 200 OK\n\n{\"status\":\"ok\",\"resource\":\""
              << resource << "\",\"data\":\"[synthetic payload]\"}";
            break;
        case 1:
            r << "HTTP/1.1 200 OK\n\n{\"status\":\"ok\",\"resource\":\""
              << resource << "\",\"data\":null}";
            break;
        case 2:
            r << "HTTP/1.1 206 Partial\n\n"
              << resource << ": [PARTIAL] data truncated";
            break;
        default:
            r << "HTTP/1.1 200 OK\n\n{\"redirect\":\""
              << resource << "\",\"retry_after\":0}";
            break;
    }
    return r.str();
}

ResponseEvent ActiveResponse::serve(const std::string& sid,
                                     const std::string& res,
                                     const std::string& ioc_hint) {
    std::lock_guard<std::mutex> lk(mutex_);
    int& count = session_counts_[sid];
    ++count;
    int tier = response_tier(count);
    std::string body = build_response(tier, res, count);
    bool ioc_hit = false;
    std::string matched;
    if (!ioc_hint.empty()) {
        for (const auto& e : ioc_list_) {
            if (e.indicator == ioc_hint) {
                ioc_hit = true;
                matched = ioc_hint;
                std::ostringstream p;
                p << "indicator=\"" << ioc_hint << "\""
                  << " type=" << ioc_type_name(e.type)
                  << " description=\"" << e.description << "\""
                  << " source=\"" << e.source << "\""
                  << " session=" << sid;
                audit_adder_("ioc_correlation_match", p.str());
                break;
            }
        }
    }
    ResponseEvent ev;
    ev.timestamp_ms  = now_ms_ar();
    ev.session_id    = sid;
    ev.resource      = res;
    ev.response_tier = tier;
    ev.response_body = body;
    ev.ioc_match     = ioc_hit;
    ev.ioc_indicator = matched;
    forensic_log_.push_back(ev);
    std::ostringstream p;
    p << "session=" << sid << " resource=" << res
      << " tier=" << tier << " interaction=" << count
      << " ioc_match=" << (ioc_hit ? "true" : "false");
    audit_adder_("active_response_served", p.str());
    return ev;
}

IocMatch ActiveResponse::check_ioc(const std::string& indicator) {
    std::lock_guard<std::mutex> lk(mutex_);
    for (const auto& e : ioc_list_) {
        if (e.indicator == indicator) {
            std::ostringstream p;
            p << "indicator=\"" << indicator << "\""
              << " type=" << ioc_type_name(e.type)
              << " description=\"" << e.description << "\""
              << " source=\"" << e.source << "\"";
            audit_adder_("ioc_correlation_match", p.str());
            return {true, e};
        }
    }
    return {false, {}};
}

std::vector<ResponseEvent> ActiveResponse::forensic_log() const {
    std::lock_guard<std::mutex> lk(mutex_);
    return forensic_log_;
}

int ActiveResponse::session_interaction_count(const std::string& sid) const {
    std::lock_guard<std::mutex> lk(mutex_);
    auto it = session_counts_.find(sid);
    return (it == session_counts_.end()) ? 0 : it->second;
}

}} // namespace astartis::active_response

// Made with Bob

