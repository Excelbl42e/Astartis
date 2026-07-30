// action_dispatcher.cpp -- AI agent → real action dispatch (Astartis v3.0)
//
// JSON parsing uses a two-pass approach:
//   Pass 1: Try nlohmann JSON parse for structured output.
//   Pass 2: If no actionable fields found, fall back to regex-style text scan.

// Winsock2 first (required by firewall module)
#include <winsock2.h>

#pragma warning(push)
#pragma warning(disable: 4706 4127 4244)
#include "nlohmann/json.hpp"
#pragma warning(pop)

#include "agents/controller/action_dispatcher.h"
#include "agents/controller/policy_engine.h"

#include <regex>
#include <sstream>
#include <algorithm>
#include <cctype>

using json = nlohmann::json;

namespace astartis {

// ---------------------------------------------------------------------------
// Constructor
// ---------------------------------------------------------------------------

ActionDispatcher::ActionDispatcher(
    firewall::FirewallBlocker&               fw,
    quarantine::Quarantine&                  qtn,
    active_response::ActiveResponse&         ar,
    zerotrust::ZeroTrustEngine&              zt,
    std::function<std::string(const std::string&, const std::string&)> audit_adder)
    : fw_(fw)
    , qtn_(qtn)
    , ar_(ar)
    , zt_(zt)
    , audit_adder_(std::move(audit_adder))
{}

// ---------------------------------------------------------------------------
// is_safe_ip — never block loopback, RFC1918, gateway, etc.
// ---------------------------------------------------------------------------

bool ActionDispatcher::is_safe_ip(const std::string& ip)
{
    // Loopback
    if (ip == "127.0.0.1" || ip == "::1" || ip == "0.0.0.0") return true;
    // IPv6 loopback prefix
    if (ip.find("::") == 0 && ip.size() < 6)                  return true;
    // RFC 1918 private ranges — real environments block these only deliberately
    if (ip.rfind("192.168.", 0) == 0) return true;
    if (ip.rfind("10.",      0) == 0) return true;
    if (ip.rfind("172.16.",  0) == 0) return true;
    if (ip.rfind("172.17.",  0) == 0) return true;
    if (ip.rfind("172.18.",  0) == 0) return true;
    if (ip.rfind("172.19.",  0) == 0) return true;
    if (ip.rfind("172.20.",  0) == 0) return true;  // RFC 1918: 172.20-29
    if (ip.rfind("172.21.",  0) == 0) return true;
    if (ip.rfind("172.22.",  0) == 0) return true;
    if (ip.rfind("172.23.",  0) == 0) return true;
    if (ip.rfind("172.24.",  0) == 0) return true;
    if (ip.rfind("172.25.",  0) == 0) return true;
    if (ip.rfind("172.26.",  0) == 0) return true;
    if (ip.rfind("172.27.",  0) == 0) return true;
    if (ip.rfind("172.28.",  0) == 0) return true;
    if (ip.rfind("172.29.",  0) == 0) return true;
    if (ip.rfind("172.30.",  0) == 0) return true;
    if (ip.rfind("172.31.",  0) == 0) return true;
    return false;
}

// ---------------------------------------------------------------------------
// extract_ipv4 — first routable IPv4 found in text
// ---------------------------------------------------------------------------

std::string ActionDispatcher::extract_ipv4(const std::string& text)
{
    // Simple regex: 1-3 digits dot 1-3 digits dot 1-3 digits dot 1-3 digits
    std::regex ip_re(R"(\b((?:[0-9]{1,3}\.){3}[0-9]{1,3})\b)");
    std::sregex_iterator it(text.begin(), text.end(), ip_re);
    std::sregex_iterator end;
    for (; it != end; ++it) {
        std::string ip = (*it)[1].str();
        if (!is_safe_ip(ip)) return ip;
    }
    return "";
}

// ---------------------------------------------------------------------------
// extract_filepath — first Windows file path
// ---------------------------------------------------------------------------

std::string ActionDispatcher::extract_filepath(const std::string& text)
{
    // Look for C:\ or %AppData%, then grab until whitespace or quote
    std::regex path_re(R"([A-Za-z]:\\[^\s\"'<>|*?]+\.[a-zA-Z0-9]{1,6})");
    std::smatch m;
    if (std::regex_search(text, m, path_re)) return m[0].str();
    return "";
}

// ---------------------------------------------------------------------------
// try_firewall_block
// ---------------------------------------------------------------------------

bool ActionDispatcher::try_firewall_block(const std::string& output_json,
                                           const std::string& agent_name,
                                           DispatchResult& out)
{
    if (!PolicyEngine::can_block_firewall(agent_name)) return false;

    std::string target_ip;

    // Pass 1: structured JSON
    try {
        auto j = json::parse(output_json);
        // containment_actions: ["Block IP 185.220.101.42", ...]
        if (j.contains("containment_actions")) {
            const auto& ca = j["containment_actions"];
            if (ca.is_array()) {
                for (const auto& action : ca) {
                    std::string s = action.is_string() ? action.get<std::string>()
                                                       : action.dump();
                    target_ip = extract_ipv4(s);
                    if (!target_ip.empty()) break;
                }
            } else if (ca.is_string()) {
                target_ip = extract_ipv4(ca.get<std::string>());
            }
        }
        // iocs_found array fallback
        if (target_ip.empty() && j.contains("iocs_found")) {
            const auto& iocs = j["iocs_found"];
            if (iocs.is_array()) {
                for (const auto& ioc : iocs) {
                    std::string s = ioc.is_string() ? ioc.get<std::string>() : ioc.dump();
                    target_ip = extract_ipv4(s);
                    if (!target_ip.empty()) break;
                }
            }
        }
    } catch (...) {}

    // Pass 2: scan raw text for any IP
    if (target_ip.empty()) {
        target_ip = extract_ipv4(output_json);
    }

    if (target_ip.empty()) return false;

    // Block it
    auto br = fw_.block(target_ip, 900); // 15-minute TTL
    out.action_taken    = br.blocked;
    out.action_type     = "firewall_block";
    out.target          = target_ip;
    out.error_message   = br.blocked ? "" : br.reason;
    out.audit_entry_id  = audit_adder_("action_dispatcher_firewall",
                                       "agent=" + agent_name +
                                       " ip=" + target_ip +
                                       " blocked=" + (br.blocked ? "true" : "false") +
                                       " reason=" + br.reason);
    return br.blocked;
}

// ---------------------------------------------------------------------------
// try_quarantine
// ---------------------------------------------------------------------------

bool ActionDispatcher::try_quarantine(const std::string& output_json,
                                       const std::string& agent_name,
                                       DispatchResult& out)
{
    if (!PolicyEngine::can_quarantine(agent_name)) return false;

    std::string filepath;

    // Pass 1: structured JSON
    try {
        auto j = json::parse(output_json);
        // recommended_detections may contain file paths
        if (j.contains("recommended_detections")) {
            const auto& rd = j["recommended_detections"];
            if (rd.is_array()) {
                for (const auto& item : rd) {
                    std::string s = item.is_string() ? item.get<std::string>() : item.dump();
                    filepath = extract_filepath(s);
                    if (!filepath.empty()) break;
                }
            } else if (rd.is_string()) {
                filepath = extract_filepath(rd.get<std::string>());
            }
        }
        // eradication_steps fallback
        if (filepath.empty() && j.contains("eradication_steps")) {
            const auto& es = j["eradication_steps"];
            if (es.is_array()) {
                for (const auto& step : es) {
                    std::string s = step.is_string() ? step.get<std::string>() : step.dump();
                    filepath = extract_filepath(s);
                    if (!filepath.empty()) break;
                }
            }
        }
    } catch (...) {}

    // Pass 2: scan raw text
    if (filepath.empty()) {
        filepath = extract_filepath(output_json);
    }

    if (filepath.empty()) return false;

    auto entry = qtn_.quarantine_file(filepath, "AI-flagged by " + agent_name);
    bool success = !entry.entry_id.empty();
    out.action_taken   = success;
    out.action_type    = "quarantine";
    out.target         = filepath;
    out.error_message  = success ? "" : "Quarantine failed (file may not exist)";
    out.audit_entry_id = audit_adder_("action_dispatcher_quarantine",
                                      "agent=" + agent_name +
                                      " path=" + filepath +
                                      " ok=" + (success ? "true" : "false"));
    return success;
}

// ---------------------------------------------------------------------------
// try_deception
// ---------------------------------------------------------------------------

bool ActionDispatcher::try_deception(const std::string& output_json,
                                      const std::string& agent_name,
                                      DispatchResult& out)
{
    if (!PolicyEngine::can_deceive(agent_name)) return false;

    std::string session_id;

    try {
        auto j = json::parse(output_json);
        // eradication_steps may contain session IDs
        if (j.contains("eradication_steps")) {
            const auto& es = j["eradication_steps"];
            if (es.is_array() && !es.empty()) {
                std::string s = es[0].is_string() ? es[0].get<std::string>() : es[0].dump();
                // Extract session_id — look for patterns like "session_<word>" or "sess_<word>"
                std::regex sess_re(R"(\b(sess(?:ion)?_?\w{3,20})\b)", std::regex_constants::icase);
                std::smatch m;
                if (std::regex_search(s, m, sess_re)) session_id = m[1].str();
            }
        }
    } catch (...) {}

    if (session_id.empty()) session_id = "session_ai_" + agent_name;

    auto event = ar_.serve(session_id, "/ai_triggered", agent_name);
    out.action_taken   = true;
    out.action_type    = "deception";
    out.target         = session_id;
    out.error_message  = "";
    out.audit_entry_id = audit_adder_("action_dispatcher_deception",
                                      "agent=" + agent_name +
                                      " session=" + session_id +
                                      " tier=" + std::to_string(event.response_tier));
    return true;
}

// ---------------------------------------------------------------------------
// try_zerotrust_deny
// ---------------------------------------------------------------------------

bool ActionDispatcher::try_zerotrust_deny(const std::string& output_json,
                                           const std::string& agent_name,
                                           DispatchResult& out)
{
    if (!PolicyEngine::can_zerotrust_deny(agent_name)) return false;

    std::string device_id;
    std::string resource;

    try {
        auto j = json::parse(output_json);
        // recovery_checklist may contain device/access info
        if (j.contains("recovery_checklist")) {
            const auto& rc = j["recovery_checklist"];
            if (rc.is_array() && !rc.empty()) {
                std::string s = rc[0].is_string() ? rc[0].get<std::string>() : rc[0].dump();
                // Extract MAC address pattern
                std::regex mac_re(R"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})");
                std::smatch m;
                if (std::regex_search(s, m, mac_re)) device_id = m[0].str();
            }
        }
        // zt_score from zero_trust_engineer output
        if (j.contains("zt_score") && device_id.empty()) {
            device_id = "device_ai_flagged";
            resource  = j.value("zt_score", "");
        }
    } catch (...) {}

    if (device_id.empty()) device_id = "device_ai_" + agent_name;

    zerotrust::AccessContext ctx;
    ctx.user_id            = agent_name + "_assessment";
    ctx.device_id          = device_id;
    ctx.source_ip          = "0.0.0.0";
    ctx.destination_ip     = "10.0.200.1";
    ctx.requested_resource = resource.empty() ? "/ai_flagged_resource" : resource;
    ctx.ssid_name          = "ENTERPRISE";
    ctx.trust_score        = 0; // Engine will compute

    auto decision = zt_.evaluate(ctx);
    bool denied   = (decision == zerotrust::TrustDecision::DENY ||
                     decision == zerotrust::TrustDecision::QUARANTINE);

    out.action_taken   = denied;
    out.action_type    = "zerotrust_deny";
    out.target         = device_id;
    out.error_message  = denied ? "" : "ZeroTrust did not DENY (decision: " +
                         std::string(zerotrust::ZeroTrustEngine::decision_str(decision)) + ")";
    out.audit_entry_id = audit_adder_("action_dispatcher_zerotrust",
                                      "agent=" + agent_name +
                                      " device=" + device_id +
                                      " decision=" + zerotrust::ZeroTrustEngine::decision_str(decision));
    return denied;
}

// ---------------------------------------------------------------------------
// dispatch — main entry point
// ---------------------------------------------------------------------------

ActionDispatcher::DispatchResult ActionDispatcher::dispatch(
    const std::string& agent_name,
    const std::string& agent_output_json)
{
    DispatchResult result;
    result.action_taken = false;
    result.action_type  = "advisory";
    result.target       = "";
    result.error_message= "";

    if (agent_output_json.empty()) {
        result.error_message = "empty agent output";
        return result;
    }

    // Try each action type in priority order:
    // 1. Firewall block (highest priority — stops active threats)
    if (try_firewall_block(agent_output_json, agent_name, result)) return result;

    // 2. Quarantine (remove malware)
    if (try_quarantine(agent_output_json, agent_name, result))     return result;

    // 3. Deception (engage attacker)
    if (try_deception(agent_output_json, agent_name, result))      return result;

    // 4. Zero Trust deny (revoke access)
    if (try_zerotrust_deny(agent_output_json, agent_name, result)) return result;

    // No action taken — advisory mode
    result.audit_entry_id = audit_adder_("action_dispatcher_advisory",
                                         "agent=" + agent_name + " reason=no_actionable_output");
    return result;
}

} // namespace astartis

// Made with Bob
