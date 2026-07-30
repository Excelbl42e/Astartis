// system_config.cpp -- JSON-backed configuration loader (Astartis v2.0)

#pragma warning(push)
#pragma warning(disable: 4706 4127 4244)
#include "nlohmann/json.hpp"
#pragma warning(pop)

#include "config/system_config.h"

#include <fstream>
#include <stdexcept>

using json = nlohmann::json;

namespace astartis {
namespace config {

SystemConfig load_config(const std::filesystem::path& path)
{
    SystemConfig cfg;  // start from defaults

    if (!std::filesystem::exists(path)) {
        return cfg;  // use defaults when file absent
    }

    std::ifstream f(path);
    if (!f.is_open()) {
        throw std::runtime_error("Cannot open config file: " + path.string());
    }

    json j;
    try {
        f >> j;
    } catch (const json::parse_error& e) {
        throw std::runtime_error(
            std::string("Config parse error in ") + path.string() + ": " + e.what());
    }

    // Network
    if (j.contains("ollama_host"))   cfg.ollama_host  = j["ollama_host"].get<std::string>();
    if (j.contains("ollama_port"))   cfg.ollama_port  = j["ollama_port"].get<uint16_t>();
    if (j.contains("fast_model"))    cfg.fast_model   = j["fast_model"].get<std::string>();
    if (j.contains("heavy_model"))   cfg.heavy_model  = j["heavy_model"].get<std::string>();

    // Thresholds
    if (j.contains("chaos_threshold"))           cfg.chaos_threshold           = j["chaos_threshold"].get<double>();
    if (j.contains("rule03_failure_threshold"))  cfg.rule03_failure_threshold  = j["rule03_failure_threshold"].get<int>();
    if (j.contains("rule03_critical_threshold")) cfg.rule03_critical_threshold = j["rule03_critical_threshold"].get<int>();
    if (j.contains("escalate_confidence"))       cfg.escalate_confidence       = j["escalate_confidence"].get<double>();

    // Timing
    if (j.contains("firewall_ttl_default_s")) cfg.firewall_ttl_default_s = j["firewall_ttl_default_s"].get<int>();
    if (j.contains("chaos_window_size"))      cfg.chaos_window_size      = j["chaos_window_size"].get<int>();
    if (j.contains("tick_interval_ms"))       cfg.tick_interval_ms       = j["tick_interval_ms"].get<int>();
    if (j.contains("fast_timeout_ms"))        cfg.fast_timeout_ms        = j["fast_timeout_ms"].get<int>();
    if (j.contains("heavy_timeout_ms"))       cfg.heavy_timeout_ms       = j["heavy_timeout_ms"].get<int>();

    // Paths
    if (j.contains("sandbox_root"))   cfg.sandbox_root   = j["sandbox_root"].get<std::string>();
    if (j.contains("quarantine_dir")) cfg.quarantine_dir = j["quarantine_dir"].get<std::string>();
    if (j.contains("agents_dir"))     cfg.agents_dir     = j["agents_dir"].get<std::string>();
    if (j.contains("skills_dir"))     cfg.skills_dir     = j["skills_dir"].get<std::string>();

    // Feature flags
    if (j.contains("clamav_enabled"))    cfg.clamav_enabled    = j["clamav_enabled"].get<bool>();
    if (j.contains("firewall_enabled"))  cfg.firewall_enabled  = j["firewall_enabled"].get<bool>();
    if (j.contains("ai_triage_enabled")) cfg.ai_triage_enabled = j["ai_triage_enabled"].get<bool>();
    if (j.contains("agents_enabled"))    cfg.agents_enabled    = j["agents_enabled"].get<bool>();
    if (j.contains("pipeline_enabled"))  cfg.pipeline_enabled  = j["pipeline_enabled"].get<bool>();

    // Unlock
    if (j.contains("unlock_threshold")) cfg.unlock_threshold = j["unlock_threshold"].get<int>();

    return cfg;
}

void save_config(const SystemConfig& cfg, const std::filesystem::path& path)
{
    json j;
    j["ollama_host"]               = cfg.ollama_host;
    j["ollama_port"]               = cfg.ollama_port;
    j["fast_model"]                = cfg.fast_model;
    j["heavy_model"]               = cfg.heavy_model;
    j["chaos_threshold"]           = cfg.chaos_threshold;
    j["rule03_failure_threshold"]  = cfg.rule03_failure_threshold;
    j["rule03_critical_threshold"] = cfg.rule03_critical_threshold;
    j["escalate_confidence"]       = cfg.escalate_confidence;
    j["firewall_ttl_default_s"]    = cfg.firewall_ttl_default_s;
    j["chaos_window_size"]         = cfg.chaos_window_size;
    j["tick_interval_ms"]          = cfg.tick_interval_ms;
    j["fast_timeout_ms"]           = cfg.fast_timeout_ms;
    j["heavy_timeout_ms"]          = cfg.heavy_timeout_ms;
    j["sandbox_root"]              = cfg.sandbox_root;
    j["quarantine_dir"]            = cfg.quarantine_dir;
    j["agents_dir"]                = cfg.agents_dir;
    j["skills_dir"]                = cfg.skills_dir;
    j["clamav_enabled"]            = cfg.clamav_enabled;
    j["firewall_enabled"]          = cfg.firewall_enabled;
    j["ai_triage_enabled"]         = cfg.ai_triage_enabled;
    j["agents_enabled"]            = cfg.agents_enabled;
    j["pipeline_enabled"]          = cfg.pipeline_enabled;
    j["unlock_threshold"]          = cfg.unlock_threshold;

    std::ofstream f(path);
    f << j.dump(2) << "\n";
}

} // namespace config
} // namespace astartis

// Made with Bob
