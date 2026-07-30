// system_config.h -- Astartis v2.0 centralised configuration
// Replaces all hardcoded magic numbers scattered across the codebase.
// Load via: astartis::config::load_config(path) or use DEFAULTS directly.

#ifndef ASTARTIS_SYSTEM_CONFIG_H
#define ASTARTIS_SYSTEM_CONFIG_H

#include <string>
#include <cstdint>
#include <filesystem>

namespace astartis {
namespace config {

struct SystemConfig {
    // -----------------------------------------------------------------------
    // Network — Ollama endpoint
    // -----------------------------------------------------------------------
    std::string ollama_host = "127.0.0.1";
    uint16_t    ollama_port = 11434;

    // -----------------------------------------------------------------------
    // AI model tags (must be local Granite only — zero API cost policy)
    // -----------------------------------------------------------------------
    std::string fast_model  = "granite3.1-moe:3b";    ///< MoE 3B: latency-critical
    std::string heavy_model = "granite3.1-dense:8b";  ///< Dense 8B: accuracy-critical

    // -----------------------------------------------------------------------
    // Threat / Rule Engine thresholds
    // -----------------------------------------------------------------------
    double chaos_threshold           = 0.9;   ///< K value for RULE-05 chaos trigger
    int    rule03_failure_threshold  = 5;     ///< consecutive failures before MEDIUM
    int    rule03_critical_threshold = 10;    ///< consecutive failures before CRITICAL
    double escalate_confidence       = 0.70;  ///< fast-tier confidence below which heavy runs

    // -----------------------------------------------------------------------
    // Timing (milliseconds unless noted)
    // -----------------------------------------------------------------------
    int firewall_ttl_default_s  = 3600;   ///< default firewall block TTL (seconds)
    int chaos_window_size       = 16;     ///< samples per chaos detection window
    int tick_interval_ms        = 500;    ///< bridge tick rate
    int fast_timeout_ms         = 15000;  ///< Ollama fast-tier socket timeout
    int heavy_timeout_ms        = 90000;  ///< Ollama heavy-tier socket timeout

    // -----------------------------------------------------------------------
    // Paths
    // -----------------------------------------------------------------------
    std::string sandbox_root    = "";        ///< "" = system temp / astartis_demo
    std::string quarantine_dir  = "";        ///< "" = auto (DEFAULT_DIR or temp)
    std::string agents_dir      = "agents/definitions";  ///< persona JSON directory
    std::string skills_dir      = "agents/skills";       ///< skill fragment directory

    // -----------------------------------------------------------------------
    // Feature flags
    // -----------------------------------------------------------------------
    bool clamav_enabled    = true;
    bool firewall_enabled  = true;
    bool ai_triage_enabled = true;
    bool agents_enabled    = true;
    bool pipeline_enabled  = true;

    // -----------------------------------------------------------------------
    // Unlock protocol
    // -----------------------------------------------------------------------
    int unlock_threshold = 3;  ///< votes needed (DEMO=3; production=12)
};

// ---------------------------------------------------------------------------
// Load from a JSON file; missing keys keep their defaults.
// Returns default-constructed SystemConfig if the file does not exist.
// Throws std::runtime_error if the file exists but cannot be parsed.
// ---------------------------------------------------------------------------
SystemConfig load_config(const std::filesystem::path& path);

// Write the current config back to a JSON file (useful for first-run generation).
void save_config(const SystemConfig& cfg, const std::filesystem::path& path);

} // namespace config
} // namespace astartis

#endif // ASTARTIS_SYSTEM_CONFIG_H

// Made with Bob
