// persona_loader.cpp -- Persona JSON loader (Astartis v3.0)

#pragma warning(push)
#pragma warning(disable: 4706 4127 4244)
#include "nlohmann/json.hpp"
#pragma warning(pop)

#include "agents/controller/persona_loader.h"
#include "agents/controller/granite_client.h"

#include <fstream>
#include <stdexcept>
#include <cctype>

using json = nlohmann::json;

namespace astartis {
namespace agents {

AgentPersona PersonaLoader::load_from_json(const std::filesystem::path& path)
{
    std::ifstream f(path);
    if (!f.is_open()) {
        throw std::runtime_error("Cannot open persona file: " + path.string());
    }

    json j;
    try {
        f >> j;
    } catch (const json::parse_error& e) {
        throw std::runtime_error(
            std::string("Persona parse error in ") + path.string() + ": " + e.what());
    }

    AgentPersona p;
    p.name          = j.value("name",          "");
    p.description   = j.value("description",   "");
    p.category      = j.value("category",      "");
    p.system_prompt = j.value("system_prompt", "");
    p.max_tokens    = j.value("max_tokens",    512);
    p.temperature   = j.value("temperature",   0.2);
    p.input_schema  = j.value("input_schema",  "");
    p.output_schema = j.value("output_schema", "");

    // Parse granite_model: "fast"|"heavy"|"accuracy"|"orchestrator" (case-insensitive)
    // Defaults to HEAVY if unrecognised.
    std::string model_str = j.value("granite_model", "heavy");
    // Lowercase normalisation
    for (auto& c : model_str) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    if (model_str == "fast") {
        p.preferred_model = GraniteModel::FAST;
    } else if (model_str == "heavy") {
        p.preferred_model = GraniteModel::HEAVY;
    } else if (model_str == "accuracy") {
        p.preferred_model = GraniteModel::ACCURACY;
    } else if (model_str == "orchestrator") {
        p.preferred_model = GraniteModel::ORCHESTRATOR;
    } else {
        p.preferred_model = GraniteModel::HEAVY;
    }

    // Parse skills array
    if (j.contains("skills") && j["skills"].is_array()) {
        for (const auto& s : j["skills"]) {
            if (s.is_string()) p.skills.push_back(s.get<std::string>());
        }
    }

    return p;
}

bool PersonaLoader::validate_persona(const AgentPersona& persona)
{
    // Required: name and system_prompt must be non-empty
    if (persona.name.empty())          return false;
    if (persona.system_prompt.empty()) return false;
    if (persona.max_tokens < 1)        return false;
    if (persona.temperature < 0.0 || persona.temperature > 2.0) return false;
    return true;
}

bool PersonaLoader::is_granite_only(const AgentPersona& persona)
{
    // All four tiers map to local Ollama models — no cloud endpoints.
    // FAST  → granite3.1-moe:3b
    // HEAVY → granite3.1-dense:8b
    // ACCURACY / ORCHESTRATOR → granite4.1-8b-q5_K_M (local)
    return (persona.preferred_model == GraniteModel::FAST        ||
            persona.preferred_model == GraniteModel::HEAVY       ||
            persona.preferred_model == GraniteModel::ACCURACY    ||
            persona.preferred_model == GraniteModel::ORCHESTRATOR);
}

} // namespace agents
} // namespace astartis

// Made with Bob
