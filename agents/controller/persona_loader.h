// persona_loader.h -- Load and validate agent persona JSON files (Astartis v3.0)
//
// Validates that every persona references ONLY local Granite models.
// Any persona referencing a non-local model is rejected with an audit entry.

#ifndef ASTARTIS_PERSONA_LOADER_H
#define ASTARTIS_PERSONA_LOADER_H

#include <filesystem>
#include "agents/controller/agent_controller.h"

namespace astartis {
namespace agents {

class PersonaLoader {
public:
    /**
     * @brief Load a single AgentPersona from a JSON file.
     * @throws std::runtime_error if the file cannot be parsed.
     */
    static AgentPersona load_from_json(const std::filesystem::path& path);

    /**
     * @brief Validate that required fields are present and non-empty.
     * @return true if valid.
     */
    static bool validate_persona(const AgentPersona& persona);

    /**
     * @brief Enforce zero-API-cost policy.
     * @return true ONLY if the persona's preferred_model is one of the four
     *         local Granite tiers: FAST, HEAVY, ACCURACY, or ORCHESTRATOR.
     *
     * The JSON field "granite_model" must be one of:
     *   "fast"        → granite3.1-moe:3b
     *   "heavy"       → granite3.1-dense:8b
     *   "accuracy"    → granite4.1-8b-q5_K_M
     *   "orchestrator"→ granite4.1-8b-q5_K_M (with prefix injection)
     * Any other value causes this to return false, and the controller
     * will record an audit entry and discard the persona.
     */
    static bool is_granite_only(const AgentPersona& persona);
};

} // namespace agents
} // namespace astartis

#endif // ASTARTIS_PERSONA_LOADER_H

// Made with Bob
