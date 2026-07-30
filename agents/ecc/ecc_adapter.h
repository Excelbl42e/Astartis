// ecc_adapter.h -- ECC Markdown agent adapter (Astartis v3.0)
//
// Parses ECC-format agent markdown files (YAML frontmatter + body).
// Converts them to AgentPersona objects loadable by AgentController.
//
// ECC File Format:
//   ---
//   name: security-reviewer
//   description: Security vulnerability detection specialist...
//   tools: ["Read", "Write", "Edit", "Bash", "Grep", "Glob"]
//   model: sonnet
//   color: orange
//   ---
//   ## Body content...
//
// Model hint mapping (ECC → Astartis tier):
//   opus    → ORCHESTRATOR
//   sonnet  → ACCURACY
//   haiku   → HEAVY
//   fast / mini → FAST
//   (missing) → HEAVY

#ifndef ASTARTIS_ECC_ADAPTER_H
#define ASTARTIS_ECC_ADAPTER_H

#include <filesystem>
#include <string>
#include <vector>

#include "agents/controller/agent_controller.h"
#include "agents/controller/granite_client.h"

namespace astartis {
namespace agents {

// ---------------------------------------------------------------------------
// Parsed ECC YAML frontmatter
// ---------------------------------------------------------------------------

struct ECCFrontmatter {
    std::string              name;
    std::string              description;
    std::vector<std::string> tools;
    std::string              model_hint;   ///< raw ECC model field ("sonnet", "haiku", etc.)
    std::string              color;
    std::string              body;         ///< Everything after second "---", trimmed
};

// ---------------------------------------------------------------------------
// ECCAdapter — static utility class
// ---------------------------------------------------------------------------

class ECCAdapter {
public:
    /**
     * @brief Returns true if the file has a valid ECC YAML frontmatter block.
     * Fast check: opens file and looks for leading "---".
     */
    static bool is_ecc_file(const std::filesystem::path& path);

    /**
     * @brief Parse YAML frontmatter from ECC markdown content.
     * Falls back gracefully: missing fields are left as empty strings.
     */
    static ECCFrontmatter parse_frontmatter(const std::string& md_content);

    /**
     * @brief Convert a parsed ECCFrontmatter to an AgentPersona.
     * The body is used as the system_prompt.
     */
    static AgentPersona to_agent_persona(const ECCFrontmatter& fm);

    /**
     * @brief Map ECC model hint string to GraniteModel tier.
     */
    static GraniteModel parse_model_hint(const std::string& hint);

    /**
     * @brief Load a single ECC .md file directly into an AgentPersona.
     * Convenience: parse_frontmatter + to_agent_persona + basic validation.
     * Returns false if the file is not a valid ECC file or parsing fails.
     */
    static bool load_from_md(const std::filesystem::path& path,
                             AgentPersona& out_persona);

private:
    static std::string yaml_to_snake_case(const std::string& name);
    static std::vector<std::string> parse_yaml_array(const std::string& value);
};

} // namespace agents
} // namespace astartis

#endif // ASTARTIS_ECC_ADAPTER_H

// Made with Bob
