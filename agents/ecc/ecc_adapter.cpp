// ecc_adapter.cpp -- ECC Markdown agent adapter implementation (Astartis v3.0)
//
// Line-by-line YAML frontmatter parser — no external YAML library.
// Handles: simple key: value, quoted strings, inline arrays ["a", "b"].

#include "agents/ecc/ecc_adapter.h"
#include "agents/controller/persona_loader.h"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace astartis {
namespace agents {

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

namespace {

/// Trim leading and trailing whitespace from a string.
static std::string trim(const std::string& s)
{
    auto start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

/// Strip wrapping double-quotes from a string if present: "foo" → foo.
static std::string unquote(const std::string& s)
{
    std::string t = trim(s);
    if (t.size() >= 2 && t.front() == '"' && t.back() == '"') {
        return t.substr(1, t.size() - 2);
    }
    return t;
}

/// Lowercase a string in-place.
static std::string to_lower(std::string s)
{
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// ECCAdapter::yaml_to_snake_case
// ---------------------------------------------------------------------------

std::string ECCAdapter::yaml_to_snake_case(const std::string& name)
{
    std::string result = name;
    // Replace hyphens with underscores, lowercase everything
    for (auto& c : result) {
        if (c == '-') c = '_';
        else c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return result;
}

// ---------------------------------------------------------------------------
// ECCAdapter::parse_yaml_array
// ---------------------------------------------------------------------------

std::vector<std::string> ECCAdapter::parse_yaml_array(const std::string& value)
{
    std::vector<std::string> result;
    // Handles ["item1", "item2"] and [item1, item2] formats
    std::string s = trim(value);
    if (s.empty()) return result;

    // Strip surrounding brackets
    if (s.front() == '[') s = s.substr(1);
    if (!s.empty() && s.back() == ']') s = s.substr(0, s.size() - 1);

    // Split on comma
    std::istringstream ss(s);
    std::string token;
    while (std::getline(ss, token, ',')) {
        std::string item = unquote(trim(token));
        if (!item.empty()) result.push_back(item);
    }
    return result;
}

// ---------------------------------------------------------------------------
// ECCAdapter::parse_model_hint
// ---------------------------------------------------------------------------

GraniteModel ECCAdapter::parse_model_hint(const std::string& hint)
{
    std::string h = to_lower(trim(hint));
    if (h == "opus")                             return GraniteModel::ORCHESTRATOR;
    if (h == "sonnet")                           return GraniteModel::ACCURACY;
    if (h == "haiku")                            return GraniteModel::HEAVY;
    if (h == "fast" || h == "mini")              return GraniteModel::FAST;
    if (h == "accuracy")                         return GraniteModel::ACCURACY;
    if (h == "orchestrator")                     return GraniteModel::ORCHESTRATOR;
    if (h == "heavy")                            return GraniteModel::HEAVY;
    // Default: HEAVY (balanced)
    return GraniteModel::HEAVY;
}

// ---------------------------------------------------------------------------
// ECCAdapter::is_ecc_file
// ---------------------------------------------------------------------------

bool ECCAdapter::is_ecc_file(const std::filesystem::path& path)
{
    if (path.extension() != ".md") return false;
    std::ifstream f(path);
    if (!f.is_open()) return false;
    std::string first_line;
    std::getline(f, first_line);
    return trim(first_line) == "---";
}

// ---------------------------------------------------------------------------
// ECCAdapter::parse_frontmatter
// ---------------------------------------------------------------------------

ECCFrontmatter ECCAdapter::parse_frontmatter(const std::string& md_content)
{
    ECCFrontmatter fm;
    if (md_content.empty()) return fm;

    std::istringstream ss(md_content);
    std::string line;

    // Skip optional UTF-8 BOM
    auto pos = md_content.find_first_not_of("\xEF\xBB\xBF");
    std::string content = (pos != std::string::npos) ? md_content.substr(pos) : md_content;
    std::istringstream ss2(content);

    // Expect first line to be "---"
    if (!std::getline(ss2, line) || trim(line) != "---") return fm;

    // Parse key: value pairs until second "---"
    bool in_frontmatter = true;
    std::ostringstream body_builder;
    bool past_frontmatter = false;

    while (std::getline(ss2, line)) {
        if (in_frontmatter) {
            if (trim(line) == "---") {
                in_frontmatter  = false;
                past_frontmatter = true;
                continue;
            }
            // Parse key: value
            auto colon = line.find(':');
            if (colon == std::string::npos) continue;
            std::string key = to_lower(trim(line.substr(0, colon)));
            std::string val = trim(line.substr(colon + 1));

            if      (key == "name")        fm.name        = unquote(val);
            else if (key == "description") fm.description = unquote(val);
            else if (key == "model")       fm.model_hint  = unquote(val);
            else if (key == "color")       fm.color       = unquote(val);
            else if (key == "tools")       fm.tools       = parse_yaml_array(val);
        } else {
            body_builder << line << "\n";
        }
    }

    fm.body = trim(body_builder.str());
    return fm;
}

// ---------------------------------------------------------------------------
// ECCAdapter::to_agent_persona
// ---------------------------------------------------------------------------

AgentPersona ECCAdapter::to_agent_persona(const ECCFrontmatter& fm)
{
    AgentPersona p;
    p.name            = yaml_to_snake_case(fm.name);
    p.description     = fm.description;
    p.category        = "pen_test";       // ECC agents default to pen_test; overrideable
    p.preferred_model = parse_model_hint(fm.model_hint);
    p.system_prompt   = fm.body;          // ECC body IS the system prompt
    p.max_tokens      = 2048;
    p.temperature     = 0.2;
    p.input_schema    = "";
    p.output_schema   = "";
    // tools are stored in the ECC frontmatter but not directly in AgentPersona (v2 schema)
    // They are available via the ECCFrontmatter struct if needed
    return p;
}

// ---------------------------------------------------------------------------
// ECCAdapter::load_from_md
// ---------------------------------------------------------------------------

bool ECCAdapter::load_from_md(const std::filesystem::path& path,
                               AgentPersona& out_persona)
{
    if (!is_ecc_file(path)) return false;

    std::ifstream f(path);
    if (!f.is_open()) return false;
    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());

    ECCFrontmatter fm = parse_frontmatter(content);
    if (fm.name.empty()) return false;
    if (fm.body.empty()) return false;

    out_persona = to_agent_persona(fm);
    return PersonaLoader::validate_persona(out_persona);
}

} // namespace agents
} // namespace astartis

// Made with Bob
