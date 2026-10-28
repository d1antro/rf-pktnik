#pragma once
#include "hooks/hooks.h"
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace rfte {

inline constexpr wchar_t kRulesFile[] = L"RFTrafficEditor.rules.json";

struct RulesLoad {
    bool found = false;
    std::string error;
    std::vector<PatchRule> rules;
};

RulesLoad parse_rules_json(std::string_view text);
RulesLoad load_rules_file(const std::filesystem::path& p);
std::vector<std::string> describe_load(const RulesLoad& L);

bool parse_offset_text(std::string_view s, int* out);
bool parse_part_text(std::string_view s, int* out);
std::vector<std::string> describe_rules(const std::vector<PatchRule>& rules, size_t* active = nullptr);
std::string rules_json(const std::vector<PatchRule>& rules);
bool save_rules_file(const std::filesystem::path& p, const std::vector<PatchRule>& rules, std::string* err = nullptr);

}
