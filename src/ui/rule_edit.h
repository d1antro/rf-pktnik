#pragma once
#include "hooks/hooks.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace rfte {

inline constexpr size_t kRuleHexChars = 3 * kMaxRuleBytes + 64;

struct RuleForm {
    char name[128] = "";
    bool enabled = true;
    int dir = 0;
    char main[16] = "";
    char sub[16] = "";
    bool gate = false;
    char match_off[16] = "";
    char match_hex[kRuleHexChars] = "";
    int kind = 0;
    char write_off[16] = "";
    char write_hex[kRuleHexChars] = "";
    char find_hex[kRuleHexChars] = "";
    char repl_hex[kRuleHexChars] = "";
};

RuleForm form_of(const PatchRule& r);
PatchRule rule_of(const RuleForm& f);

PatchRule rule_from_bytes(Dir dir, uint8_t main, uint8_t sub, int off, const uint8_t* bytes, size_t n,
                          std::string name);

size_t active_rules(const std::vector<PatchRule>& rules);

}
