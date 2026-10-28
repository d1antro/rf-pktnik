#pragma once
#include "hooks/hooks.h"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace rfte {

bool parse_pattern_hex(std::string_view s, std::vector<uint16_t>& out, std::string* err = nullptr);
std::string pattern_text(const std::vector<uint16_t>& p);
std::string describe_rule(const PatchRule& r);
std::string rule_label(size_t index, const PatchRule& r);
std::string rule_title(size_t index, const PatchRule& r);
std::string check_rule(const PatchRule& r);

struct CompiledRule {
    Dir dir;
    int16_t main, sub;
    uint16_t src;
    int32_t match_off;
    uint8_t match_len;
    bool replace;
    int32_t write_off;
    uint8_t len;
    uint8_t match[kMaxRuleBytes], match_any[kMaxRuleBytes];
    uint8_t find[kMaxRuleBytes], find_any[kMaxRuleBytes];
    uint8_t put[kMaxRuleBytes], keep[kMaxRuleBytes];
};

CompiledRule compile_rule(const PatchRule& r, uint16_t src);

struct Applied {
    uint32_t changed = 0;
    uint32_t rules = 0;
};

class RuleSet {
public:
    size_t set(const std::vector<PatchRule>& rules);
    void arm(bool on);

    bool armed() const {
        return armed_.load(std::memory_order_relaxed);
    }

    bool live() const {
        return live_.load(std::memory_order_relaxed);
    }

    Applied apply(Dir dir, uint8_t main, uint8_t sub, uint8_t* p, size_t len, uint8_t* before, size_t cap);
    RuleStats stats() const;

private:
    CompiledRule rules_[kMaxRules];
    size_t n_ = 0;
    uint64_t hits_[kMaxRules] = {};
    uint64_t edited_[2] = {0, 0};
    std::atomic<bool> armed_{false}, live_{false};
    mutable std::mutex mtx_;
};

}
