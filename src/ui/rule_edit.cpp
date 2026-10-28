#include "ui/rule_edit.h"
#include "hooks/patch_rules.h"
#include "hooks/rules_file.h"
#include <cstdio>
#include <string_view>

namespace rfte {
namespace {

template <size_t N> void put(char (&dst)[N], const std::string& s) {
    std::snprintf(dst, N, "%s", s.c_str());
}

std::string offset_box(int off) {
    char b[24];
    if (off >= 0 && off <= 0xFFFFFF) {
        std::snprintf(b, sizeof b, "+%04X", (unsigned)off);
    } else {
        std::snprintf(b, sizeof b, "%d", off);
    }
    return b;
}

bool blank(const char* s) {
    for (; *s; ++s) {
        if (*s != ' ' && *s != '\t') {
            return false;
        }
    }
    return true;
}

}

RuleForm form_of(const PatchRule& r) {
    RuleForm f;
    put(f.name, r.name);
    f.enabled = r.enabled;
    f.dir = r.dir == Dir::C2S ? 0 : 1;
    put(f.main, r.main == -1 ? std::string() : std::to_string(r.main));
    put(f.sub, r.sub == -1 ? std::string() : std::to_string(r.sub));
    f.gate = !r.match_pat.empty() || r.match_off >= 0;
    put(f.match_off, r.match_off < 0 ? std::string() : offset_box(r.match_off));
    put(f.match_hex, pattern_text(r.match_pat));
    f.kind = r.kind == PatchRule::Kind::Write ? 0 : 1;
    put(f.write_off, offset_box(r.write_off));
    put(f.write_hex, pattern_text(r.write_bytes));
    put(f.find_hex, pattern_text(r.find_bytes));
    put(f.repl_hex, pattern_text(r.repl_bytes));
    return f;
}

PatchRule rule_of(const RuleForm& f) {
    PatchRule r;
    auto fail = [&r](std::string why) {
        if (r.error.empty()) {
            r.error = std::move(why);
        }
    };
    r.name = f.name;
    r.enabled = f.enabled;
    r.dir = f.dir == 0 ? Dir::C2S : Dir::S2C;
    if (!parse_part_text(f.main, &r.main)) {
        fail("main: 0..255 (or 0x hex); blank or * = any");
    }
    if (!parse_part_text(f.sub, &r.sub)) {
        fail("sub: 0..255 (or 0x hex); blank or * = any");
    }
    std::string err;
    auto hex = [&](const char* box, std::vector<uint16_t>& out, const char* where) {
        if (!parse_pattern_hex(box, out, &err)) {
            fail(std::string(where) + err);
        }
    };
    if (f.gate) {
        if (!blank(f.match_off) && !parse_offset_text(f.match_off, &r.match_off)) {
            fail("match: offset 13, 0x0D or +000D (blank: anywhere)");
        }
        hex(f.match_hex, r.match_pat, "match: ");
    }
    if (f.kind == 0) {
        r.kind = PatchRule::Kind::Write;
        if (!parse_offset_text(f.write_off, &r.write_off)) {
            fail("write: offset 13, 0x0D or +000D");
        }
        hex(f.write_hex, r.write_bytes, "write: ");
    } else {
        r.kind = PatchRule::Kind::Replace;
        hex(f.find_hex, r.find_bytes, "find: ");
        hex(f.repl_hex, r.repl_bytes, "replace: ");
    }
    return r;
}

PatchRule rule_from_bytes(Dir dir, uint8_t main, uint8_t sub, int off, const uint8_t* bytes, size_t n,
                          std::string name) {
    PatchRule r;
    r.name = std::move(name);
    r.dir = dir;
    r.main = main;
    r.sub = sub;
    r.kind = PatchRule::Kind::Write;
    r.write_off = off;
    for (size_t i = 0; bytes && i < n && i < kMaxRuleBytes; ++i) {
        r.write_bytes.push_back(bytes[i]);
    }
    return r;
}

size_t active_rules(const std::vector<PatchRule>& rules) {
    size_t n = 0;
    for (size_t i = 0; i < rules.size() && i < kMaxRules; ++i) {
        if (rules[i].enabled && check_rule(rules[i]).empty()) {
            ++n;
        }
    }
    return n;
}

}
