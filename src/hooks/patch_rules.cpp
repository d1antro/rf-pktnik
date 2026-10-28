#include "hooks/patch_rules.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <iterator>

namespace rfte {
namespace {

const char* dir_text(Dir d) {
    return d == Dir::C2S ? "C2S" : "S2C";
}

int nib(char c) {
    return c >= '0' && c <= '9'   ? c - '0'
           : c >= 'a' && c <= 'f' ? c - 'a' + 10
           : c >= 'A' && c <= 'F' ? c - 'A' + 10
                                  : -1;
}

bool all_any(const std::vector<uint16_t>& v) {
    return std::all_of(v.begin(), v.end(), [](uint16_t b) {
        return b == kAnyByte;
    });
}

bool bytes_ok(const std::vector<uint16_t>& v) {
    return std::all_of(v.begin(), v.end(), [](uint16_t b) {
        return b <= 0xFF || b == kAnyByte;
    });
}

std::string part(int v) {
    return v < 0 ? "*" : std::to_string(v);
}

std::string off_text(int off) {
    char b[16];
    std::snprintf(b, sizeof b, "+%04X", (unsigned)off);
    return b;
}

bool equal_at(const uint8_t* p, const uint8_t* pat, const uint8_t* any, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (!any[i] && p[i] != pat[i]) {
            return false;
        }
    }
    return true;
}

bool gate(const CompiledRule& r, const uint8_t* p, size_t len) {
    if (r.match_off >= 0) {
        return (size_t)r.match_off + r.match_len <= len && equal_at(p + r.match_off, r.match, r.match_any, r.match_len);
    }
    for (size_t at = 0; at + r.match_len <= len; ++at) {
        if (equal_at(p + at, r.match, r.match_any, r.match_len)) {
            return true;
        }
    }
    return false;
}

}

bool parse_pattern_hex(std::string_view s, std::vector<uint16_t>& out, std::string* err) {
    out.clear();
    auto sep = [](char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',';
    };
    auto fail = [&](std::string why) {
        out.clear();
        if (err) {
            *err = std::move(why);
        }
        return false;
    };
    for (size_t i = 0; i < s.size();) {
        if (sep(s[i])) {
            ++i;
            continue;
        }
        size_t e = i;
        while (e < s.size() && !sep(s[e])) {
            ++e;
        }
        const std::string tok(s.substr(i, e - i));
        if (tok.size() % 2) {
            return fail("\"" + tok + "\": an odd number of characters (a byte is 2 hex digits or ??)");
        }
        for (size_t k = 0; k < tok.size(); k += 2) {
            if (tok[k] == '?' && tok[k + 1] == '?') {
                out.push_back(kAnyByte);
            } else if (nib(tok[k]) >= 0 && nib(tok[k + 1]) >= 0) {
                out.push_back((uint16_t)(nib(tok[k]) << 4 | nib(tok[k + 1])));
            } else {
                return fail("\"" + tok.substr(k, 2) + "\" is not a hex byte or ??");
            }
            if (out.size() > kMaxRuleBytes) {
                return fail("more than " + std::to_string(kMaxRuleBytes) + " bytes");
            }
        }
        i = e;
    }
    return true;
}

std::string pattern_text(const std::vector<uint16_t>& p) {
    static const char kHex[] = "0123456789ABCDEF";
    std::string s;
    for (size_t i = 0; i < p.size(); ++i) {
        if (i) {
            s += ' ';
        }
        if (p[i] == kAnyByte) {
            s += "??";
            continue;
        }
        s += kHex[(p[i] >> 4) & 0xF];
        s += kHex[p[i] & 0xF];
    }
    return s;
}

std::string describe_rule(const PatchRule& r) {
    std::string s = std::string(dir_text(r.dir)) + " (" + part(r.main) + "," + part(r.sub) + ")";
    if (!r.match_pat.empty()) {
        s += (r.match_off < 0 ? std::string(" if anywhere ") : " if " + off_text(r.match_off) + " = ") +
             pattern_text(r.match_pat) + ":";
    }
    if (r.kind == PatchRule::Kind::Write) {
        s += " write " + off_text(r.write_off) + " = " + pattern_text(r.write_bytes);
    } else {
        s += " replace " + pattern_text(r.find_bytes) + " -> " + pattern_text(r.repl_bytes);
    }
    return s;
}

std::string rule_label(size_t index, const PatchRule& r) {
    std::string s = "#" + std::to_string(index + 1);
    if (!r.name.empty()) {
        s += " \"" + r.name + "\"";
    }
    return s;
}

std::string rule_title(size_t index, const PatchRule& r) {
    return rule_label(index, r) + ": " + describe_rule(r);
}

std::string check_rule(const PatchRule& r) {
    if (!r.error.empty()) {
        return r.error;
    }
    const std::string mx = std::to_string(kMaxRuleBytes);
    if (r.main < -1 || r.main > 255) {
        return "main: 0..255, or any";
    }
    if (r.sub < -1 || r.sub > 255) {
        return "sub: 0..255, or any";
    }
    if (r.match_pat.size() > kMaxRuleBytes) {
        return "match: more than " + mx + " bytes";
    }
    if (r.match_pat.empty() && r.match_off >= 0) {
        return "match: an offset without a pattern";
    }
    if (r.match_off < -1 || r.match_off > 0xFFFF) {
        return "match: offset 0..65535 (or absent: anywhere)";
    }
    if (!bytes_ok(r.match_pat)) {
        return "match: a byte value over 0xFF";
    }
    if (r.kind == PatchRule::Kind::Write) {
        if (r.write_off < 0 || r.write_off > 0xFFFF) {
            return "write: offset 0..65535";
        }
        if (r.write_bytes.empty()) {
            return "write: no bytes";
        }
        if (r.write_bytes.size() > kMaxRuleBytes) {
            return "write: more than " + mx + " bytes";
        }
        if (!bytes_ok(r.write_bytes)) {
            return "write: a byte value over 0xFF";
        }
        if (all_any(r.write_bytes)) {
            return "write: only ?? -- it writes nothing";
        }
    } else {
        if (r.find_bytes.empty()) {
            return "replace: no find bytes";
        }
        if (r.find_bytes.size() > kMaxRuleBytes) {
            return "replace: more than " + mx + " find bytes";
        }
        if (r.repl_bytes.size() != r.find_bytes.size()) {
            return "replace: " + std::to_string(r.find_bytes.size()) + " find bytes but " +
                   std::to_string(r.repl_bytes.size()) +
                   " replace bytes -- rules are length-preserving: the same count";
        }
        if (!bytes_ok(r.find_bytes) || !bytes_ok(r.repl_bytes)) {
            return "replace: a byte value over 0xFF";
        }
        if (all_any(r.find_bytes)) {
            return "replace: find is only ?? -- it would match everywhere";
        }
        if (all_any(r.repl_bytes)) {
            return "replace: replace is only ?? -- it writes nothing";
        }
    }
    return "";
}

CompiledRule compile_rule(const PatchRule& r, uint16_t src) {
    CompiledRule c{};
    c.dir = r.dir;
    c.main = (int16_t)r.main;
    c.sub = (int16_t)r.sub;
    c.src = src;
    c.match_len = (uint8_t)r.match_pat.size();
    c.match_off = c.match_len ? r.match_off : -1;
    for (size_t i = 0; i < r.match_pat.size(); ++i) {
        c.match_any[i] = r.match_pat[i] == kAnyByte;
        c.match[i] = (uint8_t)r.match_pat[i];
    }
    c.replace = r.kind == PatchRule::Kind::Replace;
    const std::vector<uint16_t>& put = c.replace ? r.repl_bytes : r.write_bytes;
    c.write_off = c.replace ? 0 : r.write_off;
    c.len = (uint8_t)put.size();
    for (size_t i = 0; i < put.size(); ++i) {
        c.keep[i] = put[i] == kAnyByte;
        c.put[i] = (uint8_t)put[i];
    }
    if (c.replace) {
        for (size_t i = 0; i < r.find_bytes.size(); ++i) {
            c.find_any[i] = r.find_bytes[i] == kAnyByte;
            c.find[i] = (uint8_t)r.find_bytes[i];
        }
    }
    return c;
}

size_t RuleSet::set(const std::vector<PatchRule>& rules) {
    std::vector<CompiledRule> c;
    for (size_t i = 0; i < rules.size() && i < kMaxRules; ++i) {
        if (rules[i].enabled && check_rule(rules[i]).empty()) {
            c.push_back(compile_rule(rules[i], (uint16_t)i));
        }
    }
    std::lock_guard<std::mutex> lk(mtx_);
    if (!c.empty()) {
        std::memcpy(rules_, c.data(), c.size() * sizeof(CompiledRule));
    }
    n_ = c.size();
    std::fill(std::begin(hits_), std::end(hits_), uint64_t(0));
    edited_[0] = edited_[1] = 0;
    live_.store(armed_.load(std::memory_order_relaxed) && n_ > 0, std::memory_order_relaxed);
    return n_;
}

void RuleSet::arm(bool on) {
    std::lock_guard<std::mutex> lk(mtx_);
    armed_.store(on, std::memory_order_relaxed);
    live_.store(on && n_ > 0, std::memory_order_relaxed);
}

Applied RuleSet::apply(Dir dir, uint8_t m, uint8_t s, uint8_t* p, size_t len, uint8_t* before, size_t cap) {
    Applied a;
    if (!p || !len || !live_.load(std::memory_order_relaxed)) {
        return a;
    }
    bool saved = false;
    auto put = [&](size_t i, uint8_t v) {
        if (p[i] == v) {
            return;
        }
        if (!saved) {
            if (before && cap) {
                std::memcpy(before, p, len < cap ? len : cap);
            }
            saved = true;
        }
        p[i] = v;
        ++a.changed;
    };
    std::lock_guard<std::mutex> lk(mtx_);
    if (!live_.load(std::memory_order_relaxed)) {
        return a;
    }
    for (size_t k = 0; k < n_; ++k) {
        const CompiledRule& r = rules_[k];
        if (r.dir != dir || (r.main >= 0 && r.main != m) || (r.sub >= 0 && r.sub != s)) {
            continue;
        }
        if (r.match_len && !gate(r, p, len)) {
            continue;
        }
        bool hit = false;
        if (!r.replace) {
            if ((size_t)r.write_off + r.len > len) {
                continue;
            }
            for (size_t i = 0; i < r.len; ++i) {
                if (!r.keep[i]) {
                    put((size_t)r.write_off + i, r.put[i]);
                }
            }
            hit = true;
        } else {
            for (size_t at = 0; at + r.len <= len;) {
                if (!equal_at(p + at, r.find, r.find_any, r.len)) {
                    ++at;
                    continue;
                }
                for (size_t i = 0; i < r.len; ++i) {
                    if (!r.keep[i]) {
                        put(at + i, r.put[i]);
                    }
                }
                hit = true;
                at += r.len;
            }
        }
        if (hit) {
            ++hits_[r.src];
            ++a.rules;
        }
    }
    if (a.changed) {
        ++edited_[(size_t)dir];
    }
    return a;
}

RuleStats RuleSet::stats() const {
    RuleStats st;
    std::lock_guard<std::mutex> lk(mtx_);
    st.armed = armed_.load(std::memory_order_relaxed);
    st.active = (uint32_t)n_;
    st.edited[0] = edited_[0];
    st.edited[1] = edited_[1];
    std::copy(std::begin(hits_), std::end(hits_), st.hits);
    return st;
}

}
