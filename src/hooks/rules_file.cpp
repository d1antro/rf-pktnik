#include "hooks/rules_file.h"
#include "hooks/patch_rules.h"
#include <nlohmann/json.hpp>
#include <cctype>
#include <climits>
#include <cstdio>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <system_error>

namespace rfte {
namespace {
using json = nlohmann::json;

const char* const kOffsetForms = "13, \"0x0D\" or \"+000D\"";

int digit(char c, int base) {
    const int d = c >= '0' && c <= '9'   ? c - '0'
                  : c >= 'a' && c <= 'f' ? c - 'a' + 10
                  : c >= 'A' && c <= 'F' ? c - 'A' + 10
                                         : -1;
    return d < base ? d : -1;
}

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) {
        s.remove_prefix(1);
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) {
        s.remove_suffix(1);
    }
    return s;
}

bool parse_digits(std::string_view s, int base, int* out) {
    if (s.empty()) {
        return false;
    }
    long long x = 0;
    for (const char c : s) {
        const int d = digit(c, base);
        if (d < 0) {
            return false;
        }
        x = x * base + d;
        if (x > 0xFFFFFF) {
            return false;
        }
    }
    *out = (int)x;
    return true;
}

bool parse_offset(const json& v, int* out) {
    if (v.is_number_integer()) {
        const long long x = v.get<long long>();
        if (x < INT_MIN || x > INT_MAX) {
            return false;
        }
        *out = (int)x;
        return true;
    }
    return v.is_string() && parse_offset_text(v.get<std::string>(), out);
}

bool parse_part(const json& e, const char* key, int* out) {
    const auto it = e.find(key);
    if (it == e.end() || it->is_null() || (it->is_string() && it->get<std::string>() == "*")) {
        *out = -1;
        return true;
    }
    if (!it->is_number_integer()) {
        return false;
    }
    const long long x = it->get<long long>();
    if (x < INT_MIN || x > INT_MAX) {
        return false;
    }
    *out = (int)x;
    return true;
}

std::string unknown_key(const json& o, std::initializer_list<const char*> known, const char* where) {
    for (const auto& kv : o.items()) {
        bool ok = false;
        for (const char* k : known) {
            ok = ok || kv.key() == k;
        }
        if (!ok) {
            return std::string(where) + "unknown key \"" + kv.key() + "\"";
        }
    }
    return "";
}

std::string offset_json(int off) {
    if (off < 0 || off > 0xFFFF) {
        return std::to_string(off);
    }
    char b[16];
    std::snprintf(b, sizeof b, "\"+%04X\"", (unsigned)off);
    return b;
}

std::string quoted(const std::string& s) {
    return json(s).dump(-1, ' ', false, json::error_handler_t::replace);
}

const char* const kSavedHeader =
    "// pktnik -- patch rules, saved by the Rules editor (format: README, section \"Patch rules\").\n"
    "// Loaded DISARMED: tick Rules in the tool window to apply them (it asks first).\n";

PatchRule parse_rule(const json& e) {
    PatchRule r;
    auto fail = [&r](const std::string& why) {
        if (r.error.empty()) {
            r.error = why;
        }
    };
    if (!e.is_object()) {
        fail("not an object");
        return r;
    }
    fail(unknown_key(e, {"name", "enabled", "dir", "main", "sub", "match", "action"}, ""));
    if (const auto it = e.find("name"); it != e.end()) {
        if (it->is_string()) {
            r.name = it->get<std::string>();
        } else {
            fail("name: a string");
        }
    }
    if (const auto it = e.find("enabled"); it != e.end()) {
        if (it->is_boolean()) {
            r.enabled = it->get<bool>();
        } else {
            fail("enabled: true or false");
        }
    }
    if (const auto it = e.find("dir"); it == e.end()) {
        fail("dir: missing (\"C2S\" or \"S2C\")");
    } else {
        std::string d = it->is_string() ? it->get<std::string>() : std::string();
        for (char& ch : d) {
            ch = (char)std::toupper((unsigned char)ch);
        }
        if (d == "C2S") {
            r.dir = Dir::C2S;
        } else if (d == "S2C") {
            r.dir = Dir::S2C;
        } else {
            fail("dir: \"C2S\" or \"S2C\"");
        }
    }
    if (!parse_part(e, "main", &r.main)) {
        fail("main: 0..255, \"*\" or absent");
    }
    if (!parse_part(e, "sub", &r.sub)) {
        fail("sub: 0..255, \"*\" or absent");
    }
    std::string err;
    auto hex = [&](const json& o, const char* key, std::vector<uint16_t>& out, const char* where) {
        const auto it = o.find(key);
        if (it == o.end() || !it->is_string()) {
            fail(std::string(where) + key + ": missing (a hex string like \"39 30 ?? ??\")");
        } else if (!parse_pattern_hex(it->get<std::string>(), out, &err)) {
            fail(std::string(where) + key + ": " + err);
        }
    };
    if (const auto it = e.find("match"); it != e.end()) {
        if (!it->is_object()) {
            fail("match: an object { \"offset\"?, \"hexPattern\" }");
        } else {
            fail(unknown_key(*it, {"offset", "hexPattern"}, "match: "));
            if (const auto o = it->find("offset"); o != it->end() && !parse_offset(*o, &r.match_off)) {
                fail(std::string("match.offset: ") + kOffsetForms);
            }
            hex(*it, "hexPattern", r.match_pat, "match.");
        }
    }
    if (const auto it = e.find("action"); it == e.end() || !it->is_object()) {
        fail("action: missing -- { \"offset\", \"hexReplace\" } or { \"findHex\", \"replaceHex\" }");
    } else {
        const json& a = *it;
        fail(unknown_key(a, {"offset", "hexReplace", "findHex", "replaceHex"}, "action: "));
        const bool w = a.contains("offset") || a.contains("hexReplace");
        const bool f = a.contains("findHex") || a.contains("replaceHex");
        if (w == f) {
            fail("action: either { \"offset\", \"hexReplace\" } or { \"findHex\", \"replaceHex\" }");
        } else if (w) {
            r.kind = PatchRule::Kind::Write;
            const auto o = a.find("offset");
            if (o == a.end() || !parse_offset(*o, &r.write_off)) {
                fail(std::string("action.offset: ") + kOffsetForms);
            }
            hex(a, "hexReplace", r.write_bytes, "action.");
        } else {
            r.kind = PatchRule::Kind::Replace;
            hex(a, "findHex", r.find_bytes, "action.");
            hex(a, "replaceHex", r.repl_bytes, "action.");
        }
    }
    return r;
}

}

RulesLoad parse_rules_json(std::string_view text) {
    RulesLoad L;
    L.found = true;
    json j;
    try {
        j = json::parse(text.data(), text.data() + text.size(), nullptr, true, true);
    } catch (const json::parse_error& e) {
        L.error = std::string("not valid JSON: ") + e.what();
        return L;
    }
    if (!j.is_object() || !j.contains("rules") || !j.at("rules").is_array()) {
        L.error = "no \"rules\" array at the top level -- { \"rules\": [ ... ] }";
        return L;
    }
    for (const json& e : j.at("rules")) {
        L.rules.push_back(parse_rule(e));
    }
    return L;
}

RulesLoad load_rules_file(const std::filesystem::path& p) {
    std::error_code ec;
    if (p.empty() || !std::filesystem::exists(p, ec)) {
        return RulesLoad{};
    }
    std::ifstream f(p, std::ios::binary);
    if (!f) {
        RulesLoad L;
        L.found = true;
        L.error = "cannot open the file";
        return L;
    }
    const std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return parse_rules_json(text);
}

bool parse_offset_text(std::string_view s, int* out) {
    s = trim(s);
    if (s.size() > 1 && s[0] == '+') {
        return parse_digits(s.substr(1), 16, out);
    }
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        return parse_digits(s.substr(2), 16, out);
    }
    return parse_digits(s, 10, out);
}

bool parse_part_text(std::string_view s, int* out) {
    s = trim(s);
    if (s.empty() || s == "*") {
        *out = -1;
        return true;
    }
    if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        return parse_digits(s.substr(2), 16, out);
    }
    return parse_digits(s, 10, out);
}

std::vector<std::string> describe_rules(const std::vector<PatchRule>& rules, size_t* active) {
    std::vector<std::string> out;
    size_t n = 0;
    for (size_t i = 0; i < rules.size(); ++i) {
        const PatchRule& r = rules[i];
        if (!r.error.empty()) {
            out.push_back(rule_label(i, r) + ": INVALID: " + r.error + " (not applied)");
            continue;
        }
        std::string s = rule_title(i, r);
        const std::string why = check_rule(r);
        if (!why.empty()) {
            s += " -- INVALID: " + why + " (not applied)";
        } else if (i >= kMaxRules) {
            s += " -- ignored: only the first " + std::to_string(kMaxRules) + " rules are used";
        } else if (!r.enabled) {
            s += " -- disabled";
        } else {
            s += " -- ok";
            ++n;
        }
        out.push_back(std::move(s));
    }
    if (active) {
        *active = n;
    }
    return out;
}

std::vector<std::string> describe_load(const RulesLoad& L) {
    const std::string file = "RFTrafficEditor.rules.json";
    if (!L.found) {
        return {"no " + file +
                " next to the DLL -- no patch rules (RFTrafficEditor.rules.example.json shows the format)"};
    }
    if (!L.error.empty()) {
        return {file + ": " + L.error + " -- no patch rules"};
    }
    size_t active = 0;
    std::vector<std::string> out = describe_rules(L.rules, &active);
    out.push_back(std::to_string(L.rules.size()) + " rule(s) in " + file + ", " + std::to_string(active) +
                  " active (enabled and valid)");
    return out;
}

std::string rules_json(const std::vector<PatchRule>& rules) {
    std::string s = kSavedHeader;
    if (rules.empty()) {
        return s + "{\n  \"rules\": []\n}\n";
    }
    s += "{\n  \"rules\": [\n";
    for (size_t i = 0; i < rules.size(); ++i) {
        const PatchRule& r = rules[i];
        s += "    {\n";
        if (!r.name.empty()) {
            s += "      \"name\": " + quoted(r.name) + ",\n";
        }
        s += std::string("      \"enabled\": ") + (r.enabled ? "true" : "false") + ",\n";
        s += std::string("      \"dir\": \"") + (r.dir == Dir::C2S ? "C2S" : "S2C") + "\"";
        if (r.main != -1) {
            s += ", \"main\": " + std::to_string(r.main);
        }
        if (r.sub != -1) {
            s += ", \"sub\": " + std::to_string(r.sub);
        }
        s += ",\n";
        if (!r.match_pat.empty() || r.match_off >= 0) {
            s += "      \"match\": { ";
            if (r.match_off >= 0) {
                s += "\"offset\": " + offset_json(r.match_off) + ", ";
            }
            s += "\"hexPattern\": \"" + pattern_text(r.match_pat) + "\" },\n";
        }
        if (r.kind == PatchRule::Kind::Write) {
            s += "      \"action\": { \"offset\": " + offset_json(r.write_off) + ", \"hexReplace\": \"" +
                 pattern_text(r.write_bytes) + "\" }\n";
        } else {
            s += "      \"action\": { \"findHex\": \"" + pattern_text(r.find_bytes) + "\", \"replaceHex\": \"" +
                 pattern_text(r.repl_bytes) + "\" }\n";
        }
        s += i + 1 < rules.size() ? "    },\n" : "    }\n";
    }
    return s + "  ]\n}\n";
}

bool save_rules_file(const std::filesystem::path& p, const std::vector<PatchRule>& rules, std::string* err) {
    auto fail = [err](std::string why) {
        if (err) {
            *err = std::move(why);
        }
        return false;
    };
    if (p.empty()) {
        return fail("no path for the rules file (the DLL's folder is unknown)");
    }
    for (size_t i = 0; i < rules.size(); ++i) {
        if (!rules[i].error.empty()) {
            return fail(rule_label(i, rules[i]) + " did not parse (" + rules[i].error +
                        ") -- fix it or delete it first");
        }
    }
    const std::string text = rules_json(rules);
    const std::string name = p.filename().string();
    std::error_code ec;
    if (std::filesystem::exists(p, ec)) {
        std::filesystem::path bak = p;
        bak += L".bak";
        if (!std::filesystem::copy_file(p, bak, std::filesystem::copy_options::overwrite_existing, ec)) {
            return fail("cannot back up the previous " + name + " to " + bak.filename().string() + ": " + ec.message());
        }
    }
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    if (!f) {
        return fail("cannot open " + name + " for writing");
    }
    f.write(text.data(), (std::streamsize)text.size());
    f.flush();
    if (!f) {
        return fail("writing " + name + " failed (the previous file is in " + name + ".bak)");
    }
    return true;
}

}
