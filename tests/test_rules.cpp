#include "hooks/patch_rules.h"
#include "hooks/rules_file.h"
#include "ui/rule_edit.h"
#include <atomic>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <thread>
#include <vector>

using namespace rfte;

static int g_fail = 0;
#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_fail;                                                   \
        }                                                               \
    } while (0)

static constexpr uint16_t A = kAnyByte;
using Pat = std::vector<uint16_t>;
using Bytes = std::vector<uint8_t>;

static PatchRule write_rule(Dir d, int m, int s, int off, Pat bytes) {
    PatchRule r;
    r.dir = d;
    r.main = m;
    r.sub = s;
    r.kind = PatchRule::Kind::Write;
    r.write_off = off;
    r.write_bytes = std::move(bytes);
    return r;
}

static PatchRule replace_rule(Dir d, int m, int s, Pat find, Pat repl) {
    PatchRule r;
    r.dir = d;
    r.main = m;
    r.sub = s;
    r.kind = PatchRule::Kind::Replace;
    r.find_bytes = std::move(find);
    r.repl_bytes = std::move(repl);
    return r;
}

static const Bytes kMove = {0x01, 0x00, 0x00, 0xC0, 0x3F, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x80,
                            0xC8, 0x42, 0xD2, 0x04, 0x00, 0x00, 0xFB, 0xFF, 0x07, 0x00, 0x03};

static std::vector<PatchRule> shapes() {
    std::vector<PatchRule> v;
    PatchRule w = write_rule(Dir::C2S, 4, 1, 13, {0x39, 0x30, A, A});
    w.name = "serial";
    w.match_off = 0;
    w.match_pat = {0x01};
    v.push_back(w);
    PatchRule r = replace_rule(Dir::S2C, -1, 10, {0xD2, 0x04, A}, {0x39, 0x30, A});
    r.match_pat = {0xD2, 0x04};
    r.enabled = false;
    v.push_back(r);
    PatchRule q = write_rule(Dir::S2C, 2, -1, 0x1A, {0x58});
    q.name = "quote \" backslash \\ newline \n tab \t utf8 \xC3\xA9";
    v.push_back(q);
    v.push_back(write_rule(Dir::C2S, 300, 0, 0, {0x00}));
    v.push_back(write_rule(Dir::C2S, 4, 1, 13, {}));
    v.push_back(replace_rule(Dir::C2S, 2, 2, {0x68, 0x65}, {0x48}));
    v.push_back(write_rule(Dir::C2S, 4, 1, 0x10000, {0x01}));
    PatchRule g = write_rule(Dir::C2S, 4, 1, 0, {0x01});
    g.match_off = 3;
    v.push_back(g);
    return v;
}

static void test_pattern() {
    Pat p;
    std::string err;
    CHECK(parse_pattern_hex("39 30 ?? ??", p) && (p == Pat{0x39, 0x30, A, A}));
    CHECK(parse_pattern_hex("3930????", p) && (p == Pat{0x39, 0x30, A, A}));
    CHECK(parse_pattern_hex("de,AD\n??", p) && (p == Pat{0xDE, 0xAD, A}));
    CHECK(parse_pattern_hex("", p) && p.empty());
    CHECK(!parse_pattern_hex("393", p, &err) && p.empty() && !err.empty());
    CHECK(!parse_pattern_hex("01 3G", p, &err) && p.empty() && err.find("3G") != std::string::npos);
    CHECK(!parse_pattern_hex("?1", p, &err));
    std::string s64;
    for (int i = 0; i < 64; ++i) {
        s64 += "AB ";
    }
    CHECK(parse_pattern_hex(s64, p) && p.size() == kMaxRuleBytes);
    CHECK(!parse_pattern_hex(s64 + "CD", p, &err) && err.find("64") != std::string::npos);
    CHECK(pattern_text({0x39, 0x30, A, 0x0F}) == "39 30 ?? 0F");
    CHECK(pattern_text({}).empty());
    std::printf("pattern: done\n");
}

static void test_check() {
    PatchRule w = write_rule(Dir::C2S, 4, 1, 13, {0x39, 0x30, 0x00, 0x00});
    CHECK(check_rule(w).empty());
    CHECK(describe_rule(w) == "C2S (4,1) write +000D = 39 30 00 00");
    w.match_off = 0;
    w.match_pat = {0x01};
    CHECK(check_rule(w).empty());
    CHECK(describe_rule(w) == "C2S (4,1) if +0000 = 01: write +000D = 39 30 00 00");
    w.name = "serial";
    CHECK(rule_title(0, w) == "#1 \"serial\": C2S (4,1) if +0000 = 01: write +000D = 39 30 00 00");
    PatchRule r = replace_rule(Dir::S2C, 2, -1, {0xD2, 0x04, A, A}, {0x39, 0x30, A, A});
    r.match_pat = {0xD2, 0x04};
    CHECK(check_rule(r).empty());
    CHECK(describe_rule(r) == "S2C (2,*) if anywhere D2 04: replace D2 04 ?? ?? -> 39 30 ?? ??");
    CHECK(rule_title(2, r) == "#3: S2C (2,*) if anywhere D2 04: replace D2 04 ?? ?? -> 39 30 ?? ??");
    auto bad = [](const PatchRule& x) {
        return !check_rule(x).empty();
    };
    {
        PatchRule x = w;
        x.main = 256;
        CHECK(bad(x));
    }
    {
        PatchRule x = w;
        x.sub = -2;
        CHECK(bad(x));
    }
    {
        PatchRule x = w;
        x.write_bytes.clear();
        CHECK(bad(x));
    }
    {
        PatchRule x = w;
        x.write_bytes = {A, A};
        CHECK(bad(x));
    }
    {
        PatchRule x = w;
        x.write_bytes.assign(kMaxRuleBytes + 1, 0);
        CHECK(bad(x));
    }
    {
        PatchRule x = w;
        x.write_off = -1;
        CHECK(bad(x));
    }
    {
        PatchRule x = w;
        x.write_off = 0x10000;
        CHECK(bad(x));
    }
    {
        PatchRule x = w;
        x.match_pat.clear();
        x.match_off = 3;
        CHECK(bad(x));
    }
    {
        PatchRule x = w;
        x.write_bytes = {0x1FF};
        CHECK(bad(x));
    }
    {
        PatchRule x = r;
        x.repl_bytes.pop_back();
        CHECK(bad(x));
    }
    {
        PatchRule x = r;
        x.find_bytes = {A, A, A, A};
        CHECK(bad(x));
    }
    {
        PatchRule x = r;
        x.repl_bytes = {A, A, A, A};
        CHECK(bad(x));
    }
    {
        PatchRule x = r;
        x.find_bytes.clear();
        x.repl_bytes.clear();
        CHECK(bad(x));
    }
    {
        PatchRule x = w;
        x.error = "unknown key \"hexReplce\"";
        CHECK(check_rule(x) == x.error);
    }
    std::printf("check: done\n");
}

static void test_apply() {
    RuleSet rs;
    uint8_t before[64];
    Bytes p = kMove;
    CHECK(!rs.live() && rs.apply(Dir::C2S, 4, 1, p.data(), p.size(), before, sizeof before).changed == 0);
    PatchRule w = write_rule(Dir::C2S, 4, 1, 13, {0x39, 0x30, A, A});
    w.match_off = 0;
    w.match_pat = {0x01};
    CHECK(rs.set({w}) == 1);
    CHECK(!rs.live() && !rs.armed());
    CHECK(rs.apply(Dir::C2S, 4, 1, p.data(), p.size(), before, sizeof before).changed == 0 && p == kMove);
    rs.arm(true);
    CHECK(rs.live() && rs.armed());
    std::memset(before, 0xEE, sizeof before);
    Applied a = rs.apply(Dir::C2S, 4, 1, p.data(), p.size(), before, sizeof before);
    CHECK(a.changed == 2 && a.rules == 1);
    Bytes want = kMove;
    want[13] = 0x39;
    want[14] = 0x30;
    CHECK(p == want);
    CHECK(std::memcmp(before, kMove.data(), kMove.size()) == 0);
    CHECK(before[22] == 0xEE);
    std::memset(before, 0xEE, sizeof before);
    a = rs.apply(Dir::C2S, 4, 1, p.data(), p.size(), before, sizeof before);
    CHECK(a.changed == 0 && a.rules == 1 && before[0] == 0xEE && p == want);
    p = kMove;
    p[0] = 0x02;
    CHECK(rs.apply(Dir::C2S, 4, 1, p.data(), p.size(), before, sizeof before).rules == 0 && p[13] == 0xD2);
    p = kMove;
    CHECK(rs.apply(Dir::S2C, 4, 1, p.data(), p.size(), before, sizeof before).rules == 0);
    CHECK(rs.apply(Dir::C2S, 4, 2, p.data(), p.size(), before, sizeof before).rules == 0);
    CHECK(rs.apply(Dir::C2S, 4, 1, p.data(), 15, before, sizeof before).rules == 0 && p == kMove);
    RuleStats st = rs.stats();
    CHECK(st.armed && st.active == 1 && st.hits[0] == 2 && st.edited[0] == 1 && st.edited[1] == 0);
    {
        PatchRule r = replace_rule(Dir::S2C, -1, -1, {0x68, 0x65, 0x6C, 0x6C, 0x6F}, {0x48, 0x45, 0x4C, 0x4C, 0x4F});
        PatchRule q = replace_rule(Dir::S2C, 2, 10, {0xAA, A}, {0xBB, A});
        PatchRule off = r;
        off.enabled = false;
        PatchRule inv = r;
        inv.repl_bytes.pop_back();
        CHECK(rs.set({inv, off, r, q}) == 2);
        CHECK(rs.live() && rs.stats().hits[0] == 0 && rs.stats().edited[0] == 0);
        const std::string msg = "hello, hellohello";
        Bytes b(msg.begin(), msg.end());
        a = rs.apply(Dir::S2C, 2, 10, b.data(), b.size(), before, sizeof before);
        CHECK(std::string(b.begin(), b.end()) == "HELLO, HELLOHELLO");
        CHECK(a.changed == 15 && a.rules == 1);
        Bytes c = {0xAA, 0xAA, 0xAA, 0x01, 0xAA};
        a = rs.apply(Dir::S2C, 2, 10, c.data(), c.size(), before, sizeof before);
        CHECK((c == Bytes{0xBB, 0xAA, 0xBB, 0x01, 0xAA}) && a.rules == 1 && a.changed == 2);
        st = rs.stats();
        CHECK(st.active == 2 && st.hits[0] == 0 && st.hits[1] == 0 && st.hits[2] == 1 && st.hits[3] == 1);
        CHECK(st.edited[1] == 2 && st.edited[0] == 0);
    }
    {
        CHECK(rs.set({write_rule(Dir::C2S, -1, -1, 0, {0x11}),
                      replace_rule(Dir::C2S, -1, -1, {0x11, 0x22}, {0x33, 0x44})}) == 2);
        Bytes b = {0x00, 0x22, 0x00};
        a = rs.apply(Dir::C2S, 9, 9, b.data(), b.size(), before, sizeof before);
        CHECK((b == Bytes{0x33, 0x44, 0x00}) && a.rules == 2 && a.changed == 3);
        CHECK(before[0] == 0x00 && before[1] == 0x22 && before[2] == 0x00);
    }
    {
        CHECK(rs.set({write_rule(Dir::C2S, -1, -1, 9, {0x01})}) == 1);
        Bytes b(10, 0);
        uint8_t small[4];
        std::memset(small, 0xEE, sizeof small);
        a = rs.apply(Dir::C2S, 1, 1, b.data(), b.size(), small, sizeof small);
        CHECK(a.changed == 1 && b[9] == 0x01 && small[0] == 0x00 && small[3] == 0x00);
    }
    {
        const std::vector<PatchRule> many(kMaxRules + 5, write_rule(Dir::C2S, -1, -1, 0, {0x01}));
        CHECK(rs.set(many) == kMaxRules);
    }
    rs.arm(false);
    CHECK(!rs.live() && !rs.armed());
    p = kMove;
    CHECK(rs.apply(Dir::C2S, 4, 1, p.data(), p.size(), before, sizeof before).changed == 0 && p == kMove);
    rs.arm(true);
    CHECK(rs.set({}) == 0 && !rs.live() && rs.armed());
    std::printf("apply: done\n");
}

static void test_threads() {
    RuleSet rs;
    const PatchRule r1 = write_rule(Dir::C2S, -1, -1, 0, {0x11, 0x11, 0x11, 0x11});
    const PatchRule r2 = write_rule(Dir::C2S, -1, -1, 0, {0x22, 0x22, 0x22, 0x22});
    rs.set({r1});
    rs.arm(true);
    std::atomic<bool> stop{false};
    bool torn = false;
    std::thread t([&] {
        uint8_t b[8], before[8];
        while (!stop.load()) {
            std::memset(b, 0, sizeof b);
            rs.apply(Dir::C2S, 1, 1, b, sizeof b, before, sizeof before);
            if (!(b[0] == b[1] && b[1] == b[2] && b[2] == b[3])) {
                torn = true;
            }
        }
    });
    for (int i = 0; i < 2000; ++i) {
        rs.set({i % 2 ? r1 : r2});
        rs.arm(i % 3 != 0);
    }
    stop.store(true);
    t.join();
    CHECK(!torn);
    std::printf("threads: done\n");
}

static void test_file(const char* example) {
    {
        const RulesLoad L = load_rules_file(example);
        CHECK(L.found && L.error.empty() && L.rules.size() == 2);
        if (L.rules.size() == 2) {
            CHECK(L.rules[0].enabled && check_rule(L.rules[0]).empty());
            CHECK(describe_rule(L.rules[0]) == "C2S (2,*) replace 68 65 6C 6C 6F -> 48 45 4C 4C 4F");
            CHECK(!L.rules[1].enabled && check_rule(L.rules[1]).empty());
            CHECK(describe_rule(L.rules[1]) == "S2C (2,10) if +0000 = 01: write +001A = 58");
        }
        const std::vector<std::string> lines = describe_load(L);
        CHECK(lines.size() == 3);
        if (lines.size() == 3) {
            CHECK(lines[0] ==
                  "#1 \"local chat: hello -> HELLO\": C2S (2,*) replace 68 65 6C 6C 6F -> 48 45 4C 4C 4F -- ok");
            CHECK(lines[1] ==
                  "#2 \"received chat: first letter -> X\": S2C (2,10) if +0000 = 01: write +001A = 58 -- disabled");
            CHECK(lines[2] == "2 rule(s) in RFTrafficEditor.rules.json, 1 active (enabled and valid)");
        }
    }
    {
        const RulesLoad L = load_rules_file("Z:/no/such/dir/RFTrafficEditor.rules.json");
        CHECK(!L.found && L.error.empty() && L.rules.empty());
        const std::vector<std::string> lines = describe_load(L);
        CHECK(lines.size() == 1 && lines[0].rfind("no RFTrafficEditor.rules.json next to the DLL", 0) == 0);
        CHECK(!load_rules_file(std::filesystem::path()).found);
    }
    CHECK(!parse_rules_json("{ nope").error.empty());
    CHECK(!parse_rules_json("[]").error.empty());
    CHECK(!parse_rules_json("{\"rules\": 5}").error.empty());
    CHECK(parse_rules_json("{\"rules\": []}").error.empty() && parse_rules_json("{\"rules\": []}").rules.empty());
    CHECK(describe_load(parse_rules_json("[]")).size() == 1);
    {
        const RulesLoad L = parse_rules_json(R"({ "rules": [
            { "dir": "s2c", "main": "*", "sub": null,
              "action": { "offset": "0x1A", "hexReplace": "58 ??" } },
            { "dir": "C2S", "main": 4, "sub": 1, "enabled": false, // a comment
              "match": { "hexPattern": "D2 04" },
              "action": { "findHex": "D2 04", "replaceHex": "39 30" } },
            { "dir": "C2S", "action": { "offset": 13, "hexReplce": "00" } },
            { "dir": "C2X", "action": { "offset": 0, "hexReplace": "00" } },
            { "dir": "C2S", "action": { "offset": "+000D", "hexReplace": "3G" } },
            { "dir": "C2S", "action": { "offset": 0, "hexReplace": "00", "findHex": "00" } },
            { "dir": "C2S", "main": 300, "action": { "offset": "13", "hexReplace": "00" } },
            { "dir": "C2S" },
            7
        ] })");
        CHECK(L.error.empty() && L.rules.size() == 9);
        if (L.rules.size() == 9) {
            const PatchRule& a = L.rules[0];
            CHECK(a.error.empty() && a.enabled && a.dir == Dir::S2C && a.main == -1 && a.sub == -1);
            CHECK(a.kind == PatchRule::Kind::Write && a.write_off == 0x1A && (a.write_bytes == Pat{0x58, A}));
            CHECK(check_rule(a).empty());
            const PatchRule& b = L.rules[1];
            CHECK(b.error.empty() && !b.enabled && b.main == 4 && b.sub == 1 && b.match_off == -1);
            CHECK((b.match_pat == Pat{0xD2, 0x04}) && b.kind == PatchRule::Kind::Replace && check_rule(b).empty());
            CHECK(L.rules[2].error.find("hexReplce") != std::string::npos);
            CHECK(!L.rules[3].error.empty());
            CHECK(L.rules[4].error.find("3G") != std::string::npos);
            CHECK(!L.rules[5].error.empty());
            CHECK(L.rules[6].error.empty() && L.rules[6].write_off == 13 && !check_rule(L.rules[6]).empty());
            CHECK(!L.rules[7].error.empty());
            CHECK(!L.rules[8].error.empty());
        }
        const std::vector<std::string> lines = describe_load(L);
        CHECK(lines.size() == 10);
        if (lines.size() == 10) {
            CHECK(lines[0] == "#1: S2C (*,*) write +001A = 58 ?? -- ok");
            CHECK(lines[1].find(" -- disabled") != std::string::npos);
            CHECK(lines[2].rfind("#3: INVALID: ", 0) == 0 && lines[2].find("(not applied)") != std::string::npos);
            CHECK(lines[6].find(" -- INVALID: main") != std::string::npos);
            CHECK(lines[9] == "9 rule(s) in RFTrafficEditor.rules.json, 1 active (enabled and valid)");
        }
    }
    std::printf("file: done\n");
}

static void test_form() {
    for (const PatchRule& x : shapes()) {
        CHECK(rule_of(form_of(x)) == x);
    }
    {
        const RuleForm f = form_of(shapes()[0]);
        CHECK(std::string(f.name) == "serial" && f.enabled && f.dir == 0 && f.kind == 0);
        CHECK(std::string(f.main) == "4" && std::string(f.sub) == "1");
        CHECK(f.gate && std::string(f.match_off) == "+0000" && std::string(f.match_hex) == "01");
        CHECK(std::string(f.write_off) == "+000D" && std::string(f.write_hex) == "39 30 ?? ??");
        const RuleForm g = form_of(shapes()[1]);
        CHECK(!g.enabled && g.dir == 1 && g.kind == 1 && std::string(g.main).empty() && std::string(g.sub) == "10");
        CHECK(g.gate && std::string(g.match_off).empty() && std::string(g.find_hex) == "D2 04 ??");
        CHECK(std::string(g.write_off) == "+0000");
    }
    {
        RuleForm g;
        PatchRule r = rule_of(g);
        CHECK(r.main == -1 && r.sub == -1 && r.error.rfind("write: offset", 0) == 0 && check_rule(r) == r.error);
        std::snprintf(g.main, sizeof g.main, " 0x04 ");
        std::snprintf(g.sub, sizeof g.sub, "*");
        std::snprintf(g.write_off, sizeof g.write_off, "0x0d");
        std::snprintf(g.write_hex, sizeof g.write_hex, "39,30");
        r = rule_of(g);
        CHECK(r.error.empty() && r.main == 4 && r.sub == -1 && r.write_off == 13 && (r.write_bytes == Pat{0x39, 0x30}));
        CHECK(check_rule(r).empty());
        std::snprintf(g.main, sizeof g.main, "-1");
        CHECK(rule_of(g).error.rfind("main:", 0) == 0);
        std::snprintf(g.main, sizeof g.main, "abc");
        CHECK(rule_of(g).error.rfind("main:", 0) == 0);
        std::snprintf(g.main, sizeof g.main, "300");
        r = rule_of(g);
        CHECK(r.error.empty() && r.main == 300 && !check_rule(r).empty());
        std::snprintf(g.main, sizeof g.main, "4");
        g.gate = true;
        std::snprintf(g.match_hex, sizeof g.match_hex, "3G");
        CHECK(rule_of(g).error.find("3G") != std::string::npos && rule_of(g).error.rfind("match: ", 0) == 0);
        std::snprintf(g.match_hex, sizeof g.match_hex, "01");
        r = rule_of(g);
        CHECK(r.error.empty() && r.match_off == -1 && (r.match_pat == Pat{0x01}));
        std::snprintf(g.match_off, sizeof g.match_off, "+zz");
        CHECK(rule_of(g).error.rfind("match: offset", 0) == 0);
        g.gate = false;
        r = rule_of(g);
        CHECK(r.error.empty() && r.match_off == -1 && r.match_pat.empty());
        g.kind = 1;
        std::snprintf(g.write_off, sizeof g.write_off, "bad");
        std::snprintf(g.find_hex, sizeof g.find_hex, "39 30");
        std::snprintf(g.repl_hex, sizeof g.repl_hex, "31 32");
        r = rule_of(g);
        CHECK(r.error.empty() && r.kind == PatchRule::Kind::Replace && r.write_off == 0 && r.write_bytes.empty());
        CHECK((r.find_bytes == Pat{0x39, 0x30}) && (r.repl_bytes == Pat{0x31, 0x32}) && check_rule(r).empty());
        std::snprintf(g.repl_hex, sizeof g.repl_hex, "31");
        r = rule_of(g);
        CHECK(r.error.empty() && !check_rule(r).empty());
        std::snprintf(g.find_hex, sizeof g.find_hex, "3");
        CHECK(rule_of(g).error.rfind("find: ", 0) == 0);
        PatchRule e = shapes()[0];
        e.error = "action: unknown key \"hexReplce\"";
        CHECK(rule_of(form_of(e)).error.empty());
    }
    {
        int v = 0;
        CHECK(parse_offset_text("13", &v) && v == 13);
        CHECK(parse_offset_text("0x0D", &v) && v == 13);
        CHECK(parse_offset_text("+000D", &v) && v == 13);
        CHECK(parse_offset_text(" +1A\t", &v) && v == 26);
        v = 7;
        CHECK(!parse_offset_text("", &v) && !parse_offset_text("+", &v) && !parse_offset_text("0x", &v) && v == 7);
        CHECK(!parse_offset_text("-1", &v) && !parse_offset_text("1 2", &v) && !parse_offset_text("+1000000", &v));
        CHECK(parse_part_text("", &v) && v == -1);
        CHECK(parse_part_text(" * ", &v) && v == -1);
        CHECK(parse_part_text(" 7 ", &v) && v == 7);
        CHECK(parse_part_text("0xFF", &v) && v == 255);
        CHECK(parse_part_text("300", &v) && v == 300);
        CHECK(!parse_part_text("-1", &v) && !parse_part_text("4,1", &v) && !parse_part_text("x", &v));
    }
    {
        uint8_t b[70];
        for (int i = 0; i < 70; ++i) {
            b[i] = (uint8_t)i;
        }
        PatchRule r = rule_from_bytes(Dir::S2C, 3, 4, 0x47, b, 70, "EquipList[0]");
        CHECK(r.name == "EquipList[0]" && r.enabled && r.dir == Dir::S2C && r.main == 3 && r.sub == 4);
        CHECK(r.kind == PatchRule::Kind::Write && r.write_off == 0x47 && r.write_bytes.size() == kMaxRuleBytes);
        CHECK(r.write_bytes[0] == 0 && r.write_bytes[63] == 63 && r.match_pat.empty() && check_rule(r).empty());
        CHECK(describe_rule(rule_from_bytes(Dir::C2S, 4, 1, 13, kMove.data() + 13, 4, "x")) ==
              "C2S (4,1) write +000D = D2 04 00 00");
        CHECK(rule_from_bytes(Dir::C2S, 4, 1, 0, nullptr, 0, "").write_bytes.empty());
    }
    {
        CHECK(active_rules(shapes()) == 2);
        CHECK(active_rules(std::vector<PatchRule>(kMaxRules + 6, write_rule(Dir::C2S, -1, -1, 0, {0x01}))) ==
              kMaxRules);
        CHECK(active_rules({}) == 0);
    }
    std::printf("form: done\n");
}

static void test_save(const char* example) {
    const RulesLoad ex = load_rules_file(example);
    CHECK(ex.error.empty() && ex.rules.size() == 2);
    {
        const std::string want =
            "// pktnik -- patch rules, saved by the Rules editor (format: README, section \"Patch "
            "rules\").\n"
            "// Loaded DISARMED: tick Rules in the tool window to apply them (it asks first).\n"
            "{\n"
            "  \"rules\": [\n"
            "    {\n"
            "      \"name\": \"local chat: hello -> HELLO\",\n"
            "      \"enabled\": true,\n"
            "      \"dir\": \"C2S\", \"main\": 2,\n"
            "      \"action\": { \"findHex\": \"68 65 6C 6C 6F\", \"replaceHex\": \"48 45 4C 4C 4F\" }\n"
            "    },\n"
            "    {\n"
            "      \"name\": \"received chat: first letter -> X\",\n"
            "      \"enabled\": false,\n"
            "      \"dir\": \"S2C\", \"main\": 2, \"sub\": 10,\n"
            "      \"match\": { \"offset\": \"+0000\", \"hexPattern\": \"01\" },\n"
            "      \"action\": { \"offset\": \"+001A\", \"hexReplace\": \"58\" }\n"
            "    }\n"
            "  ]\n"
            "}\n";
        const std::string got = rules_json(ex.rules);
        CHECK(got == want);
        if (got != want) {
            std::printf("got:\n%s", got.c_str());
        }
    }
    {
        std::vector<PatchRule> v = shapes();
        v.push_back(write_rule(Dir::C2S, -5, 1, -3, {0x01}));
        const RulesLoad back = parse_rules_json(rules_json(v));
        CHECK(back.error.empty() && back.rules == v);
        CHECK(parse_rules_json(rules_json(ex.rules)).rules == ex.rules);
        const RulesLoad none = parse_rules_json(rules_json({}));
        CHECK(none.error.empty() && none.rules.empty());
        const std::string e = rules_json({}), tail = "{\n  \"rules\": []\n}\n";
        CHECK(e.size() > tail.size() && e.compare(e.size() - tail.size(), tail.size(), tail) == 0);
    }
    {
        size_t active = 99;
        const std::vector<std::string> d = describe_rules(ex.rules, &active);
        const std::vector<std::string> l = describe_load(ex);
        CHECK(d.size() == 2 && l.size() == 3 && d[0] == l[0] && d[1] == l[1] && active == 1);
        CHECK(ex.rules[0] == ex.rules[0] && !(ex.rules[0] == ex.rules[1]));
        PatchRule x = ex.rules[0];
        x.enabled = false;
        CHECK(x != ex.rules[0]);
    }
    {
        std::error_code ec;
        const std::filesystem::path dir = std::filesystem::temp_directory_path(ec) / "rfte_test_rules";
        std::filesystem::remove_all(dir, ec);
        std::filesystem::create_directories(dir, ec);
        const std::filesystem::path p = dir / "RFTrafficEditor.rules.json";
        std::filesystem::path bak = p;
        bak += L".bak";
        std::string err;
        CHECK(save_rules_file(p, ex.rules, &err) && err.empty());
        CHECK(!std::filesystem::exists(bak, ec));
        CHECK(load_rules_file(p).rules == ex.rules);
        {
            std::ifstream f(p, std::ios::binary);
            const std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            CHECK(text == rules_json(ex.rules));
        }
        const std::vector<PatchRule> one = {shapes()[0]};
        CHECK(save_rules_file(p, one, &err));
        CHECK(load_rules_file(p).rules == one);
        CHECK(std::filesystem::exists(bak, ec) && load_rules_file(bak).rules == ex.rules);
        std::vector<PatchRule> unparsed = one;
        unparsed[0].error = "action: unknown key \"hexReplce\"";
        err.clear();
        CHECK(!save_rules_file(p, unparsed, &err) && err.find("#1") != std::string::npos);
        CHECK(load_rules_file(p).rules == one);
        err.clear();
        CHECK(!save_rules_file(dir / "no_such_dir" / "x.json", one, &err) && !err.empty());
        CHECK(!save_rules_file(std::filesystem::path(), one, &err));
        std::filesystem::remove_all(dir, ec);
    }
    std::printf("save: done\n");
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::printf("usage: test_rules <RFTrafficEditor.rules.example.json>\nFAILED (1 failure(s))\n");
        return 1;
    }
    test_pattern();
    test_check();
    test_apply();
    test_threads();
    test_file(argv[1]);
    test_form();
    test_save(argv[1]);
    if (g_fail) {
        std::printf("FAILED (%d failure(s))\n", g_fail);
    } else {
        std::printf("PASSED (0 failure(s))\n");
    }
    return g_fail ? 1 : 0;
}
