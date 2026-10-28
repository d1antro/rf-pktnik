#include "proto/packet_db.h"
#include "proto/packet_text.h"
#include "ui/field_edit.h"
#include "ui/filter.h"
#include "ui/packet_model.h"
#include "ui/packet_view.h"
#include <cstdio>
#include <cstring>
#include <string>
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
#define CHECK_STR(got, want)                                                                                           \
    do {                                                                                                               \
        const std::string g_ = (got), w_ = (want);                                                                     \
        if (g_ != w_) {                                                                                                \
            std::printf("FAIL %s:%d: %s\n  want: %s\n  got:  %s\n", __FILE__, __LINE__, #got, w_.c_str(), g_.c_str()); \
            ++g_fail;                                                                                                  \
        }                                                                                                              \
    } while (0)

template <class T> static void put(std::vector<uint8_t>& b, T v) {
    const size_t at = b.size();
    b.resize(at + sizeof v);
    std::memcpy(b.data() + at, &v, sizeof v);
}

static PacketRec rec(uint64_t seq, uint64_t ts, Dir d, uint8_t m, uint8_t s, uint16_t len) {
    PacketRec r{};
    r.seq = seq;
    r.ts_qpc = ts;
    r.dir = d;
    r.main = m;
    r.sub = s;
    r.size = len;
    r.edited = false;
    r.bytes.assign(len, 0);
    return r;
}

static void check_row(const Row& r, Status st, const char* name, const char* label, const Struct* layout) {
    if (r.status != st) {
        std::printf("FAIL: row #%llu status %s\n", (unsigned long long)r.rec.seq, status_name(r.status));
        ++g_fail;
    }
    CHECK_STR(r.name, name);
    CHECK_STR(r.label, label);
    if (r.layout != layout) {
        std::printf("FAIL: row #%llu layout %p, want %p\n", (unsigned long long)r.rec.seq, (const void*)r.layout,
                    (const void*)layout);
        ++g_fail;
    }
}

static void test_rows(const PacketDb& fx) {
    PacketModel m(&fx, 1000, 10.0);
    m.push(rec(0, 1015, Dir::S2C, 9, 1, 8));
    m.push(rec(1, 1020, Dir::S2C, 9, 1, 30));
    m.push(rec(2, 1030, Dir::S2C, 9, 3, 4));
    m.push(rec(3, 1040, Dir::S2C, 9, 9, 4));
    m.push(rec(4, 1050, Dir::S2C, 9, 1, 5));
    m.push(rec(5, 1060, Dir::C2S, 9, 1, 5));
    CHECK(m.size() == 6);
    if (m.size() == 6) {
        check_row(m.at(0), Status::Ok, "_fix_a_zocl", "_fix_a_zocl ok", fx.get("_fix_a_zocl"));
        check_row(m.at(1), Status::Mismatch, "_fix_a_zocl | _fix_b_zocl | _fix_var_zocl",
                  "MISMATCH(30 fits none of: _fix_a_zocl 8, _fix_b_zocl 2, _fix_var_zocl 20)", nullptr);
        check_row(m.at(2), Status::Unknown, "_fix_missing_zocl", "_fix_missing_zocl unknown(no layout)", nullptr);
        check_row(m.at(3), Status::Unknown, "", "unknown", nullptr);
        check_row(m.at(4), Status::Var, "_fix_var_zocl", "_fix_var_zocl var(5/20)", fx.get("_fix_var_zocl"));
        check_row(m.at(5), Status::Ok, "_fix_req_clzo", "_fix_req_clzo ok", fx.get("_fix_req_clzo"));
        CHECK(m.at(0).t_ms == 1.5);
        for (size_t i = 0; i < 6; ++i) {
            CHECK(m.at(i).rec.seq == i);
        }
    }
    CHECK(m.count(Dir::C2S) == 1);
    CHECK(m.count(Dir::S2C) == 5);
    CHECK(m.count(Status::Ok) == 2);
    CHECK(m.count(Status::Mismatch) == 1);
    CHECK(m.count(Status::Unknown) == 2);
    CHECK(m.count(Status::Var) == 1);
    CHECK(m.ingested() == 6);
    CHECK(m.evicted() == 0);
    CHECK(m.payload_bytes() == 8 + 30 + 4 + 4 + 5 + 5);

    PacketModel raw(nullptr, 0, 1.0);
    PacketRec r = rec(0, 0, Dir::S2C, 4, 4, 2);
    r.bytes = {0x01, 0x02};
    raw.push(std::move(r));
    CHECK(raw.size() == 1);
    if (raw.size() == 1) {
        check_row(raw.at(0), Status::Unknown, "", "", nullptr);
    }
    std::printf("model: done\n");
}

static PacketRec move_rec() {
    PacketRec r{};
    r.seq = 7;
    r.ts_qpc = 1015;
    r.dir = Dir::C2S;
    r.main = 4;
    r.sub = 1;
    r.size = 22;
    r.edited = false;
    put(r.bytes, (uint8_t)1);
    put(r.bytes, 1.5f);
    put(r.bytes, -2.0f);
    put(r.bytes, 100.25f);
    put(r.bytes, (uint32_t)1234);
    put(r.bytes, (int16_t)-5);
    put(r.bytes, (int16_t)7);
    put(r.bytes, (uint8_t)3);
    return r;
}

static void test_log(const PacketDb& db) {
    {
        PacketModel m(&db, 1000, 10.0);
        PacketRec r = move_rec();
        CHECK(r.bytes.size() == 22);
        std::string log;
        m.push(std::move(r), &log);
        CHECK_STR(log, "#7 t+1.500ms C2S (4,1) size=22 _move_request_clzo ok\n"
                       "      +0000 uint8_t byMoveType = 1\n"
                       "      +0001 float fCur[3] = [1.5, -2, 100.25]\n"
                       "      +000D uint32_t dwSerial = 1234 (0x4D2)\n"
                       "      +0011 int16_t zTar[2] = [-5, 7]\n"
                       "      +0015 uint8_t byDirect = 3\n"
                       "    0000  01 00 00 C0 3F 00 00 00 C0 00 80 C8 42 D2 04 00\n"
                       "    0010  00 FB FF 07 00 03\n");
    }
    {
        PacketModel m(nullptr, 0, 1.0);
        PacketRec r = rec(0, 0, Dir::S2C, 4, 4, 2);
        r.bytes = {0x01, 0x02};
        std::string log;
        m.push(std::move(r), &log);
        CHECK_STR(log, "#0 t+0.000ms S2C (4,4) size=2\n    0000  01 02\n");
        m.push(rec(1, 0, Dir::S2C, 4, 4, 2), nullptr);
        CHECK_STR(log, "#0 t+0.000ms S2C (4,4) size=2\n    0000  01 02\n");
        CHECK(m.size() == 2);
    }
    std::printf("log: done\n");
}

static void test_cap() {
    PacketModel a(nullptr, 0, 1.0, 4, 1 << 20);
    for (uint64_t i = 0; i < 6; ++i) {
        a.push(rec(i, 0, Dir::C2S, 1, 1, 1));
    }
    CHECK(a.size() == 4);
    if (a.size() == 4) {
        CHECK(a.at(0).rec.seq == 2);
        CHECK(a.at(3).rec.seq == 5);
    }
    CHECK(a.evicted() == 2);
    CHECK(a.ingested() == 6);
    CHECK(a.count(Dir::C2S) == 4);
    CHECK(a.payload_bytes() == 4);

    PacketModel b(nullptr, 0, 1.0, 100, 100);
    for (uint64_t i = 0; i < 3; ++i) {
        b.push(rec(i, 0, Dir::S2C, 1, 1, 40));
    }
    CHECK(b.size() == 2);
    CHECK(b.payload_bytes() == 80);
    CHECK(b.evicted() == 1);
    b.push(rec(3, 0, Dir::S2C, 1, 1, 500));
    CHECK(b.size() == 1);
    CHECK(b.payload_bytes() == 500);
    CHECK(b.evicted() == 3);

    b.add_dropped(5);
    b.add_dropped(2);
    CHECK(b.ring_dropped() == 7);
    b.clear();
    CHECK(b.size() == 0);
    CHECK(b.count(Dir::C2S) == 0 && b.count(Dir::S2C) == 0);
    CHECK(b.count(Status::Ok) == 0 && b.count(Status::Unknown) == 0 && b.count(Status::Mismatch) == 0 &&
          b.count(Status::Var) == 0);
    CHECK(b.payload_bytes() == 0);
    CHECK(b.ingested() == 4);
    CHECK(b.evicted() == 3);
    CHECK(b.ring_dropped() == 7);
    std::printf("cap: done\n");
}

static void check_view(const PacketView& v, const Row& r, size_t layouts, int pick, bool trial, size_t spans,
                       const std::vector<int>& owner) {
    if (v.seq != r.rec.seq || v.layouts.size() != layouts || v.pick != pick || v.trial != trial ||
        v.spans.size() != spans || v.owner != owner) {
        std::printf("FAIL: view of #%llu: seq %llu layouts %zu pick %d trial %d spans %zu owner size %zu\n",
                    (unsigned long long)r.rec.seq, (unsigned long long)v.seq, v.layouts.size(), v.pick, (int)v.trial,
                    v.spans.size(), v.owner.size());
        ++g_fail;
    }
}

static void test_view(const PacketDb& fx, const PacketDb& db) {
    PacketModel m(&fx, 1000, 10.0);
    m.push(rec(0, 1015, Dir::S2C, 9, 1, 8));
    m.push(rec(1, 1020, Dir::S2C, 9, 1, 30));
    m.push(rec(2, 1030, Dir::S2C, 9, 3, 4));
    m.push(rec(3, 1050, Dir::S2C, 9, 1, 5));
    m.push(rec(4, 1060, Dir::C2S, 9, 1, 5));
    {
        PacketRec r = rec(5, 1070, Dir::S2C, 9, 2, 14);
        r.bytes = {0x00, 0xAA, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xBB, 0xCC, 0xDD, 0xEE};
        m.push(std::move(r));
    }
    CHECK(m.size() == 6);
    if (m.size() != 6) {
        return;
    }
    CHECK(m.find(3) && m.find(3)->rec.seq == 3);
    CHECK(m.find(0) == &m.at(0));
    CHECK(m.find(6) == nullptr);

    PacketView v;
    using K = FieldSpan::Kind;
    build_view(v, m.at(0), &fx);
    check_view(v, m.at(0), 3, 0, false, 3, {0, 0, 0, 0, 1, 1, 2, 2});
    build_view(v, m.at(1), &fx);
    {
        std::vector<int> own(30, 0);
        for (int i = 4; i < 6; ++i) {
            own[i] = 1;
        }
        for (int i = 6; i < 8; ++i) {
            own[i] = 2;
        }
        for (int i = 8; i < 30; ++i) {
            own[i] = 3;
        }
        check_view(v, m.at(1), 3, 0, true, 4, own);
        if (v.spans.size() == 4) {
            CHECK(v.spans[3].kind == K::Extra && v.spans[3].offset == 8 && v.spans[3].size == 22);
        }
        CHECK(v.owner.size() == 30 && v.owner[8] == 3 && v.owner[29] == 3);
    }
    build_view(v, m.at(2), &fx);
    check_view(v, m.at(2), 0, -1, false, 0, {-1, -1, -1, -1});
    build_view(v, m.at(3), &fx);
    check_view(v, m.at(3), 3, 2, false, 2, {0, 1, 1, 1, 1});
    build_view(v, m.at(4), &fx);
    check_view(v, m.at(4), 1, 0, false, 2, {0, 1, 1, 1, 1});
    build_view(v, m.at(5), &fx);
    check_view(v, m.at(5), 1, 0, false, 5, {0, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 4, 4});

    build_view(v, m.at(1), &fx, 2);
    CHECK(v.pick == 2 && v.trial && v.spans.size() == 3);
    if (v.spans.size() == 3) {
        CHECK(v.spans[2].kind == K::Extra && v.spans[2].offset == 20 && v.spans[2].size == 10);
    }
    CHECK(v.owner.size() == 30 && v.owner[0] == 0 && v.owner[19] == 1 && v.owner[20] == 2);
    build_view(v, m.at(1), &fx, 7);
    CHECK(v.pick == 0);
    build_view(v, m.at(0), nullptr);
    check_view(v, m.at(0), 0, -1, false, 0, std::vector<int>(8, -1));

    build_view(v, m.at(1), &fx);
    {
        const std::string t = copy_text(v, m.at(1), CopyKind::Decoded);
        const std::string head =
            "#1 t+2.000ms S2C (9,1) size=30 MISMATCH(30 fits none of: _fix_a_zocl 8, _fix_b_zocl 2, "
            "_fix_var_zocl 20) [decoded as _fix_a_zocl]\n      +0000 uint32_t dwA = 0\n";
        CHECK_STR(t.substr(0, head.size()), head);
        CHECK(t.find("      +0008 (beyond sizeof) = <22 B: 00 00 ") != std::string::npos);
    }
    build_view(v, m.at(2), &fx);
    CHECK_STR(copy_text(v, m.at(2), CopyKind::Decoded),
              "#2 t+3.000ms S2C (9,3) size=4 _fix_missing_zocl unknown(no layout)\n    0000  00 00 00 00\n");

    {
        PacketModel md(&db, 1000, 10.0);
        std::string log;
        md.push(move_rec(), &log);
        CHECK(md.size() == 1);
        if (md.size() == 1) {
            const Row& r = md.at(0);
            build_view(v, r, &db);
            CHECK(v.layouts.size() == 1 && v.pick == 0 && !v.trial && v.spans.size() == 5);
            CHECK_STR(copy_text(v, r, CopyKind::Decoded), log);
            CHECK_STR(copy_text(v, r, CopyKind::Hex),
                      "01 00 00 C0 3F 00 00 00 C0 00 80 C8 42 D2 04 00 00 FB FF 07 00 03");
            CHECK_STR(copy_text(v, r, CopyKind::Snippet), format_snippet(r.rec, r.label, r.layout));
        }
    }

    PacketModel a(nullptr, 0, 1.0, 2, 1 << 20);
    for (uint64_t i = 0; i < 4; ++i) {
        a.push(rec(i, 0, Dir::C2S, 1, 1, 1));
    }
    CHECK(a.find(1) == nullptr);
    CHECK(a.find(2) && a.find(2)->rec.seq == 2);
    CHECK(a.find(3) != nullptr);
    a.clear();
    CHECK(a.find(3) == nullptr);
    std::printf("view: done\n");
}

static void check_seqs(const PacketModel& m, const Filter& f, const std::vector<uint64_t>& want, int line) {
    FilterView fv;
    fv.reset(f);
    const size_t left = fv.update(m);
    std::vector<uint64_t> got;
    for (size_t i = 0; i < fv.size(); ++i) {
        got.push_back(fv.seq(i));
    }
    if (left != 0 || got != want) {
        std::printf("FAIL %s:%d: filter shows", __FILE__, line);
        for (uint64_t s : got) {
            std::printf(" %llu", (unsigned long long)s);
        }
        std::printf(" (left %zu), want", left);
        for (uint64_t s : want) {
            std::printf(" %llu", (unsigned long long)s);
        }
        std::printf("\n");
        ++g_fail;
    }
}

static void test_filter(const PacketDb& fx) {
    const struct {
        const char* s;
        bool ok;
        int mn, sb;
    } kOp[] = {{"", true, -1, -1},          {"   ", true, -1, -1}, {"4", true, 4, -1},         {"4,1", true, 4, 1},
               {" ( 4 , 1 ) ", true, 4, 1}, {"4 1", true, 4, 1},   {"0x1F,0x02", true, 31, 2}, {"255,0", true, 255, 0},
               {"256", false, 7, 7},        {"4,", false, 7, 7},   {",1", false, 7, 7},        {"a", false, 7, 7},
               {"4,1,2", false, 7, 7},      {"(4,1", false, 7, 7}, {"4)", false, 7, 7},        {"-1", false, 7, 7},
               {"0x", false, 7, 7},         {"4,,1", false, 7, 7}};

    for (const auto& c : kOp) {
        int mn = 7, sb = 7;
        const bool ok = parse_opcode(c.s, mn, sb);
        if (ok != c.ok || mn != c.mn || sb != c.sb) {
            std::printf("FAIL: parse_opcode(\"%s\") = %d (%d,%d), want %d (%d,%d)\n", c.s, (int)ok, mn, sb, (int)c.ok,
                        c.mn, c.sb);
            ++g_fail;
        }
    }
    CHECK(icontains("_fix_A_zocl", "FIX_a"));
    CHECK(icontains("abc", ""));
    CHECK(!icontains("", "a"));
    CHECK(!icontains("ab", "abc"));
    CHECK(mute_key(Dir::S2C, 4, 1) == 0x10401u);
    CHECK(mute_key(Dir::C2S, 255, 2) == 0xFF02u);
    {
        Filter f;
        set_muted(f, mute_key(Dir::S2C, 9, 1), true);
        set_muted(f, mute_key(Dir::C2S, 9, 1), true);
        set_muted(f, mute_key(Dir::S2C, 9, 1), true);
        CHECK(f.muted.size() == 2 && f.muted[0] == mute_key(Dir::C2S, 9, 1));
        CHECK(is_muted(f, mute_key(Dir::S2C, 9, 1)) && !is_muted(f, mute_key(Dir::S2C, 9, 2)));
        set_muted(f, mute_key(Dir::C2S, 9, 1), false);
        CHECK(f.muted.size() == 1 && !is_muted(f, mute_key(Dir::C2S, 9, 1)));
        CHECK(f != Filter{});
    }
    PacketModel m(&fx, 1000, 10.0);
    m.push(rec(0, 1015, Dir::S2C, 9, 1, 8));
    m.push(rec(1, 1020, Dir::S2C, 9, 1, 30));
    m.push(rec(2, 1030, Dir::S2C, 9, 3, 4));
    m.push(rec(3, 1040, Dir::S2C, 9, 9, 4));
    m.push(rec(4, 1050, Dir::S2C, 9, 1, 5));
    m.push(rec(5, 1060, Dir::C2S, 9, 1, 5));
    {
        PacketRec r = rec(6, 1070, Dir::C2S, 9, 1, 5);
        r.edited = true;
        r.bytes = {0x01, 0x00, 0x00, 0x80, 0x3F};
        m.push(std::move(r));
    }
    CHECK(m.size() == 7);
    if (m.size() != 7) {
        return;
    }
    CHECK(m.lower_bound(0) == 0 && m.lower_bound(3) == 3 && m.lower_bound(7) == 7);
    CHECK_STR(search_text(m.at(6)), format_packet(m.at(6).rec, m.at(6).t_ms, m.at(6).label, m.at(6).layout));
    Filter f;
    check_seqs(m, f, {0, 1, 2, 3, 4, 5, 6}, __LINE__);
    f = Filter{};
    f.dir = {true, false};
    check_seqs(m, f, {5, 6}, __LINE__);
    f = Filter{};
    f.dir = {false, true};
    check_seqs(m, f, {0, 1, 2, 3, 4}, __LINE__);
    f = Filter{};
    f.status.fill(false);
    f.status[(size_t)Status::Unknown] = true;
    check_seqs(m, f, {2, 3}, __LINE__);
    f = Filter{};
    f.status.fill(false);
    f.status[(size_t)Status::Mismatch] = true;
    check_seqs(m, f, {1}, __LINE__);
    f = Filter{};
    f.status.fill(false);
    f.status[(size_t)Status::Var] = true;
    check_seqs(m, f, {4}, __LINE__);
    f = Filter{};
    f.status[(size_t)Status::Ok] = false;
    check_seqs(m, f, {1, 2, 3, 4}, __LINE__);
    f = Filter{};
    f.edited_only = true;
    check_seqs(m, f, {6}, __LINE__);
    f = Filter{};
    f.main = 9;
    f.sub = 1;
    check_seqs(m, f, {0, 1, 4, 5, 6}, __LINE__);
    f = Filter{};
    f.main = 9;
    check_seqs(m, f, {0, 1, 2, 3, 4, 5, 6}, __LINE__);
    f = Filter{};
    f.main = 9;
    f.sub = 3;
    check_seqs(m, f, {2}, __LINE__);
    f = Filter{};
    f.main = 4;
    check_seqs(m, f, {}, __LINE__);
    f = Filter{};
    f.size_min = 5;
    f.size_max = 8;
    check_seqs(m, f, {0, 4, 5, 6}, __LINE__);
    f = Filter{};
    f.size_min = 30;
    check_seqs(m, f, {1}, __LINE__);
    f = Filter{};
    f.size_max = 4;
    check_seqs(m, f, {2, 3}, __LINE__);
    f = Filter{};
    f.name = "FIX_A";
    check_seqs(m, f, {0, 1}, __LINE__);
    f = Filter{};
    f.name = "var";
    check_seqs(m, f, {1, 4}, __LINE__);
    f = Filter{};
    f.name = "clzo";
    check_seqs(m, f, {5, 6}, __LINE__);
    f = Filter{};
    f.text = "fx = 1";
    check_seqs(m, f, {6}, __LINE__);
    f = Filter{};
    f.text = "EDITED";
    check_seqs(m, f, {6}, __LINE__);
    f = Filter{};
    f.text = "00 00 80 3f";
    check_seqs(m, f, {6}, __LINE__);
    f = Filter{};
    f.text = "mismatch(30";
    check_seqs(m, f, {1}, __LINE__);
    f = Filter{};
    f.text = "unknown";
    check_seqs(m, f, {2, 3}, __LINE__);
    f = Filter{};
    set_muted(f, mute_key(Dir::S2C, 9, 1), true);
    check_seqs(m, f, {2, 3, 5, 6}, __LINE__);
    set_muted(f, mute_key(Dir::C2S, 9, 1), true);
    check_seqs(m, f, {2, 3}, __LINE__);
    set_muted(f, mute_key(Dir::S2C, 9, 1), false);
    check_seqs(m, f, {0, 1, 2, 3, 4}, __LINE__);
    f = Filter{};
    f.dir = {false, true};
    f.name = "fix";
    f.size_max = 8;
    check_seqs(m, f, {0, 2, 4}, __LINE__);

    FilterView fv;
    fv.reset(Filter{});
    CHECK(fv.update(m, 3) == 4 && fv.size() == 3);
    CHECK(fv.update(m, 3) == 1 && fv.size() == 6);
    CHECK(fv.update(m, 3) == 0 && fv.size() == 7);
    CHECK(fv.update(m) == 0 && fv.size() == 7);
    m.push(rec(7, 1080, Dir::C2S, 9, 1, 5));
    CHECK(fv.update(m) == 0 && fv.size() == 8 && fv.seq(7) == 7);
    Filter c2s;
    c2s.dir = {true, false};
    fv.reset(c2s);
    CHECK(fv.filter() == c2s);
    CHECK(fv.update(m, 4) == 4 && fv.size() == 0);
    CHECK(fv.update(m, 4) == 0 && fv.size() == 3 && fv.seq(0) == 5 && fv.seq(2) == 7);

    PacketModel c(&fx, 1000, 10.0, 3, 1 << 20);
    FilterView cv;
    cv.reset(Filter{});
    for (uint64_t i = 0; i < 3; ++i) {
        c.push(rec(i, 1000, Dir::S2C, 9, 1, 8));
    }
    CHECK(cv.update(c) == 0 && cv.size() == 3);
    c.push(rec(3, 1000, Dir::S2C, 9, 1, 8));
    c.push(rec(4, 1000, Dir::S2C, 9, 1, 8));
    CHECK(c.lower_bound(0) == 0 && c.lower_bound(3) == 1 && c.lower_bound(9) == 3);
    CHECK(cv.update(c) == 0 && cv.size() == 3 && cv.seq(0) == 2 && cv.seq(2) == 4);
    c.clear();
    CHECK(cv.update(c) == 0 && cv.size() == 0);
    c.push(rec(5, 1000, Dir::S2C, 9, 1, 8));
    CHECK(cv.update(c) == 0 && cv.size() == 1 && cv.seq(0) == 5);
    std::printf("filter: done\n");
}

static void test_trigger(const PacketDb& db) {
    PacketModel m(&db, 1000, 10.0);
    std::string log;
    m.push(rec(8, 1015, Dir::C2S, 3, 3, 0), &log);
    m.push(rec(9, 1020, Dir::C2S, 56, 4, 2), &log);
    CHECK_STR(log, "#8 t+1.500ms C2S (3,3) size=0 CNetworkEX::BaseDownloadRequest trigger\n"
                   "#9 t+2.000ms C2S (56,4) size=2 PatriarchElectProcessor::Doit(_eVote) unknown(no layout)\n"
                   "    0000  00 00\n");
    CHECK(m.size() == 2);
    if (m.size() == 2) {
        check_row(m.at(0), Status::Trigger, "CNetworkEX::BaseDownloadRequest",
                  "CNetworkEX::BaseDownloadRequest trigger", nullptr);
        check_row(m.at(1), Status::Unknown, "PatriarchElectProcessor::Doit(_eVote)",
                  "PatriarchElectProcessor::Doit(_eVote) unknown(no layout)", nullptr);
    }
    CHECK(m.count(Status::Trigger) == 1 && m.count(Status::Unknown) == 1);
    Filter f;
    CHECK(f.status.size() == kStatusCount);
    for (const bool b : f.status) {
        CHECK(b);
    }
    f.status.fill(false);
    f.status[(size_t)Status::Trigger] = true;
    check_seqs(m, f, {8}, __LINE__);
    f = Filter{};
    f.status[(size_t)Status::Trigger] = false;
    check_seqs(m, f, {9}, __LINE__);
    f = Filter{};
    f.name = "basedownload";
    check_seqs(m, f, {8}, __LINE__);
    f = Filter{};
    f.text = "trigger";
    check_seqs(m, f, {8}, __LINE__);
    if (m.size() == 2) {
        PacketView v;
        build_view(v, m.at(0), &db);
        CHECK(v.layouts.empty() && v.pick == -1);
    }
    std::vector<const Struct*> out;
    CHECK(layout_choices(db, Dir::C2S, 3, 3, 0, out) == -1 && out.empty());
    m.clear();
    CHECK(m.count(Status::Trigger) == 0);
    std::printf("trigger: done\n");
}

static void test_rates(const PacketDb& fx) {
    RateMeter r(2000.0);
    r.add(0.0, Dir::C2S, 10);
    r.add(500.0, Dir::C2S, 30);
    r.add(1000.0, Dir::S2C, 100);
    r.add(1500.0, Dir::C2S, 20);
    Rates a = r.rates(1500.0);
    CHECK(a.pkts[0] == 1.5 && a.bytes[0] == 30.0 && a.pkts[1] == 0.5 && a.bytes[1] == 50.0);
    a = r.rates(2000.0);
    CHECK(a.pkts[0] == 1.0 && a.bytes[0] == 25.0 && a.pkts[1] == 0.5 && a.bytes[1] == 50.0);
    a = r.rates(2600.0);
    CHECK(a.pkts[0] == 0.5 && a.bytes[0] == 10.0 && a.pkts[1] == 0.5 && a.bytes[1] == 50.0);
    a = r.rates(4000.0);
    CHECK(a.pkts[0] == 0.0 && a.bytes[0] == 0.0 && a.pkts[1] == 0.0 && a.bytes[1] == 0.0);

    PacketModel m(&fx, 1000, 10.0);
    m.push(rec(0, 1015, Dir::S2C, 9, 1, 8));
    m.push(rec(1, 1020, Dir::S2C, 9, 1, 30));
    m.push(rec(2, 1030, Dir::S2C, 9, 3, 4));
    m.push(rec(3, 1040, Dir::S2C, 9, 9, 4));
    m.push(rec(4, 1050, Dir::S2C, 9, 1, 5));
    m.push(rec(5, 1060, Dir::C2S, 9, 1, 5));
    a = m.rates(6.0);
    CHECK(a.pkts[1] == 2.5 && a.bytes[1] == 25.5 && a.pkts[0] == 0.5 && a.bytes[0] == 2.5);
    m.clear();
    a = m.rates(6.0);
    CHECK(a.pkts[1] == 2.5 && a.pkts[0] == 0.5);
    a = m.rates(5000.0);
    CHECK(a.pkts[0] == 0.0 && a.pkts[1] == 0.0);
    std::printf("rates: done\n");
}

static const Struct* need(const PacketDb& db, const char* name) {
    const Struct* s = db.get(name);
    if (!s) {
        std::printf("FAIL: no struct %s in the db\n", name);
        ++g_fail;
    }
    return s;
}

static void test_edit(const PacketDb& fx, const PacketDb& db) {
    std::string err;
    if (const Struct* s = need(fx, "_fix_a_zocl")) {
        std::vector<uint8_t> b(8, 0);
        const std::vector<EditField> v = edit_fields(*s, &fx, b.data(), b.size());
        CHECK(v.size() == 3);
        if (v.size() == 3) {
            CHECK(v[0].name == "dwA" && v[0].type == "uint32_t" && v[0].offset == 0 && v[0].size == 4 &&
                  v[0].prim == Prim::U);
            CHECK(v[1].name == "wB" && v[1].offset == 4 && v[1].size == 2 && v[1].prim == Prim::U);
            CHECK(v[2].name == "zC" && v[2].offset == 6 && v[2].size == 2 && v[2].prim == Prim::S);
            CHECK(set_field(v[0], "0x01020304", b));
            CHECK((b == std::vector<uint8_t>{0x04, 0x03, 0x02, 0x01, 0, 0, 0, 0}));
            CHECK_STR(field_text(v[0], b.data(), b.size()), "16909060");
            CHECK(set_field(v[2], " -2 ", b) && b[6] == 0xFE && b[7] == 0xFF);
            CHECK_STR(field_text(v[2], b.data(), b.size()), "-2");
            CHECK(set_field(v[2], "0xFFFF", b));
            CHECK_STR(field_text(v[2], b.data(), b.size()), "-1");
            CHECK(set_field(v[1], "65535", b) && b[4] == 0xFF && b[5] == 0xFF);
            const std::vector<uint8_t> keep = b;
            CHECK(!set_field(v[1], "65536", b, &err) && !err.empty());
            CHECK(!set_field(v[2], "32768", b));
            CHECK(!set_field(v[2], "-32769", b));
            CHECK(!set_field(v[2], "0x10000", b));
            CHECK(!set_field(v[0], "-1", b));
            CHECK(!set_field(v[0], "", b));
            CHECK(!set_field(v[0], "12ab", b));
            CHECK(!set_field(v[0], "0x", b));
            CHECK(b == keep);
            CHECK(set_field(v[2], "32767", b) && b[6] == 0xFF && b[7] == 0x7F);
            CHECK(set_field(v[2], "-32768", b) && b[6] == 0x00 && b[7] == 0x80);
        }
        std::vector<uint8_t> sb(5, 0);
        const std::vector<EditField> w = edit_fields(*s, &fx, sb.data(), sb.size());
        CHECK(w.size() == 3);
        if (w.size() == 3) {
            CHECK(present(w[0], sb.size()) && !present(w[1], sb.size()) && !present(w[2], sb.size()));
            CHECK(field_text(w[1], sb.data(), sb.size()).empty());
            CHECK(!set_field(w[1], "1", sb, &err) && sb == std::vector<uint8_t>(5, 0));
        }
        const std::vector<EditField> e = edit_fields(*s, &fx, nullptr, 0);
        CHECK(e.size() == 3 && !present(e[0], 0));
    }
    if (const Struct* s = need(fx, "_fix_req_clzo")) {
        std::vector<uint8_t> b(5, 0);
        const std::vector<EditField> v = edit_fields(*s, &fx, b.data(), b.size());
        CHECK(v.size() == 2);
        if (v.size() == 2) {
            CHECK(v[0].prim == Prim::Bool && v[1].prim == Prim::F32 && v[1].offset == 1 && v[1].size == 4);
            CHECK_STR(field_text(v[0], b.data(), b.size()), "false");
            CHECK(set_field(v[0], "TRUE", b) && b[0] == 1);
            CHECK_STR(field_text(v[0], b.data(), b.size()), "true");
            b[0] = 2;
            CHECK_STR(field_text(v[0], b.data(), b.size()), "2");
            CHECK(set_field(v[0], "false", b) && b[0] == 0);
            CHECK(!set_field(v[0], "256", b));
            CHECK(set_field(v[1], "1.5", b) && b[1] == 0x00 && b[2] == 0x00 && b[3] == 0xC0 && b[4] == 0x3F);
            CHECK_STR(field_text(v[1], b.data(), b.size()), "1.5");
            CHECK(set_field(v[1], "-2", b));
            CHECK_STR(field_text(v[1], b.data(), b.size()), "-2");
            CHECK(set_field(v[1], "0.1", b));
            CHECK_STR(field_text(v[1], b.data(), b.size()), "0.1");
            CHECK(!set_field(v[1], "abc", b));
            CHECK(!set_field(v[1], "1.5x", b));
            CHECK(!set_field(v[1], "1e999", b));
        }
    }
    if (const Struct* s = need(fx, "_fix_var_zocl")) {
        std::vector<uint8_t> b(20, 0xAA);
        const std::vector<EditField> v = edit_fields(*s, &fx, b.data(), b.size());
        CHECK(v.size() == 2);
        if (v.size() == 2) {
            CHECK(v[1].name == "szText" && v[1].type == "char[19]" && v[1].text && v[1].offset == 1 && v[1].size == 19);
            CHECK(set_field(v[1], "hi\\x01", b));
            bool zero = true;
            for (size_t i = 4; i < 20; ++i) {
                zero = zero && b[i] == 0;
            }
            CHECK(b[0] == 0xAA && b[1] == 'h' && b[2] == 'i' && b[3] == 0x01 && zero);
            CHECK_STR(field_text(v[1], b.data(), b.size()), "hi\\x01");
            CHECK(set_field(v[1], "a\\\\b", b) && b[1] == 'a' && b[2] == '\\' && b[3] == 'b' && b[4] == 0);
            CHECK_STR(field_text(v[1], b.data(), b.size()), "a\\\\b");
            CHECK(set_field(v[1], std::string(19, 'x'), b) && b[19] == 'x');
            CHECK(!set_field(v[1], std::string(20, 'x'), b, &err));
            CHECK(!set_field(v[1], "a\\q", b));
            CHECK(!set_field(v[1], "a\\x4", b));
            CHECK(set_field(v[1], "", b) && b[1] == 0);
        }
    }
    if (const Struct* s = need(fx, "_fix_nest_zocl")) {
        std::vector<uint8_t> b(12, 0);
        const std::vector<EditField> v = edit_fields(*s, &fx, b.data(), b.size());
        const char* names[] = {"byRet",          "(unmapped)",   "List[0].wIndex", "List[0].wNum",
                               "List[1].wIndex", "List[1].wNum", "(unmapped)"};
        const int offs[] = {0, 1, 2, 4, 6, 8, 10}, sizes[] = {1, 1, 2, 2, 2, 2, 2};
        CHECK(v.size() == 7);
        for (size_t i = 0; i < v.size() && i < 7; ++i) {
            CHECK_STR(v[i].name, names[i]);
            CHECK(v[i].offset == offs[i] && v[i].size == sizes[i]);
        }
        if (v.size() == 7) {
            CHECK(v[1].prim == Prim::None && !v[1].text && v[1].type.empty());
            CHECK_STR(field_text(v[1], b.data(), b.size()), "00");
            CHECK(set_field(v[1], "7F", b) && b[1] == 0x7F);
            CHECK(!set_field(v[1], "7F 00", b));
            CHECK(!set_field(v[1], "zz", b));
            CHECK(set_field(v[5], "513", b) && b[8] == 0x01 && b[9] == 0x02);
            CHECK_STR(field_text(v[6], b.data(), b.size()), "00 00");
        }
    }
    if (const Struct* s = need(fx, "_fix_raw_zocl")) {
        std::vector<uint8_t> b(6, 0);
        const std::vector<EditField> v = edit_fields(*s, &fx, b.data(), b.size());
        CHECK(v.size() == 1 && v[0].name == "id" && v[0].type == "_CLID" && v[0].size == 6 && v[0].prim == Prim::None);
        if (v.size() == 1) {
            CHECK_STR(field_text(v[0], b.data(), b.size()), "00 00 00 00 00 00");
        }
    }
    if (const Struct* s = need(fx, "_fix_arr_zocl")) {
        std::vector<uint8_t> b(20, 0);
        const std::vector<EditField> v = edit_fields(*s, &fx, b.data(), b.size());
        CHECK(v.size() == 1 && v[0].name == "byList[20]" && v[0].type == "uint8_t[20]" && v[0].size == 20 &&
              v[0].prim == Prim::None && !v[0].text);
    }
    if (const Struct* s = need(fx, "_fix_b_zocl")) {
        std::vector<uint8_t> b(5, 0);
        const std::vector<EditField> v = edit_fields(*s, &fx, b.data(), b.size());
        CHECK(v.size() == 2 && v[0].name == "wHP");
        if (v.size() == 2) {
            CHECK(v[1].name == "(beyond sizeof)" && v[1].offset == 2 && v[1].size == 3);
        }
    }
    if (const Struct* s = need(db, "_move_request_clzo")) {
        std::vector<uint8_t> mv = {0x01, 0x00, 0x00, 0xC0, 0x3F, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x80,
                                   0xC8, 0x42, 0xD2, 0x04, 0x00, 0x00, 0xFB, 0xFF, 0x07, 0x00, 0x03};
        const std::vector<EditField> v = edit_fields(*s, &db, mv.data(), mv.size());
        const char* names[] = {"byMoveType", "fCur[0]", "fCur[1]", "fCur[2]",
                               "dwSerial",   "zTar[0]", "zTar[1]", "byDirect"};
        const char* texts[] = {"1", "1.5", "-2", "100.25", "1234", "-5", "7", "3"};
        CHECK(v.size() == 8);
        for (size_t i = 0; i < v.size() && i < 8; ++i) {
            CHECK_STR(v[i].name, names[i]);
            CHECK_STR(field_text(v[i], mv.data(), mv.size()), texts[i]);
        }
        if (v.size() == 8) {
            std::vector<uint8_t> want = mv;
            want[8] = 0x40;
            CHECK(set_field(v[2], "2", mv) && mv == want);
        }
    }
    if (const Struct* s = need(db, "_base_download_result_zocl")) {
        std::vector<uint8_t> b(258, 0);
        const std::vector<EditField> v = edit_fields(*s, &db, b.data(), b.size());
        CHECK(v.size() == 114);
        if (v.size() != 114) {
            std::printf("  leaves = %zu:", v.size());
            for (const EditField& f : v) {
                std::printf(" %s", f.name.c_str());
            }
            std::printf("\n");
        }
        if (v.size() == 114) {
            CHECK(v[23].name == "EquipList[0].sTableCode" && v[23].offset == 71 && v[23].size == 1 &&
                  v[23].prim == Prim::S);
            CHECK(v.back().name == "byHonorGuildRank" && v.back().offset == 257);
        }
    }
    std::vector<const Struct*> out;
    CHECK(layout_choices(db, Dir::C2S, 4, 1, 0, out) == 0 && out.size() == 1 && out[0] == db.get("_move_request_clzo"));
    CHECK(layout_choices(fx, Dir::S2C, 9, 1, 2, out) == 1 && out.size() == 3);
    if (out.size() == 3) {
        CHECK(out[0] == fx.get("_fix_a_zocl") && out[1] == fx.get("_fix_b_zocl") && out[2] == fx.get("_fix_var_zocl"));
    }
    CHECK(layout_choices(fx, Dir::S2C, 9, 1, 5, out) == 2);
    CHECK(layout_choices(fx, Dir::S2C, 9, 1, 30, out) == 0);
    CHECK(layout_choices(fx, Dir::S2C, 9, 3, 4, out) == -1 && out.empty());
    CHECK(layout_choices(fx, Dir::C2S, 250, 250, 4, out) == -1 && out.empty());
    std::printf("edit: done\n");
}

int main(int argc, char** argv) {
    if (argc < 3) {
        std::printf("usage: test_model <packet_db.json> <packet_db_mini.json>\nFAILED (1 failure(s))\n");
        return 1;
    }
    PacketDb db, fx;
    std::string e1, e2;
    const bool ok_db = db.load(argv[1], &e1);
    const bool ok_fx = fx.load(argv[2], &e2);
    if (!ok_db) {
        std::printf("FAIL: cannot load %s: %s\n", argv[1], e1.c_str());
        ++g_fail;
    }
    if (!ok_fx) {
        std::printf("FAIL: cannot load %s: %s\n", argv[2], e2.c_str());
        ++g_fail;
    }
    if (ok_db && ok_fx) {
        test_rows(fx);
        test_log(db);
        test_cap();
        test_view(fx, db);
        test_filter(fx);
        test_trigger(db);
        test_rates(fx);
        test_edit(fx, db);
    }
    if (g_fail) {
        std::printf("FAILED (%d failure(s))\n", g_fail);
    } else {
        std::printf("PASSED (0 failure(s))\n");
    }
    return g_fail ? 1 : 0;
}
