#include "proto/packet_db.h"
#include "ui/ui.h"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdlib.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <iterator>
#include <string>
#include <utility>
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

static std::vector<PacketRec> g_src;
static size_t g_pos = 0;
static bool g_dropReported = false;
static std::string g_log;

static size_t g_drainCap = SIZE_MAX;

static size_t fake_drain(std::vector<PacketRec>& out, size_t max, uint64_t& dropped) {
    dropped = g_dropReported ? 0 : 5;
    g_dropReported = true;
    size_t n = 0;
    while (n < max && n < g_drainCap && g_pos < g_src.size()) {
        out.push_back(std::move(g_src[g_pos++]));
        ++n;
    }
    return n;
}

static void sink(const char* p, size_t n) {
    g_log.append(p, n);
}

static std::vector<bool> g_cap;

static void fake_capture(bool on) {
    g_cap.push_back(on);
}

struct QueuedCall {
    Dir dir;
    uint8_t main, sub;
    std::vector<uint8_t> bytes;
};

static std::vector<QueuedCall> g_queue;

static Queued fake_queue(Dir d, uint8_t m, uint8_t s, const uint8_t* p, size_t n) {
    g_queue.push_back({d, m, s, std::vector<uint8_t>(p, p + n)});
    return Queued::Ok;
}

static size_t fake_cancel() {
    return 0;
}

static ActionStats fake_stats() {
    ActionStats s;
    s.calls[0] = s.calls[1] = 1;
    return s;
}

static std::vector<bool> g_arm;

static void fake_arm(bool on) {
    g_arm.push_back(on);
}

static std::vector<std::vector<PatchRule>> g_setCalls;

static size_t fake_set_rules(const std::vector<PatchRule>& r) {
    g_setCalls.push_back(r);
    return r.size();
}

static std::vector<std::vector<PatchRule>> g_saveCalls;

static bool fake_save(const std::vector<PatchRule>& r, std::string*) {
    g_saveCalls.push_back(r);
    return true;
}

static RuleStats fake_rule_stats() {
    RuleStats s;
    s.armed = !g_arm.empty() && g_arm.back();
    s.active = 1;
    s.edited[0] = 1;
    s.hits[0] = 1;
    return s;
}

static void make_source(size_t n) {
    g_src.clear();
    g_pos = 0;
    g_dropReported = false;
    g_log.clear();
    for (size_t i = 0; i < n; ++i) {
        PacketRec r{};
        r.seq = i;
        r.ts_qpc = 1000 + 10 * i;
        r.edited = false;
        if (i % 2 == 0) {
            r.dir = Dir::C2S;
            r.main = 4;
            r.sub = 1;
            r.size = 22;
            r.bytes.assign(22, 0);
            r.bytes[0] = 0x01;
        } else {
            r.dir = Dir::S2C;
            r.main = 250;
            r.sub = 250;
            r.size = 4;
            r.bytes = {0x01, 0x02, 0x03, 0x04};
        }
        g_src.push_back(std::move(r));
    }
}

static void make_detail_source() {
    g_src.clear();
    g_pos = 0;
    g_dropReported = false;
    g_log.clear();
    PacketRec r{};
    r.seq = 0;
    r.ts_qpc = 1000;
    r.dir = Dir::C2S;
    r.main = 4;
    r.sub = 1;
    r.size = 22;
    r.edited = false;
    r.bytes.assign(22, 0);
    r.bytes[0] = 0x01;
    g_src.push_back(r);
    r.seq = 1;
    r.ts_qpc = 1010;
    r.dir = Dir::S2C;
    r.main = 3;
    r.sub = 4;
    r.size = 258;
    r.bytes.assign(258, 0);
    g_src.push_back(r);
    r.seq = 2;
    r.ts_qpc = 1020;
    r.dir = Dir::S2C;
    r.main = 250;
    r.sub = 250;
    r.size = 4;
    r.bytes = {0x01, 0x02, 0x03, 0x04};
    g_src.push_back(r);
}

static void make_server_source() {
    g_src.clear();
    g_pos = 0;
    g_dropReported = false;
    g_log.clear();

    const struct {
        uint8_t m, s;
        std::vector<uint8_t> b;
    } k[] = {{3, 3, {}}, {6, 1, {0x01, 0x02}}, {101, 1, {}}};

    for (size_t i = 0; i < std::size(k); ++i) {
        PacketRec r{};
        r.seq = i;
        r.ts_qpc = 1000 + 10 * i;
        r.dir = Dir::C2S;
        r.main = k[i].m;
        r.sub = k[i].s;
        r.size = (uint16_t)k[i].b.size();
        r.edited = false;
        r.bytes = k[i].b;
        g_src.push_back(std::move(r));
    }
}

static bool no_window_left() {
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof wc;
    return FindWindowW(L"RFTrafficEditorUI", nullptr) == nullptr &&
           GetClassInfoExW(GetModuleHandleW(nullptr), L"RFTrafficEditorUI", &wc) == FALSE;
}

static bool wait_for(uint64_t ingested, uint64_t min_iter) {
    for (int i = 0; i < 1000; ++i) {
        const UiStats s = ui_stats();
        if (s.ingested >= ingested && s.iterations >= min_iter) {
            return true;
        }
        Sleep(10);
    }
    return false;
}

static size_t packet_lines(const std::string& log) {
    size_t n = 0;
    for (size_t at = 0; at < log.size();) {
        if (log[at] == '#') {
            ++n;
        }
        const size_t nl = log.find('\n', at);
        if (nl == std::string::npos) {
            break;
        }
        at = nl + 1;
    }
    return n;
}

static bool starts_with(const std::string& s, const char* p) {
    return s.rfind(p, 0) == 0;
}

int main(int argc, char** argv) {
    _set_error_mode(_OUT_TO_STDERR);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    if (argc < 2) {
        std::printf("usage: test_ui <packet_db.json>\nFAILED (1 failure(s))\n");
        return 1;
    }

    ui_stop();
    {
        UiConfig bad;
        CHECK(!ui_start(bad));
        CHECK(no_window_left());
    }
    std::printf("ui: config done\n");

    PacketDb db;
    std::string err;
    if (!db.load(argv[1], &err)) {
        std::printf("FAIL: cannot load %s: %s\n", argv[1], err.c_str());
        ++g_fail;
    } else {
        make_source(300);
        UiConfig cfg;
        cfg.module = GetModuleHandleW(nullptr);
        cfg.db = &db;
        cfg.qpc_base = 1000;
        cfg.qpc_per_ms = 10.0;
        cfg.title = L"test_ui";
        cfg.show = false;
        cfg.drain = fake_drain;
        cfg.log_packets = sink;
        cfg.select_seq = 0;
        const bool up = ui_start(cfg);
        CHECK(up);
        if (up) {
            CHECK(FindWindowW(L"RFTrafficEditorUI", L"test_ui") != nullptr);
            CHECK(wait_for(300, 3));
            CHECK(!ui_unload_requested());
            std::vector<uint32_t> px;
            int w = 0, h = 0;
            CHECK(ui_snapshot(px, w, h));
            CHECK(w > 0 && h > 0 && px.size() == (size_t)w * (size_t)h);
            CHECK(std::any_of(px.begin(), px.end(), [&](uint32_t v) {
                return v != px.front();
            }));
        }
        ui_stop();
        {
            std::vector<uint32_t> px;
            int w = 0, h = 0;
            CHECK(!ui_snapshot(px, w, h, 100));
        }
        if (up) {
            const UiStats s = ui_stats();
            CHECK(s.ingested == 300);
            CHECK(s.rows == 300);
            CHECK(s.dropped == 5);
            CHECK(s.frames >= 1);
            CHECK(s.iterations >= 3);
            CHECK(packet_lines(g_log) == 300);
            CHECK(starts_with(g_log, "#0 t+0.000ms C2S (4,1) size=22 _move_request_clzo ok\n"));
            CHECK(g_log.find("\n#1 t+1.000ms S2C (250,250) size=4 unknown\n    0000  01 02 03 04\n") !=
                  std::string::npos);
            CHECK(s.detail_frames >= 1);
            CHECK(s.detail_seq == 0);
            CHECK(s.detail_rows == 5);
            CHECK(s.shown == 300);
            CHECK(s.filter_pending == 0);
            CHECK(s.detail_route == -1 && s.composer_route == -1);
            CHECK(s.detail_server == (int)ServerRoute::Kind::Arm && s.server_warns == 0);
        }
        CHECK(no_window_left());
        std::printf("ui: cycle 1 done\n");

        make_source(10);
        cfg.db = nullptr;
        cfg.select_seq = 1;
        const bool up2 = ui_start(cfg);
        CHECK(up2);
        if (up2) {
            CHECK(wait_for(10, 2));
        }
        ui_stop();
        if (up2) {
            const UiStats s = ui_stats();
            CHECK(s.ingested == 10);
            CHECK(s.dropped == 5);
            CHECK(starts_with(g_log, "#0 t+0.000ms C2S (4,1) size=22\n    0000  01 00"));
            CHECK(s.detail_frames >= 1);
            CHECK(s.detail_seq == 1);
            CHECK(s.detail_rows == 0);
            CHECK(s.shown == 10);
            CHECK(s.detail_route == -1);
            CHECK(s.detail_server == -1);
        }
        CHECK(no_window_left());
        std::printf("ui: cycle 2 done\n");

        make_detail_source();
        cfg.db = &db;
        cfg.select_seq = 1;
        cfg.open_nested = true;
        const bool up3 = ui_start(cfg);
        CHECK(up3);
        if (up3) {
            CHECK(wait_for(3, 2));
        }
        ui_stop();
        if (up3) {
            const UiStats s = ui_stats();
            CHECK(s.ingested == 3);
            CHECK(s.detail_frames >= 1);
            CHECK(s.detail_seq == 1);
            CHECK(s.detail_rows == 126);
            if (s.detail_rows != 126) {
                std::printf("  detail_rows = %llu\n", (unsigned long long)s.detail_rows);
            }
            CHECK(g_log.find("\n#1 t+1.000ms S2C (3,4) size=258 _base_download_result_zocl ok\n") != std::string::npos);
            CHECK(s.shown == 3);
            CHECK(s.detail_route == (int)ClientRoute::Kind::Arm);
        }
        CHECK(no_window_left());
        std::printf("ui: detail done\n");

        make_source(300);
        cfg.db = &db;
        cfg.select_seq = ~0ull;
        cfg.open_nested = false;
        cfg.filter = Filter{};
        cfg.filter.text = "01 02 03 04";
        cfg.capture = false;
        cfg.set_capture = fake_capture;
        g_cap.clear();
        const bool up4 = ui_start(cfg);
        CHECK(up4);
        if (up4) {
            CHECK(wait_for(300, 2));
        }
        ui_stop();
        if (up4) {
            const UiStats s = ui_stats();
            CHECK(s.ingested == 300);
            CHECK(s.rows == 300);
            CHECK(s.shown == 150);
            CHECK(s.filter_pending == 0);
            CHECK(packet_lines(g_log) == 300);
            CHECK(g_cap.size() == 2 && !g_cap[0] && g_cap[1]);
        }
        CHECK(no_window_left());
        std::printf("ui: filter done\n");

        const std::vector<uint8_t> kMove = {0x01, 0x00, 0x00, 0xC0, 0x3F, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x80,
                                            0xC8, 0x42, 0xD2, 0x04, 0x00, 0x00, 0xFB, 0xFF, 0x07, 0x00, 0x03};
        cfg.filter = Filter{};
        cfg.capture = true;
        cfg.set_capture = nullptr;
        cfg.queue_action = fake_queue;
        cfg.cancel_actions = fake_cancel;
        cfg.action_stats = fake_stats;
        cfg.compose = ComposeInit{};
        cfg.compose.open = true;
        cfg.compose.dir = Dir::C2S;
        cfg.compose.opcode = "4,1";
        cfg.compose.hex = "01 00 00 C0 3F 00 00 00 C0 00 80 C8 42 D2 04 00 00 FB FF 07 00 03";
        cfg.compose.confirmed = true;
        cfg.compose.submit = true;
        make_source(10);
        g_queue.clear();
        const bool up5 = ui_start(cfg);
        CHECK(up5);
        if (up5) {
            CHECK(wait_for(10, 2));
        }
        ui_stop();
        if (up5) {
            const UiStats s = ui_stats();
            CHECK(s.composer_frames >= 1);
            CHECK(s.queued == 1 && s.rejected == 0 && s.confirm_asks == 0);
            CHECK(s.composer_route == -1);
            CHECK(g_queue.size() == 1);
            if (g_queue.size() == 1) {
                CHECK(g_queue[0].dir == Dir::C2S && g_queue[0].main == 4 && g_queue[0].sub == 1 &&
                      g_queue[0].bytes == kMove);
            }
        }
        CHECK(no_window_left());
        cfg.compose.confirmed = false;
        make_source(10);
        g_queue.clear();
        const bool up6 = ui_start(cfg);
        CHECK(up6);
        if (up6) {
            CHECK(wait_for(10, 2));
        }
        ui_stop();
        if (up6) {
            const UiStats s = ui_stats();
            CHECK(s.queued == 0 && s.confirm_asks == 1);
            CHECK(g_queue.empty());
        }
        CHECK(no_window_left());
        cfg.compose.confirmed = true;
        cfg.compose.dir = Dir::S2C;
        cfg.compose.opcode = "(0x3, 4)";
        cfg.compose.hex = "0xAA,0xBB";
        make_source(10);
        g_queue.clear();
        const bool up7 = ui_start(cfg);
        CHECK(up7);
        if (up7) {
            CHECK(wait_for(10, 2));
        }
        ui_stop();
        if (up7) {
            const UiStats s = ui_stats();
            CHECK(s.queued == 1 && s.confirm_asks == 0);
            CHECK(s.composer_route == (int)ClientRoute::Kind::Arm);
            CHECK(g_queue.size() == 1);
            if (g_queue.size() == 1) {
                CHECK(g_queue[0].dir == Dir::S2C && g_queue[0].main == 3 && g_queue[0].sub == 4 &&
                      (g_queue[0].bytes == std::vector<uint8_t>{0xAA, 0xBB}));
            }
        }
        CHECK(no_window_left());
        std::printf("ui: composer done\n");

        cfg.compose = ComposeInit{};
        cfg.compose.open = true;
        cfg.compose.dir = Dir::C2S;
        cfg.compose.opcode = "4,1";
        cfg.compose.hex = "";
        cfg.compose.confirmed = true;
        cfg.compose.submit = true;
        cfg.compose.fill = true;
        cfg.compose.edits = {{"fCur[1]", "2"}, {"dwSerial", "0x01020304"}};
        make_source(10);
        g_queue.clear();
        const bool up8 = ui_start(cfg);
        CHECK(up8);
        if (up8) {
            CHECK(wait_for(10, 2));
        }
        ui_stop();
        if (up8) {
            const UiStats s = ui_stats();
            CHECK(s.editor_fields == 8);
            CHECK(s.field_edits == 2);
            CHECK(s.queued == 1 && s.confirm_asks == 0);
            std::vector<uint8_t> want(22, 0);
            want[8] = 0x40;
            want[13] = 0x04;
            want[14] = 0x03;
            want[15] = 0x02;
            want[16] = 0x01;
            CHECK(g_queue.size() == 1);
            if (g_queue.size() == 1) {
                CHECK(g_queue[0].dir == Dir::C2S && g_queue[0].main == 4 && g_queue[0].sub == 1 &&
                      g_queue[0].bytes == want);
            }
        }
        CHECK(no_window_left());
        std::printf("ui: editor done\n");

        std::vector<uint8_t> row0(22, 0);
        row0[0] = 0x01;
        cfg.compose = ComposeInit{};
        cfg.compose.confirmed = true;
        cfg.resend_seq = 0;
        cfg.resend_other = false;
        make_source(10);
        g_queue.clear();
        const bool up9 = ui_start(cfg);
        CHECK(up9);
        if (up9) {
            CHECK(wait_for(10, 2));
        }
        ui_stop();
        if (up9) {
            const UiStats s = ui_stats();
            CHECK(s.resends == 1 && s.queued == 1 && s.confirm_asks == 0 && s.composer_frames == 0);
            CHECK(g_queue.size() == 1);
            if (g_queue.size() == 1) {
                CHECK(g_queue[0].dir == Dir::C2S && g_queue[0].main == 4 && g_queue[0].sub == 1 &&
                      g_queue[0].bytes == row0);
            }
        }
        CHECK(no_window_left());
        cfg.resend_seq = 1;
        cfg.resend_other = true;
        make_source(10);
        g_queue.clear();
        const bool up10 = ui_start(cfg);
        CHECK(up10);
        if (up10) {
            CHECK(wait_for(10, 2));
        }
        ui_stop();
        if (up10) {
            const UiStats s = ui_stats();
            CHECK(s.resends == 1 && s.queued == 1);
            CHECK(g_queue.size() == 1);
            if (g_queue.size() == 1) {
                CHECK(g_queue[0].dir == Dir::C2S && g_queue[0].main == 250 && g_queue[0].sub == 250 &&
                      (g_queue[0].bytes == std::vector<uint8_t>{0x01, 0x02, 0x03, 0x04}));
            }
        }
        CHECK(no_window_left());
        cfg.compose.confirmed = false;
        make_source(10);
        g_queue.clear();
        const bool up11 = ui_start(cfg);
        CHECK(up11);
        if (up11) {
            CHECK(wait_for(10, 2));
        }
        ui_stop();
        if (up11) {
            const UiStats s = ui_stats();
            CHECK(s.resends == 1 && s.confirm_asks == 1 && s.queued == 0);
            CHECK(g_queue.empty());
        }
        CHECK(no_window_left());
        cfg.resend_seq = ~0ull;
        std::printf("ui: resend done\n");

        cfg.compose = ComposeInit{};
        cfg.compose.open = true;
        cfg.compose.dir = Dir::S2C;
        cfg.compose.opcode = "4,4";
        cfg.compose.hex = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
        cfg.compose.confirmed = true;
        cfg.select_seq = 1;
        make_source(10);
        g_queue.clear();
        const bool up12 = ui_start(cfg);
        CHECK(up12);
        if (up12) {
            CHECK(wait_for(10, 2));
        }
        ui_stop();
        if (up12) {
            const UiStats s = ui_stats();
            CHECK(s.detail_seq == 1 && s.detail_route == (int)ClientRoute::Kind::NoCase);
            CHECK(s.composer_frames >= 1 && s.composer_route == (int)ClientRoute::Kind::Processor);
            CHECK(s.queued == 0 && g_queue.empty());
            CHECK(s.route_warns > 0);
        }
        CHECK(no_window_left());
        std::printf("ui: client done\n");

        cfg.host_build = "4.15";
        make_source(10);
        g_queue.clear();
        const bool up12b = ui_start(cfg);
        CHECK(up12b);
        if (up12b) {
            CHECK(wait_for(10, 2));
        }
        ui_stop();
        if (up12b) {
            const UiStats s = ui_stats();
            CHECK(s.detail_seq == 1 && s.detail_route == (int)ClientRoute::Kind::NoCase);
            CHECK(s.composer_route == (int)ClientRoute::Kind::Processor);
            CHECK(s.route_warns == 0);
        }
        CHECK(no_window_left());
        cfg.host_build.clear();
        cfg.select_seq = ~0ull;
        std::printf("ui: client reference done\n");

        cfg.compose = ComposeInit{};
        cfg.compose.open = true;
        cfg.compose.dir = Dir::C2S;
        cfg.compose.opcode = "3,3";
        cfg.compose.hex = "";
        cfg.compose.confirmed = true;
        cfg.select_seq = 1;
        make_server_source();
        g_queue.clear();
        const bool up12c = ui_start(cfg);
        CHECK(up12c);
        if (up12c) {
            CHECK(wait_for(3, 2));
        }
        ui_stop();
        if (up12c) {
            const UiStats s = ui_stats();
            CHECK(s.detail_seq == 1 && s.detail_server == (int)ServerRoute::Kind::NoCase);
            CHECK(s.detail_route == -1);
            CHECK(s.composer_frames >= 1 && s.composer_server == (int)ServerRoute::Kind::Arm);
            CHECK(s.server_warns > 0);
            CHECK(s.route_warns == 0);
            CHECK(s.queued == 0 && g_queue.empty());
            CHECK(starts_with(g_log, "#0 t+0.000ms C2S (3,3) size=0 CNetworkEX::BaseDownloadRequest trigger\n"));
            CHECK(g_log.find("\n#1 t+1.000ms C2S (6,1) size=2 unknown\n    0000  01 02\n") != std::string::npos);
            CHECK(g_log.find("\n#2 t+2.000ms C2S (101,1) size=0 unknown\n") != std::string::npos);
        }
        CHECK(no_window_left());
        std::printf("ui: server done\n");

        cfg.host_build = "4.15";
        make_server_source();
        g_queue.clear();
        const bool up12d = ui_start(cfg);
        CHECK(up12d);
        if (up12d) {
            CHECK(wait_for(3, 2));
        }
        ui_stop();
        if (up12d) {
            const UiStats s = ui_stats();
            CHECK(s.detail_seq == 1 && s.detail_server == (int)ServerRoute::Kind::NoCase);
            CHECK(s.composer_server == (int)ServerRoute::Kind::Arm);
            CHECK(s.server_warns == 0);
        }
        CHECK(no_window_left());
        cfg.host_build.clear();
        cfg.select_seq = ~0ull;
        cfg.compose = ComposeInit{};
        std::printf("ui: server reference done\n");

        PatchRule pr;
        pr.name = "serial";
        pr.dir = Dir::C2S;
        pr.main = 4;
        pr.sub = 1;
        pr.kind = PatchRule::Kind::Write;
        pr.write_off = 13;
        pr.write_bytes = {0x39, 0x30};
        cfg.compose = ComposeInit{};
        cfg.rules = {pr};
        cfg.set_rules = fake_set_rules;
        cfg.arm_rules = fake_arm;
        cfg.rule_stats = fake_rule_stats;
        cfg.rules_confirmed = true;
        cfg.rules_tick = true;
        cfg.select_seq = 0;
        make_source(10);
        g_src[0].edited = true;
        g_src[0].before = g_src[0].bytes;
        g_src[0].bytes[13] = 0x39;
        g_src[0].bytes[14] = 0x30;
        g_src[0].bytes[21] = 0x03;
        g_arm.clear();
        const bool up13 = ui_start(cfg);
        CHECK(up13);
        if (up13) {
            CHECK(wait_for(10, 2));
        }
        ui_stop();
        if (up13) {
            const UiStats s = ui_stats();
            CHECK(s.rule_arms == 1 && s.rule_asks == 0);
            CHECK(g_arm.size() == 2 && g_arm[0] && !g_arm[1]);
            CHECK(s.detail_seq == 0 && s.detail_edits == 2);
            CHECK(starts_with(g_log, "#0 t+0.000ms C2S (4,1) size=22 _move_request_clzo ok edited\n"
                                     "    edited +000D 2: 00 00 -> 39 30\n"
                                     "    edited +0015 1: 00 -> 03\n"));
        }
        CHECK(no_window_left());
        cfg.rules_confirmed = false;
        make_source(10);
        g_arm.clear();
        const bool up14 = ui_start(cfg);
        CHECK(up14);
        if (up14) {
            CHECK(wait_for(10, 2));
        }
        ui_stop();
        if (up14) {
            const UiStats s = ui_stats();
            CHECK(s.rule_asks == 1 && s.rule_arms == 0);
            CHECK(g_arm.empty());
        }
        CHECK(no_window_left());
        cfg.rules_tick = false;
        cfg.select_seq = ~0ull;
        std::printf("ui: rules done\n");

        cfg.rules = {pr};
        cfg.save_rules = fake_save;
        cfg.rules_confirmed = false;
        cfg.rules_tick = false;
        cfg.select_seq = 0;
        cfg.rules_edit = RulesEditInit{};
        cfg.rules_edit.open = true;
        cfg.rules_edit.from_row = 0;
        cfg.rules_edit.from_field = "dwSerial";
        cfg.rules_edit.apply = true;
        cfg.rules_edit.save = true;
        make_source(10);
        g_arm.clear();
        g_setCalls.clear();
        g_saveCalls.clear();
        const bool up15 = ui_start(cfg);
        CHECK(up15);
        if (up15) {
            CHECK(wait_for(10, 2));
        }
        ui_stop();
        if (up15) {
            const UiStats s = ui_stats();
            CHECK(s.rules_editor_frames >= 1 && s.rules_added == 2 && s.editor_rules == 3);
            CHECK(s.rule_applies == 1 && s.rule_apply_asks == 0 && s.rule_saves == 1 && s.rule_arms == 0);
            CHECK(g_arm.empty());
            CHECK(g_setCalls.size() == 1 && g_saveCalls.size() == 1);
            if (g_setCalls.size() == 1 && g_setCalls[0].size() == 3) {
                const std::vector<PatchRule>& l = g_setCalls[0];
                CHECK(l[0] == pr);
                CHECK(l[1].name == "_move_request_clzo" && l[1].enabled && l[1].dir == Dir::C2S && l[1].main == 4 &&
                      l[1].sub == 1 && l[1].kind == PatchRule::Kind::Write && l[1].write_off == 0 &&
                      (l[1].write_bytes == std::vector<uint16_t>{0x01, 0, 0, 0, 0, 0, 0, 0}) && l[1].match_pat.empty());
                CHECK(l[2].name == "_move_request_clzo.dwSerial" && l[2].dir == Dir::C2S && l[2].main == 4 &&
                      l[2].sub == 1 && l[2].write_off == 13 && (l[2].write_bytes == std::vector<uint16_t>{0, 0, 0, 0}));
                if (g_saveCalls.size() == 1) {
                    CHECK(g_saveCalls[0] == l);
                }
            } else {
                CHECK(false);
            }
        }
        CHECK(no_window_left());
        cfg.rules_confirmed = true;
        cfg.rules_tick = true;
        cfg.select_seq = ~0ull;
        cfg.rules_edit = RulesEditInit{};
        cfg.rules_edit.open = true;
        cfg.rules_edit.from_row = 0;
        cfg.rules_edit.apply = true;
        make_source(10);
        g_arm.clear();
        g_setCalls.clear();
        g_saveCalls.clear();
        const bool up16 = ui_start(cfg);
        CHECK(up16);
        if (up16) {
            CHECK(wait_for(10, 2));
        }
        ui_stop();
        if (up16) {
            const UiStats s = ui_stats();
            CHECK(s.rule_arms == 1 && s.rule_apply_asks == 1 && s.rule_applies == 0 && s.rules_added == 1);
            CHECK(g_setCalls.empty() && g_saveCalls.empty());
            CHECK(g_arm.size() == 2 && g_arm[0] && !g_arm[1]);
        }
        CHECK(no_window_left());
        cfg.rules_edit = RulesEditInit{};
        cfg.save_rules = nullptr;
        cfg.rules_tick = false;
        cfg.rules_confirmed = false;
        std::printf("ui: rules editor done\n");
        cfg.select_seq = ~0ull;
        cfg.script = ScriptInit{};
        cfg.script.code = "local n = 0\n"
                          "on_packet(function(p) n = n + 1 if n == 10 then log('ten', p.seq, p.dir) end end)\n";
        cfg.script.run = true;
        cfg.script.confirmed = true;
        cfg.script.open = true;
        make_source(10);
        const bool up17 = ui_start(cfg);
        CHECK(up17);
        if (up17) {
            CHECK(wait_for(10, 2));
        }
        ui_stop();
        if (up17) {
            const UiStats s = ui_stats();
            CHECK(s.script_runs == 1 && s.script_asks == 0);
            CHECK(s.script_packets == 10 && s.script_callbacks == 10 && s.script_skipped == 0);
            CHECK(s.script_lines == 1 && s.script_trips == 0 && s.script_errors == 0);
            CHECK(s.script_frames >= 1);
            CHECK(s.script_state == 0);
            CHECK(s.ingested == 10 && s.frames >= 1);
        }
        CHECK(no_window_left());
        cfg.script.code = "on_packet(function(p) while true do end end)";
        cfg.script.limits.max_instructions = 100000;
        cfg.script.limits.hook_every = 1000;
        make_source(10);
        const bool up18 = ui_start(cfg);
        CHECK(up18);
        if (up18) {
            CHECK(wait_for(10, 2));
        }
        ui_stop();
        if (up18) {
            const UiStats s = ui_stats();
            CHECK(s.script_runs == 1 && s.script_trips == 1 && s.script_packets == 1);
            CHECK(s.script_state == 3);
            CHECK(s.ingested == 10 && s.rows == 10 && s.frames >= 1);
        }
        CHECK(no_window_left());
        cfg.script.limits = ScriptLimits{};
        cfg.script.code = "log('must not run')";
        cfg.script.confirmed = false;
        make_source(10);
        const bool up19 = ui_start(cfg);
        CHECK(up19);
        if (up19) {
            CHECK(wait_for(10, 2));
        }
        ui_stop();
        if (up19) {
            const UiStats s = ui_stats();
            CHECK(s.script_asks == 1 && s.script_runs == 0 && s.script_lines == 0 && s.script_state == 0);
        }
        CHECK(no_window_left());
        cfg.script = ScriptInit{};
        std::printf("ui: script done\n");

        cfg.select_seq = ~0ull;
        cfg.compose = ComposeInit{};
        cfg.compose.confirmed = true;
        cfg.script = ScriptInit{};
        cfg.script.code =
            "log(send_to_server(4, 1, make('_move_request_clzo', {byMoveType = 1, dwSerial = 0x01020304})))\n"
            "on_packet(function(p) if p.seq == 5 then log(inject_to_client(p.main, p.sub, p.bytes)) end end)\n";
        cfg.script.run = true;
        cfg.script.confirmed = true;
        make_source(10);
        g_queue.clear();
        const bool up20 = ui_start(cfg);
        CHECK(up20);
        if (up20) {
            CHECK(wait_for(10, 2));
        }
        ui_stop();
        if (up20) {
            const UiStats s = ui_stats();
            CHECK(s.script_runs == 1 && s.script_sent == 1 && s.script_injected == 1);
            CHECK(s.script_held == 0 && s.script_refused == 0 && s.script_lines == 2);
            CHECK(s.queued == 2 && s.confirm_asks == 0);
            CHECK(g_queue.size() == 2);
            if (g_queue.size() == 2) {
                std::vector<uint8_t> mv(22, 0);
                mv[0] = 0x01;
                mv[13] = 0x04;
                mv[14] = 0x03;
                mv[15] = 0x02;
                mv[16] = 0x01;
                CHECK(g_queue[0].dir == Dir::C2S && g_queue[0].main == 4 && g_queue[0].sub == 1 &&
                      g_queue[0].bytes == mv);
                CHECK(g_queue[1].dir == Dir::S2C && g_queue[1].main == 250 && g_queue[1].sub == 250 &&
                      (g_queue[1].bytes == std::vector<uint8_t>{0x01, 0x02, 0x03, 0x04}));
            }
        }
        CHECK(no_window_left());
        cfg.compose = ComposeInit{};
        cfg.compose.answer = 2;
        cfg.script.code =
            "on_packet(function(p) if p.dir == 'C2S' then log(send_to_server(p.main, p.sub, p.bytes)) end end)";
        make_source(10);
        g_drainCap = 5;
        g_queue.clear();
        const bool up21 = ui_start(cfg);
        CHECK(up21);
        if (up21) {
            CHECK(wait_for(10, 2));
        }
        ui_stop();
        if (up21) {
            const UiStats s = ui_stats();
            CHECK(s.confirm_asks == 1 && s.queued == 0 && g_queue.empty());
            CHECK(s.script_held == 1 && s.script_refused == 2 && s.script_sent == 0);
            CHECK(s.script_packets == 5 && s.script_state == 0);
        }
        CHECK(no_window_left());
        cfg.compose.answer = 1;
        make_source(10);
        g_drainCap = 5;
        g_queue.clear();
        const bool up22 = ui_start(cfg);
        CHECK(up22);
        if (up22) {
            CHECK(wait_for(10, 2));
        }
        ui_stop();
        if (up22) {
            const UiStats s = ui_stats();
            CHECK(s.confirm_asks == 1 && s.queued == 3 && g_queue.size() == 3);
            CHECK(s.script_held == 1 && s.script_refused == 2 && s.script_sent == 2 && s.script_packets == 10);
            for (const QueuedCall& q : g_queue) {
                CHECK(q.dir == Dir::C2S && q.main == 4 && q.sub == 1 && q.bytes.size() == 22);
            }
        }
        CHECK(no_window_left());
        g_drainCap = SIZE_MAX;
        cfg.compose = ComposeInit{};
        cfg.script = ScriptInit{};
        std::printf("ui: script io done\n");

        const std::string add_x =
            "rules.add{name = 'x', dir = 'S2C', main = 250, action = {offset = 0, hexReplace = 'FF'}}";
        cfg.select_seq = ~0ull;
        cfg.compose = ComposeInit{};
        cfg.rules = {pr};
        cfg.rules_confirmed = false;
        cfg.rules_tick = false;
        cfg.rules_edit = RulesEditInit{};
        cfg.rules_edit.open = true;
        cfg.script = ScriptInit{};
        cfg.script.code = "log(" + add_x + ")";
        cfg.script.run = true;
        cfg.script.confirmed = true;
        make_source(10);
        g_arm.clear();
        g_setCalls.clear();
        const bool up23 = ui_start(cfg);
        CHECK(up23);
        if (up23) {
            CHECK(wait_for(10, 2));
        }
        ui_stop();
        if (up23) {
            const UiStats s = ui_stats();
            CHECK(s.rule_script_changes == 1 && s.rule_script_disarms == 0 && s.rule_script_undos == 1);
            CHECK(s.editor_rules == 2 && s.script_lines == 1);
            CHECK(g_arm.empty());
            CHECK(g_setCalls.size() == 2);
            if (g_setCalls.size() == 2) {
                CHECK(g_setCalls[0].size() == 2 && g_setCalls[0][0] == pr);
                if (g_setCalls[0].size() == 2) {
                    const PatchRule& x = g_setCalls[0][1];
                    CHECK(x.name == "x" && x.enabled && x.dir == Dir::S2C && x.main == 250 && x.sub == -1 &&
                          x.kind == PatchRule::Kind::Write && x.write_off == 0 &&
                          (x.write_bytes == std::vector<uint16_t>{0xFF}));
                }
                CHECK(g_setCalls[1].size() == 1 && g_setCalls[1][0] == pr);
            }
        }
        CHECK(no_window_left());
        cfg.rules_confirmed = true;
        cfg.rules_tick = true;
        cfg.rules_edit = RulesEditInit{};
        cfg.script.code = "on_packet(function(p) if p.seq == 6 then log(" + add_x + ") end end)";
        make_source(10);
        g_drainCap = 5;
        g_arm.clear();
        g_setCalls.clear();
        const bool up24 = ui_start(cfg);
        CHECK(up24);
        if (up24) {
            CHECK(wait_for(10, 2));
        }
        ui_stop();
        if (up24) {
            const UiStats s = ui_stats();
            CHECK(s.rule_arms == 1 && s.rule_script_disarms == 1 && s.rule_script_changes == 1 &&
                  s.rule_script_undos == 1);
            CHECK(g_arm.size() == 2 && g_arm[0] && !g_arm[1]);
            CHECK(g_setCalls.size() == 2 && g_setCalls[0].size() == 2 && g_setCalls[1].size() == 1);
            CHECK(s.script_lines == 1);
        }
        CHECK(no_window_left());
        cfg.rules_script_ok = true;
        cfg.script.code = "local n = 0\n"
                          "on_tick(1, function() n = n + 1 if n == 1 then log('tick') end end)\n"
                          "on_packet(function(p) if p.seq == 6 then log(" +
                          add_x + ") end end)";
        make_source(10);
        g_drainCap = 5;
        g_arm.clear();
        g_setCalls.clear();
        const bool up25 = ui_start(cfg);
        CHECK(up25);
        if (up25) {
            CHECK(wait_for(10, 2));
            for (int i = 0; i < 500 && ui_stats().script_ticks == 0; ++i) {
                Sleep(10);
            }
        }
        ui_stop();
        if (up25) {
            const UiStats s = ui_stats();
            CHECK(s.rule_arms == 1 && s.rule_script_disarms == 0 && s.rule_script_changes == 1 &&
                  s.rule_script_undos == 1);
            CHECK(g_arm.size() == 2 && g_arm[0] && !g_arm[1]);
            CHECK(g_setCalls.size() == 2 && g_setCalls[0].size() == 2 && g_setCalls[1].size() == 1);
            CHECK(s.script_ticks >= 1 && s.script_timers == 0 && s.script_lines == 2);
        }
        CHECK(no_window_left());
        g_drainCap = SIZE_MAX;
        cfg.rules_script_ok = false;
        cfg.rules_tick = false;
        cfg.rules_confirmed = false;
        cfg.script = ScriptInit{};
        std::printf("ui: script rules done\n");
    }

    if (g_fail) {
        std::printf("FAILED (%d failure(s))\n", g_fail);
    } else {
        std::printf("PASSED (0 failure(s))\n");
    }
    return g_fail ? 1 : 0;
}
