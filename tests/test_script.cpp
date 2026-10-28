#include "proto/packet_db.h"
#include "script/script_host.h"
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

using namespace rfte;
using Kind = ScriptLine::Kind;

static int g_fail = 0;
#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_fail;                                                   \
        }                                                               \
    } while (0)

static std::vector<std::string> g_sink;

static void sink(const char* line) {
    g_sink.push_back(line);
}

static bool has_line(const ScriptHost& sh, Kind k, const std::string& text) {
    for (const ScriptLine& l : sh.lines()) {
        if (l.kind == k && l.text == text) {
            return true;
        }
    }
    return false;
}

static bool has_prefix(const ScriptHost& sh, Kind k, const std::string& p) {
    for (const ScriptLine& l : sh.lines()) {
        if (l.kind == k && l.text.rfind(p, 0) == 0) {
            return true;
        }
    }
    return false;
}

static int index_of(const ScriptHost& sh, const std::string& text) {
    int i = 0;
    for (const ScriptLine& l : sh.lines()) {
        if (l.text == text) {
            return i;
        }
        ++i;
    }
    return -1;
}

static bool contains(const std::string& s, const char* sub) {
    return s.find(sub) != std::string::npos;
}

static double ms_since(std::chrono::steady_clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
}

static double g_now = 0;

static double fake_now() {
    return g_now;
}

static const std::vector<uint8_t> kMove = {0x01, 0x00, 0x00, 0xC0, 0x3F, 0,    0,    0,    0,    0,    0,
                                           0,    0,    0x04, 0x03, 0x02, 0x01, 0xFE, 0xFF, 0x00, 0x00, 0x03};

static ScriptPacket packet(const std::vector<uint8_t>& b, Dir d, uint8_t main, uint8_t sub, const char* name,
                           const char* status) {
    ScriptPacket p;
    p.seq = 7;
    p.t_ms = 1.5;
    p.dir = d;
    p.main = main;
    p.sub = sub;
    p.size = (uint16_t)b.size();
    p.bytes = b.data();
    p.len = b.size();
    p.name = name;
    p.status = status;
    return p;
}

static ScriptPacket move_packet() {
    ScriptPacket p = packet(kMove, Dir::C2S, 4, 1, "_move_request_clzo", "ok");
    p.layout = "_move_request_clzo";
    return p;
}

static ScriptLimits small_limits() {
    ScriptLimits l;
    l.max_instructions = 200000;
    l.max_ms = 60000;
    l.hook_every = 1000;
    return l;
}

static bool trips_in_callback(ScriptHost& sh, const char* code) {
    if (!sh.run(code, "=trip")) {
        return false;
    }
    const auto t0 = std::chrono::steady_clock::now();
    sh.begin_frame();
    sh.on_packet(move_packet());
    return sh.state() == ScriptState::Tripped && ms_since(t0) < 5000.0;
}

int main(int argc, char** argv) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc < 3) {
        std::printf("usage: test_script <RFTrafficEditor.example.lua> <packet_db.json>\nFAILED (1 failure(s))\n");
        return 1;
    }
    PacketDb db;
    std::string dberr;
    const bool db_ok = db.load(argv[2], &dberr);
    if (!db_ok) {
        std::printf("FAIL: cannot load %s: %s\n", argv[2], dberr.c_str());
    }
    CHECK(db_ok);

    {
        g_sink.clear();
        ScriptHost sh(ScriptLimits{}, sink);
        CHECK(sh.state() == ScriptState::Stopped && !sh.running());
        CHECK(sh.limits().max_ms == 100 && sh.limits().max_instructions == 20000000);
        CHECK(std::string(script_state_name(ScriptState::Running)) == "RUNNING");
        const char* code =
            "log('up', type(os), type(io), type(package), type(require), type(dofile), type(loadfile), type(load), "
            "type(debug))\n"
            "log('libs', type(string), type(table), type(math), type(utf8), type(coroutine), type(on_packet))\n"
            "print('via print', 1, 2.5, true, nil)\n"
            "on_packet(function(p)\n"
            "  log(p.seq, p.t, p.dir, p.main, p.sub, p.size, p.len, p.name, p.status, p.edited, p.tool)\n"
            "  log(p:u8(0), p:i8(17), p:u16(13), p:i16(17), p:u32(13), p:i32(17), p:f32(1), p:u32(19), p:u8(-1), "
            "p:u8(22))\n"
            "  log(p:hex(13, 4), '|', p:hex(20), '|', p:hex(30), '|', #p.bytes)\n"
            "  log(p:hex())\n"
            "end)\n"
            "on_packet(function(p) log('second', p.seq) end)\n";
        CHECK(ScriptHost::check(code, "=bind").empty());
        CHECK(sh.run(code, "=bind"));
        CHECK(sh.running());
        CHECK(has_line(sh, Kind::Log, "up nil nil nil nil nil nil nil nil"));
        CHECK(has_line(sh, Kind::Log, "libs table table table table table function"));
        CHECK(has_line(sh, Kind::Log, "via print 1 2.5 true nil"));
        CHECK(has_prefix(sh, Kind::Info, "started bind -- 2 on_packet handler(s)"));
        ScriptPacket p = move_packet();
        p.tool = true;
        sh.begin_frame();
        sh.on_packet(p);
        CHECK(sh.running());
        CHECK(has_line(sh, Kind::Log, "7 1.5 C2S 4 1 22 22 _move_request_clzo ok false true"));
        CHECK(has_line(sh, Kind::Log, "1 -2 772 -2 16909060 65534 1.5 nil nil nil"));
        CHECK(has_line(sh, Kind::Log, "04 03 02 01 | 00 03 |  | 22"));
        const std::string all = "01 00 00 C0 3F 00 00 00 00 00 00 00 00 04 03 02 01 FE FF 00 00 03";
        CHECK(has_line(sh, Kind::Log, all));
        CHECK(has_line(sh, Kind::Log, "second 7"));
        CHECK(index_of(sh, all) >= 0 && index_of(sh, all) < index_of(sh, "second 7"));
        const ScriptStats s = sh.stats();
        CHECK(s.handlers == 2 && s.packets == 1 && s.callbacks == 2 && s.lines == 8 && s.runs == 1);
        CHECK(s.mem_bytes > 0 && s.skipped == 0);
        CHECK(g_sink.size() == sh.line_seq());
        sh.stop("test");
        CHECK(sh.state() == ScriptState::Stopped);
        CHECK(has_line(sh, Kind::Info, "stopped (test) -- 1 packet(s), 2 callback(s) this run"));
        const uint64_t seq = sh.line_seq();
        sh.stop("again");
        sh.on_packet(p);
        CHECK(sh.line_seq() == seq && sh.stats().packets == 1 && sh.stats().mem_bytes == 0);
        CHECK(sh.run("n = (n or 0) + 1 log('n', n)", "=rerun"));
        CHECK(sh.run("n = (n or 0) + 1 log('n', n)", "=rerun"));
        int ones = 0;
        for (const ScriptLine& l : sh.lines()) {
            ones += l.text == "n 1";
        }
        CHECK(ones == 2 && !has_line(sh, Kind::Log, "n 2"));
        CHECK(has_prefix(sh, Kind::Info, "stopped (a new Run)"));
        CHECK(sh.stats().runs == 3);
        sh.note("a note");
        CHECK(sh.lines().back().kind == Kind::Info && sh.lines().back().text == "a note");
        sh.clear_lines();
        CHECK(sh.lines().empty());
    }
    std::printf("script: bind done\n");

    {
        ScriptHost sh(ScriptLimits{}, sink);
        CHECK(contains(ScriptHost::check("x = = 1", "=syn"), "syn:1:"));
        CHECK(ScriptHost::check("", "=empty").empty());
        CHECK(!sh.run("x = = 1", "=syn"));
        CHECK(sh.state() == ScriptState::Failed && contains(sh.last_error(), "syn:1:"));
        CHECK(has_prefix(sh, Kind::Error, "FAILED (syntax): syn:1:"));
        CHECK(sh.run("on_packet(function(p) error('boom') end)", "=err"));
        sh.begin_frame();
        sh.on_packet(move_packet());
        CHECK(sh.state() == ScriptState::Failed && contains(sh.last_error(), "err:1: boom"));
        CHECK(has_prefix(sh, Kind::Error, "FAILED (in on_packet, packet #7 C2S (4,1)): err:1: boom"));
        bool trace = false;
        for (const ScriptLine& l : sh.lines()) {
            trace |= l.kind == Kind::Error && contains(l.text, "stack traceback");
        }
        CHECK(trace);
        CHECK(sh.stats().mem_bytes == 0);
        CHECK(!sh.run("error('top')", "=top") && contains(sh.last_error(), "top:1: top"));
        CHECK(!sh.run("on_packet(42)", "=arg") && contains(sh.last_error(), "bad argument #1"));
        CHECK(!sh.run("error({})", "=tbl") && contains(sh.last_error(), "error object is a table value"));
        CHECK(sh.stats().errors == 5 && sh.stats().trips == 0);
    }
    std::printf("script: errors done\n");

    {
        ScriptHost sh(small_limits(), sink);
        CHECK(trips_in_callback(sh, "on_packet(function(p) while true do end end)"));
        CHECK(contains(sh.last_error(), "more than 200000 Lua instructions"));
        CHECK(has_prefix(sh, Kind::Error, "STOPPED by the watchdog -- more than 200000 Lua instructions"));
        CHECK(sh.stats().trips == 1 && sh.stats().packets == 1 && sh.stats().mem_bytes == 0);
        sh.on_packet(move_packet());
        CHECK(sh.stats().packets == 1);
        CHECK(trips_in_callback(
            sh, "on_packet(function(p) while true do pcall(function() while true do end end) end end)"));
        CHECK(trips_in_callback(sh, "on_packet(function(p) return pcall(function() while true do end end) end)"));
        CHECK(trips_in_callback(sh, "on_packet(function(p) while true do xpcall(function() while true do end end, "
                                    "function(e) return e end) end end)"));
        CHECK(trips_in_callback(sh, "on_packet(function(p) while true do coroutine.resume(coroutine.create("
                                    "function() while true do end end)) end end)"));
        CHECK(trips_in_callback(sh, "on_packet(function(p) local co = coroutine.wrap(function() while true do end end) "
                                    "while true do pcall(co) end end)"));
        CHECK(sh.stats().trips == 6);
        auto t0 = std::chrono::steady_clock::now();
        CHECK(!sh.run("while true do end", "=top"));
        CHECK(sh.state() == ScriptState::Tripped && ms_since(t0) < 5000.0 && sh.stats().trips == 7);
        CHECK(contains(sh.last_error(), "(in the top level of top)"));
        t0 = std::chrono::steady_clock::now();
        CHECK(!sh.run("setmetatable({}, {__gc = function() while true do end end})", "=gc"));
        CHECK(sh.state() == ScriptState::Failed && contains(sh.last_error(), "__gc finalizers are not allowed"));
        CHECK(sh.run("local t = setmetatable({}, {__index = function() return 5 end}) log('mt', t.x) "
                     "getmetatable(t).__gc = function() while true do end end collectgarbage()",
                     "=mt"));
        CHECK(has_line(sh, Kind::Log, "mt 5"));
        sh.stop("test");
        CHECK(sh.state() == ScriptState::Stopped && ms_since(t0) < 5000.0);
    }
    {
        ScriptLimits l;
        l.max_instructions = UINT64_MAX;
        l.max_ms = 30;
        l.hook_every = 1000;
        ScriptHost sh(l, sink);
        const auto t0 = std::chrono::steady_clock::now();
        CHECK(trips_in_callback(sh, "on_packet(function(p) local x = 0 while true do x = x + 1 end end)"));
        CHECK(ms_since(t0) >= 30.0);
        CHECK(contains(sh.last_error(), "(limit 30 ms)"));
    }
    std::printf("script: watchdog done\n");

    {
        ScriptLimits l;
        l.max_bytes = size_t(4) << 20;
        ScriptHost sh(l, sink);
        CHECK(sh.run("on_packet(function(p) local t = {} for i = 1, 1e7 do t[i] = i end end)", "=mem"));
        sh.begin_frame();
        sh.on_packet(move_packet());
        CHECK(sh.state() == ScriptState::Failed);
        CHECK(contains(sh.last_error(), "not enough memory -- the script's VM is capped at 4 MB"));
        CHECK(sh.stats().mem_bytes == 0);
        CHECK(!sh.run("local s = string.rep('x', 1 << 28)", "=rep"));
        CHECK(sh.state() == ScriptState::Failed && contains(sh.last_error(), "not enough memory"));
        CHECK(sh.run("log('fine')", "=ok"));
        CHECK(sh.running() && sh.stats().mem_bytes > 0 && sh.stats().mem_bytes < l.max_bytes);
    }
    std::printf("script: memory done\n");

    {
        ScriptLimits l;
        l.frame_ms = 1;
        l.max_ms = 10000;
        l.max_instructions = 1000000000ull;
        ScriptHost sh(l, sink);
        CHECK(sh.run("on_packet(function(p) for i = 1, 5000000 do end end)", "=slow"));
        sh.begin_frame();
        for (int i = 0; i < 50; ++i) {
            sh.on_packet(move_packet());
        }
        const ScriptStats s = sh.stats();
        CHECK(sh.running());
        CHECK(s.packets >= 1 && s.skipped >= 1 && s.packets + s.skipped == 50);
        CHECK(has_prefix(sh, Kind::Info, "frame budget: over 1 ms"));
        sh.begin_frame();
        sh.on_packet(move_packet());
        CHECK(sh.stats().packets == s.packets + 1);
    }
    std::printf("script: budget done\n");

    {
        ScriptLimits l;
        l.max_lines = 10;
        ScriptHost sh(l, sink);
        CHECK(sh.run("for i = 1, 25 do log('line', i) end log(string.rep('x', 10000))", "=cap"));
        CHECK(sh.lines().size() == 10);
        CHECK(has_line(sh, Kind::Log, "line 25") && !has_line(sh, Kind::Log, "line 1"));
        CHECK(sh.lines().back().kind == Kind::Info);
        CHECK(sh.stats().lines == 26);
        bool cut = false;
        for (const ScriptLine& x : sh.lines()) {
            cut |= x.text.size() == 4096 + 9 && x.text.compare(4096, 9, " ...(cut)") == 0;
        }
        CHECK(cut);
    }
    std::printf("script: output done\n");

    {
        std::ifstream f(argv[1], std::ios::binary);
        const std::string code((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        CHECK(!code.empty());
        CHECK(ScriptHost::check(code, "@RFTrafficEditor.example.lua").empty());
        std::vector<std::pair<Dir, std::string>> out;
        std::vector<PatchRule> live;
        std::vector<std::string> changes;
        ScriptIo io;
        io.db = &db;
        io.send = [&](const std::string&, Dir d, uint8_t m, uint8_t s, const uint8_t* p, size_t n) {
            out.emplace_back(d, std::to_string(m) + "," + std::to_string(s) + ":" +
                                    std::string(reinterpret_cast<const char*>(p), n));
            return ScriptSend::Queued;
        };
        io.rules = [&]() {
            return ScriptRulesView{&live, false};
        };
        io.set_rules = [&](const std::string&, std::vector<PatchRule> l, const std::string& c) {
            live = std::move(l);
            changes.push_back(c);
            return ScriptRules::Applied;
        };
        ScriptHost sh(ScriptLimits{}, sink);
        sh.set_io(io);
        sh.set_clock(fake_now);
        g_now = 0;
        CHECK(sh.run(code, "@RFTrafficEditor.example.lua"));
        CHECK(has_line(sh, Kind::Log,
                       "example script up: chat (main 2) is logged, every 50th move summarised, packets "
                       "counted per minute; say '!echo <text>' and the script injects <text> back as a "
                       "chat line, '!upper' and for 30 s your 'hello' goes out as 'HELLO' (a patch rule: "
                       "only while Rules is armed)"));
        CHECK(has_prefix(sh, Kind::Info, "started RFTrafficEditor.example.lua -- 1 on_packet handler(s), 1 timer(s)"));
        const std::vector<uint8_t> chat = {0x05, 'h', 'e', 'l', 'l', 'o'};
        const std::vector<uint8_t> echo = {0x08, '!', 'e', 'c', 'h', 'o', ' ', 'h', 'i'};
        const std::vector<uint8_t> up = {0x06, '!', 'u', 'p', 'p', 'e', 'r'};
        sh.begin_frame();
        sh.on_packet(packet(chat, Dir::C2S, 2, 2, "_chat_circle_request_clzo", "mismatch"));
        sh.on_packet(move_packet());
        sh.on_packet(move_packet());
        sh.on_packet(packet(echo, Dir::C2S, 2, 2, "_chat_circle_request_clzo", "mismatch"));
        ScriptPacket mine = packet(echo, Dir::C2S, 2, 2, "_chat_circle_request_clzo", "mismatch");
        mine.tool = true;
        sh.on_packet(mine);
        sh.on_packet(packet(up, Dir::C2S, 2, 2, "_chat_circle_request_clzo", "mismatch"));
        CHECK(sh.running());
        CHECK(has_line(sh, Kind::Log, "C2S (2,2) _chat_circle_request_clzo 6 B: .hello"));
        CHECK(has_line(sh, Kind::Log, "move #1: dwSerial 16909060 at (1.5, 0.0, 0.0)"));
        CHECK(!has_prefix(sh, Kind::Log, "move #2"));
        CHECK(has_line(sh, Kind::Log, "C2S (2,2) _chat_circle_request_clzo 9 B: .!echo hi"));
        CHECK(has_line(sh, Kind::Log, "echo: true"));
        std::string want("\x01\x04\x03\x02\x01"
                         "script",
                         11);
        want.append(11, '\0');
        want += std::string("\0\0\0\x02"
                            "hi"
                            "\0",
                            7);
        CHECK(out.size() == 1);
        if (out.size() == 1) {
            CHECK(out[0].first == Dir::S2C && out[0].second == "2,10:" + want);
        }
        CHECK(has_line(sh, Kind::Log, "C2S (2,2) _chat_circle_request_clzo 7 B: .!upper"));
        CHECK(has_line(sh, Kind::Log, "upper: on for 30 s -- tick Rules (toolbar) to arm it"));
        CHECK(changes.size() == 1 && live.size() == 1);
        if (changes.size() == 1) {
            CHECK(changes[0] ==
                  "added #1 \"example: hello -> HELLO\": C2S (2,*) replace 68 65 6C 6C 6F -> 48 45 4C 4C 4F");
        }
        if (live.size() == 1) {
            CHECK(live[0].name == "example: hello -> HELLO" && live[0].enabled && live[0].dir == Dir::C2S &&
                  live[0].main == 2 && live[0].sub == -1 && live[0].kind == PatchRule::Kind::Replace &&
                  (live[0].find_bytes == std::vector<uint16_t>{0x68, 0x65, 0x6C, 0x6C, 0x6F}) &&
                  (live[0].repl_bytes == std::vector<uint16_t>{0x48, 0x45, 0x4C, 0x4C, 0x4F}));
        }
        CHECK(sh.stats().timers == 2);
        g_now = 29999;
        sh.begin_frame();
        sh.tick();
        CHECK(!has_prefix(sh, Kind::Log, "upper: off") && !has_prefix(sh, Kind::Log, "last minute"));
        g_now = 30000;
        sh.begin_frame();
        sh.tick();
        CHECK(has_line(sh, Kind::Log, "upper: off true"));
        CHECK(changes.size() == 2 && live.size() == 1 && !live[0].enabled);
        if (changes.size() == 2) {
            CHECK(changes[1] == "disabled #1 \"example: hello -> HELLO\"");
        }
        g_now = 60000;
        sh.begin_frame();
        sh.tick();
        CHECK(has_line(sh, Kind::Log, "last minute: 5 C2S / 0 S2C packets"));
        const ScriptStats st = sh.stats();
        CHECK(st.lines == 9 && st.injected == 1 && st.sent == 0 && st.rule_changes == 2 && st.ticks == 2 &&
              st.timers == 1);
    }
    std::printf("script: example done\n");

    {
        struct Call {
            std::string who;
            Dir dir;
            int main, sub;
            std::string bytes;
        };

        std::vector<Call> calls;
        ScriptSend answer = ScriptSend::Queued;
        ScriptLimits l;
        l.max_actions_per_s = 5;
        ScriptHost sh(l, sink);
        CHECK(sh.run("log(send_to_server(4, 1, 'ab')) log(inject_to_client(3, 4))", "=noio"));
        CHECK(has_line(sh, Kind::Log, "false not queued: no action queue (the hooks are not installed)"));
        CHECK(has_line(sh, Kind::Info,
                       "send_to_server(4,1) 2 B: not queued: no action queue (the hooks are not "
                       "installed) -- the call returned false (said once per run)"));
        CHECK(!has_prefix(sh, Kind::Info, "inject_to_client(3,4)"));
        CHECK(sh.stats().refused == 2 && sh.stats().sent == 0 && sh.stats().injected == 0);
        ScriptIo io;
        io.send = [&](const std::string& who, Dir d, uint8_t m, uint8_t s, const uint8_t* p, size_t n) {
            calls.push_back({who, d, m, s, std::string(reinterpret_cast<const char*>(p), n)});
            return answer;
        };
        sh.set_io(io);
        CHECK(sh.run("log('c2s', send_to_server(4, 1, '\\1\\0\\255')) log('s2c', inject_to_client(250, 250))", "=io"));
        CHECK(calls.size() == 2);
        if (calls.size() == 2) {
            CHECK(calls[0].who == "io" && calls[0].dir == Dir::C2S && calls[0].main == 4 && calls[0].sub == 1 &&
                  calls[0].bytes == std::string("\x01\x00\xFF", 3));
            CHECK(calls[1].who == "io" && calls[1].dir == Dir::S2C && calls[1].main == 250 && calls[1].sub == 250 &&
                  calls[1].bytes.empty());
        }
        CHECK(has_line(sh, Kind::Log, "c2s true") && has_line(sh, Kind::Log, "s2c true"));
        CHECK(sh.stats().sent == 1 && sh.stats().injected == 1 && sh.stats().held == 0 && sh.stats().refused == 0);
        answer = ScriptSend::Held;
        CHECK(sh.run("log(inject_to_client(2, 10, 'x'))", "=held"));
        const std::string held = "held: the first inject to the client this session waits for Confirm in the tool "
                                 "window -- queued if confirmed, Cancel stops the script";
        CHECK(has_line(sh, Kind::Log, "false " + held));
        CHECK(has_line(sh, Kind::Info, "inject_to_client(2,10) 1 B: " + held));
        CHECK(sh.stats().held == 1 && sh.stats().refused == 0);
        answer = ScriptSend::Waiting;
        CHECK(sh.run("log(send_to_server(4, 1))", "=wait"));
        CHECK(has_line(sh, Kind::Log, "false not queued: a Confirm is open in the tool window"));
        answer = ScriptSend::Full;
        CHECK(sh.run("log(send_to_server(4, 1))", "=full"));
        CHECK(has_line(sh, Kind::Log,
                       "false not queued: the action queue is full (128 pending) -- it drains as the "
                       "game sends / receives"));
        CHECK(sh.stats().refused == 1);
        answer = ScriptSend::Queued;
        const size_t before = calls.size();
        CHECK(sh.run("log(send_to_server(4, 1, string.rep('x', 4097)))", "=long"));
        CHECK(has_line(sh, Kind::Log, "false not queued: longer than 4096 bytes") && calls.size() == before);
        CHECK(sh.run("local ok = 0 for i = 1, 7 do if send_to_server(4, 1) then ok = ok + 1 end end log('ok', ok) "
                     "log(send_to_server(4, 1))",
                     "=rate"));
        CHECK(has_line(sh, Kind::Log, "ok 5"));
        CHECK(has_line(sh, Kind::Log, "false not queued: over 5 sends / injects per second from this script"));
        CHECK(calls.size() == before + 5);
        CHECK(sh.stats().sent == 5 && sh.stats().refused == 3);
        CHECK(!sh.run("send_to_server(256, 1)", "=arg"));
        CHECK(contains(sh.last_error(), "bad argument #1") && contains(sh.last_error(), "main: 0..255"));
        CHECK(!sh.run("inject_to_client(1, -1)", "=arg"));
        CHECK(contains(sh.last_error(), "bad argument #2") && contains(sh.last_error(), "sub: 0..255"));
        CHECK(!sh.run("send_to_server(1, 1, 42)", "=arg"));
        CHECK(contains(sh.last_error(), "bad argument #3") && contains(sh.last_error(), "string expected, got number"));
        CHECK(sh.run("on_packet(function(p) if not p.tool then send_to_server(p.main, p.sub, p.bytes) end end)",
                     "=react"));
        ScriptPacket mp = move_packet();
        sh.begin_frame();
        sh.on_packet(mp);
        mp.tool = true;
        sh.on_packet(mp);
        CHECK(calls.size() == before + 6 && calls.back().bytes == std::string(kMove.begin(), kMove.end()));
        CHECK(sh.running() && sh.stats().sent == 1 && sh.stats().callbacks == 2);
    }
    std::printf("script: io done\n");

    {
        std::vector<std::string> sent;
        ScriptHost sh(ScriptLimits{}, sink);
        CHECK(sh.run("on_packet(function(p) log(p:field('dwSerial')) end)", "=nodb"));
        sh.begin_frame();
        sh.on_packet(move_packet());
        CHECK(has_line(sh, Kind::Log, "nil no packet db (packet_db.json was not loaded)"));
        CHECK(!sh.run("make('_move_request_clzo')", "=nodb"));
        CHECK(contains(sh.last_error(), "make: no packet db (packet_db.json was not loaded)"));
        ScriptIo io;
        io.db = &db;
        io.send = [&](const std::string&, Dir, uint8_t, uint8_t, const uint8_t* p, size_t n) {
            sent.emplace_back(reinterpret_cast<const char*>(p), n);
            return ScriptSend::Queued;
        };
        sh.set_io(io);
        CHECK(sh.run(
            "on_packet(function(p)\n"
            "  if p.layout == '' then log('none', #p:fields(), p:field('x'))\n"
            "  elseif p.layout == '_move_request_clzo' and p.size == 22 then\n"
            "    log(p.layout, p:field('byMoveType'), p:field('fCur[0]'), p:field('fCur[1]'), p:field('dwSerial'),"
            "        p:field('zTar[0]'), p:field('byDirect'))\n"
            "    local f = p:fields() log(#f, f[1], f[2], f[5], f[8])\n"
            "    log(p:field('nope'))\n"
            "  elseif p.layout == '_move_request_clzo' then log('short', p:field('byMoveType'), p:field('dwSerial'))\n"
            "  elseif p.layout == '_base_download_result_zocl' then\n"
            "    log('dl', p:field('wHP'), p:field('EquipList[2].wItemIndex'), p:field('fPos[1]'), "
            "p:field('dPvpPoint'),"
            "        p:field('EquipList[2].sTableCode'))\n"
            "  elseif p.layout == '_chat_lock_inform_zocl' then log('lock', p:field('bLock'))\n"
            "  else log('guid', p:field('wSeq'), p:field('byGuidReqMsg') == string.rep('\\171', 20))\n"
            "  end\n"
            "end)",
            "=field"));
        sh.begin_frame();
        sh.on_packet(move_packet());
        CHECK(has_line(sh, Kind::Log, "_move_request_clzo 1 1.5 0.0 16909060 -2 3"));
        CHECK(has_line(sh, Kind::Log, "8 byMoveType fCur[0] dwSerial byDirect"));
        CHECK(has_line(sh, Kind::Log, "nil no field 'nope' in _move_request_clzo -- p:fields() lists them"));
        const std::vector<uint8_t> four = {0x01, 0x02, 0x03, 0x04};
        ScriptPacket sp = packet(four, Dir::C2S, 4, 1, "_move_request_clzo", "mismatch");
        sp.layout = "_move_request_clzo";
        sh.on_packet(sp);
        CHECK(has_line(sh, Kind::Log, "short 1 nil the payload (4 B) ends before dwSerial"));
        sh.on_packet(packet(four, Dir::S2C, 250, 250, "", "unknown"));
        CHECK(has_line(sh, Kind::Log, "none 0 nil no layout: the packet db has none for this packet"));
        std::vector<uint8_t> dl(258, 0);
        dl[13] = 0xF4;
        dl[14] = 0x01;
        dl[96] = 0x34;
        dl[97] = 0x12;
        ScriptPacket dp = packet(dl, Dir::S2C, 3, 4, "_base_download_result_zocl", "ok");
        dp.layout = "_base_download_result_zocl";
        sh.on_packet(dp);
        CHECK(has_line(sh, Kind::Log, "dl 500 4660 0.0 0.0 0"));
        const std::vector<uint8_t> lock = {0x01};
        ScriptPacket lp = packet(lock, Dir::S2C, 2, 12, "_chat_lock_inform_zocl", "ok");
        lp.layout = "_chat_lock_inform_zocl";
        sh.on_packet(lp);
        CHECK(has_line(sh, Kind::Log, "lock true"));
        std::vector<uint8_t> guid(22, 0xAB);
        guid[0] = 0x07;
        guid[1] = 0x00;
        ScriptPacket gp = packet(guid, Dir::S2C, 9, 9, "_hs_msg_make_guid_req_msg_zocl", "ok");
        gp.layout = "_hs_msg_make_guid_req_msg_zocl";
        sh.on_packet(gp);
        CHECK(has_line(sh, Kind::Log, "guid 7 true"));
        CHECK(sh.running());
        CHECK(
            sh.run("send_to_server(4, 1, make('_move_request_clzo', {byMoveType = 1, fCur = {1.5, 0, 0}, dwSerial = "
                   "0x01020304,"
                   "                zTar = {-2, 0}, byDirect = 3}))\n"
                   "send_to_server(0, 0, make('_move_request_clzo'))\n"
                   "send_to_server(0, 1, make('_move_request_clzo', {['fCur[1]'] = '2', dwSerial = '0x10', byDirect = "
                   "true}))\n"
                   "send_to_server(0, 2, make('_chat_circle_request_clzo', {bySize = 5, wszChatData = 'a\\\\b\\0c'}))\n"
                   "send_to_server(0, 3, make('_base_download_result_zocl', {wHP = 500, EquipList = {[3] = {wItemIndex "
                   "= 0x1234}},"
                   "                fPos = {[2] = -1.25}}))\n"
                   "send_to_server(0, 4, make('_hs_msg_make_guid_req_msg_zocl', {wSeq = 7, byGuidReqMsg = "
                   "string.rep('\\171', 20)}))\n"
                   "send_to_server(0, 5, make('_chat_lock_inform_zocl', {bLock = true}))\n",
                   "=make"));
        CHECK(sent.size() == 7);
        if (sent.size() == 7) {
            CHECK(sent[0] == std::string(kMove.begin(), kMove.end()));
            CHECK(sent[1] == std::string(22, '\0'));
            std::string m2(22, '\0');
            m2[8] = '\x40';
            m2[13] = '\x10';
            m2[21] = '\x01';
            CHECK(sent[2] == m2);
            CHECK(sent[3].size() == 257 &&
                  sent[3].compare(0, 6,
                                  std::string("\x05"
                                              "a\\b"
                                              "\0"
                                              "c",
                                              6)) == 0 &&
                  sent[3].find_first_not_of('\0', 6) == std::string::npos);
            std::string m4(258, '\0');
            m4[13] = '\xF4';
            m4[14] = '\x01';
            m4[65] = '\xA0';
            m4[66] = '\xBF';
            m4[96] = '\x34';
            m4[97] = '\x12';
            CHECK(sent[4] == m4);
            CHECK(sent[5] == std::string("\x07\x00", 2) + std::string(20, '\xAB'));
            CHECK(sent[6] == std::string("\x01", 1));
        }
        CHECK(!sh.run("make('_nope_clzo')", "=e1") &&
              contains(sh.last_error(), "make: no struct '_nope_clzo' in the packet db"));
        CHECK(!sh.run("make('_move_request_clzo', {foo = 1})", "=e2"));
        CHECK(contains(sh.last_error(), "make(_move_request_clzo): no field 'foo' -- its fields: byMoveType, fCur[0], "
                                        "fCur[1], fCur[2], dwSerial, zTar[0], zTar[1], byDirect"));
        CHECK(!sh.run("make('_move_request_clzo', {dwSerial = -1})", "=e3"));
        CHECK(contains(sh.last_error(),
                       "make(_move_request_clzo): dwSerial = -1: a whole number in 0..4294967295 (or 0x..)"));
        CHECK(!sh.run("make('_move_request_clzo', {fCur = {1, 2, 3, 4}})", "=e4") &&
              contains(sh.last_error(), "no field 'fCur[3]'"));
        CHECK(!sh.run("make('_chat_circle_request_clzo', {wszChatData = string.rep('x', 257)})", "=e5"));
        CHECK(
            contains(sh.last_error(), "make(_chat_circle_request_clzo): wszChatData: 257 bytes: the field holds 256"));
        CHECK(!sh.run("make('_hs_msg_make_guid_req_msg_zocl', {byGuidReqMsg = 'abc'})", "=e6") &&
              contains(sh.last_error(), "3 bytes: this field is exactly 20"));
        CHECK(!sh.run("make('_move_request_clzo', {[1] = 5})", "=e7") &&
              contains(sh.last_error(), "a field key must be a name"));
        CHECK(!sh.run("make('_move_request_clzo', {byMoveType = print})", "=e8") &&
              contains(sh.last_error(), "byMoveType takes a number, a boolean or a string -- not a function"));
        CHECK(!sh.run("make('_chat_circle_request_clzo', {wszChatData = 5})", "=e9") &&
              contains(sh.last_error(), "wszChatData takes a string (its text) -- not a number"));
    }
    std::printf("script: make done\n");

    {
        std::vector<PatchRule> live;
        bool armed = false;
        ScriptRules answer = ScriptRules::Applied;
        std::vector<std::pair<std::string, std::string>> sets;
        ScriptLimits l;
        l.max_rule_changes_per_s = 4;
        ScriptHost sh(l, sink);
        CHECK(sh.run("log(rules.add{dir = 'C2S', action = {offset = 0, hexReplace = '01'}}) log(rules.enable(1)) "
                     "log(#rules.list(), rules.armed())",
                     "=norules"));
        CHECK(has_line(sh, Kind::Log, "false not applied: no patch rules here (the hooks are not installed)"));
        CHECK(has_line(sh, Kind::Log, "0 false"));
        CHECK(has_line(sh, Kind::Info,
                       "rules.add: not applied: no patch rules here (the hooks are not installed) -- the "
                       "call returned false (said once per run)"));
        CHECK(!has_prefix(sh, Kind::Info, "rules.enable:"));
        CHECK(sh.stats().rules_refused == 2 && sh.stats().rule_changes == 0);
        ScriptIo io;
        io.rules = [&]() {
            return ScriptRulesView{&live, armed};
        };
        io.set_rules = [&](const std::string& who, std::vector<PatchRule> nl, const std::string& change) {
            sets.emplace_back(who, change);
            if (answer != ScriptRules::Unavailable) {
                live = std::move(nl);
            }
            return answer;
        };
        sh.set_io(io);
        CHECK(sh.run("log('a', rules.add{name = 'serial', dir = 'c2s', main = 4, sub = 1, action = {offset = '+000D', "
                     "hexReplace = '39 30 ?? ??'}})\n"
                     "log('b', rules.add{dir = 'S2C', main = '*', match = {offset = 0, hexPattern = '01'}, "
                     "action = {findHex = 'D2 04', replaceHex = '39 30'}, enabled = false})\n"
                     "local l = rules.list()\n"
                     "log(#l, l[1].name, l[1].enabled, l[1].valid, l[1].active, l[1].text)\n"
                     "log(l[2].name, l[2].enabled, l[2].active, l[2].text)\n"
                     "log('armed', rules.armed())\n",
                     "=add"));
        CHECK(has_line(sh, Kind::Log, "a 1") && has_line(sh, Kind::Log, "b 2"));
        CHECK(has_line(sh, Kind::Log, "2 serial true true true C2S (4,1) write +000D = 39 30 ?? ??"));
        CHECK(has_line(sh, Kind::Log, "script add false false S2C (*,*) if +0000 = 01: replace D2 04 -> 39 30"));
        CHECK(has_line(sh, Kind::Log, "armed false"));
        CHECK(sets.size() == 2);
        if (sets.size() == 2) {
            CHECK(sets[0].first == "add" &&
                  sets[0].second == "added #1 \"serial\": C2S (4,1) write +000D = 39 30 ?? ??");
            CHECK(sets[1].second == "added #2 \"script add\": S2C (*,*) if +0000 = 01: replace D2 04 -> 39 30");
        }
        CHECK(live.size() == 2);
        if (live.size() == 2) {
            CHECK(live[0].write_off == 13 &&
                  (live[0].write_bytes == std::vector<uint16_t>{0x39, 0x30, kAnyByte, kAnyByte}) &&
                  live[1].main == -1 && !live[1].enabled && live[1].match_off == 0 &&
                  live[1].kind == PatchRule::Kind::Replace);
        }
        CHECK(sh.stats().rule_changes == 2);
        CHECK(sh.run("log('e1', rules.enable('serial', false))\n"
                     "log('e2', rules.enable('serial', false))\n"
                     "log('e3', rules.enable(2))\n"
                     "log('e4', rules.enable('nope', true))\n"
                     "log('e5', rules.enable(9))\n"
                     "log('r1', rules.remove(1))\n"
                     "log('r2', rules.remove('serial'))\n"
                     "log(#rules.list(), rules.list()[1].name, rules.list()[1].enabled)\n",
                     "=en"));
        CHECK(has_line(sh, Kind::Log, "e1 true") && has_line(sh, Kind::Log, "e2 true") &&
              has_line(sh, Kind::Log, "e3 true"));
        CHECK(has_line(sh, Kind::Log, "e4 false no rule named 'nope' in the Rules list"));
        CHECK(has_line(sh, Kind::Log, "e5 false no rule #9 in the Rules list (it holds 2)"));
        CHECK(has_line(sh, Kind::Log, "r1 true"));
        CHECK(has_line(sh, Kind::Log, "r2 false no rule named 'serial' in the Rules list"));
        CHECK(has_line(sh, Kind::Log, "1 script add true"));
        CHECK(has_line(sh, Kind::Info,
                       "rules.enable: no rule named 'nope' in the Rules list -- the call returned false "
                       "(said once per run)"));
        CHECK(sets.size() == 5);
        if (sets.size() == 5) {
            CHECK(sets[2].second == "disabled #1 \"serial\"");
            CHECK(sets[3].second == "enabled #2 \"script add\"");
            CHECK(sets[4].second == "removed #1 \"serial\"");
        }
        CHECK(live.size() == 1 && live[0].name == "script add" && live[0].enabled);
        CHECK(sh.stats().rule_changes == 3 && sh.stats().rules_refused == 3);
        answer = ScriptRules::Disarmed;
        armed = true;
        CHECK(sh.run("log('armed', rules.armed()) log(rules.enable(1, false))", "=dis"));
        const std::string dis =
            "applied -- Rules was ARMED and this session has not let scripts change the armed rules: "
            "it is disarmed now (tick Rules: arming the new list asks first, and lets scripts change it)";
        CHECK(has_line(sh, Kind::Log, "armed true"));
        CHECK(has_line(sh, Kind::Log, "true " + dis));
        CHECK(has_line(sh, Kind::Info, "rules.enable: " + dis));
        CHECK(sh.stats().rule_changes == 1 && live.size() == 1 && !live[0].enabled);
        answer = ScriptRules::Unavailable;
        armed = false;
        CHECK(sh.run("log('u', rules.enable(1, true))", "=unav"));
        CHECK(has_line(sh, Kind::Log, "u false not applied: no patch rules here (the hooks are not installed)"));
        CHECK(sh.stats().rule_changes == 0 && sh.stats().rules_refused == 1 && live.size() == 1 && !live[0].enabled);
        answer = ScriptRules::Applied;
        CHECK(!sh.run("rules.add{main = 2, action = {offset = 0, hexReplace = '01'}}", "=x1") &&
              contains(sh.last_error(), "rules.add: dir: missing (\"C2S\" or \"S2C\")"));
        CHECK(!sh.run("rules.add{dir = 'C2S', action = {offset = 0, hexReplace = '0G'}}", "=x2") &&
              contains(sh.last_error(), "rules.add: action.hexReplace: \"0G\" is not a hex byte or ??"));
        CHECK(!sh.run("rules.add{dir = 'C2S', main = 300, action = {offset = 0, hexReplace = '01'}}", "=x3") &&
              contains(sh.last_error(), "rules.add: main: 0..255, or any"));
        CHECK(!sh.run("rules.add{dir = 'C2S', colour = 1, action = {offset = 0, hexReplace = '01'}}", "=x4") &&
              contains(sh.last_error(), "rules.add: unknown key \"colour\""));
        CHECK(!sh.run("rules.add{dir = 'C2S', action = {offset = 0, hexReplace = print}}", "=x5") &&
              contains(sh.last_error(),
                       "rules.add: action.hexReplace takes a string, a number, a boolean or a table -- "
                       "not a function"));
        CHECK(!sh.run("rules.add{dir = 'C2S', action = {[1] = 'x'}}", "=x6") &&
              contains(sh.last_error(), "rules.add: action: every key must be a name"));
        CHECK(!sh.run("rules.add('C2S')", "=x7") && contains(sh.last_error(), "bad argument #1"));
        CHECK(!sh.run("rules.enable({})", "=x8") && contains(sh.last_error(), "a rule name (string) or # (integer)"));
        live.assign(kMaxRules, PatchRule{});
        CHECK(sh.run("log('f', rules.add{dir = 'C2S', action = {offset = 0, hexReplace = '01'}})", "=full"));
        CHECK(has_line(sh, Kind::Log,
                       "f false not added: the Rules list holds 64 rules (only the first 64 are used) -- "
                       "rules.remove some"));
        live.clear();
        sets.clear();
        CHECK(sh.run("local n = 0 for i = 1, 6 do if rules.add{dir = 'C2S', action = {offset = 0, hexReplace = '01'}} "
                     "then n = n + 1 end end log('added', n) log('e', rules.enable(1, false))",
                     "=rate"));
        CHECK(has_line(sh, Kind::Log, "added 4"));
        CHECK(has_line(sh, Kind::Log, "e false not applied: over 4 rule changes per second from this script"));
        CHECK(sets.size() == 4 && live.size() == 4 && sh.running());
        CHECK(sh.stats().rule_changes == 4 && sh.stats().rules_refused == 3);
    }
    {
        int n = 0;
        {
            ScriptIo io;
            io.stopped = [&n]() {
                ++n;
            };
            ScriptHost sh(small_limits(), sink);
            sh.set_io(io);
            CHECK(sh.run("log(1)", "=s1") && n == 0);
            sh.stop("test");
            CHECK(n == 1);
            sh.stop("again");
            CHECK(n == 1);
            CHECK(sh.run("log(2)", "=s2") && sh.run("log(3)", "=s3") && n == 2);
            CHECK(!sh.run("error('x')", "=s4") && n == 4);
            CHECK(sh.run("on_packet(function(p) while true do end end)", "=s5") && n == 4);
            sh.begin_frame();
            sh.on_packet(move_packet());
            CHECK(sh.state() == ScriptState::Tripped && n == 5);
            CHECK(sh.run("log(6)", "=s6") && n == 5);
        }
        CHECK(n == 5);
    }
    std::printf("script: rules done\n");

    {
        ScriptLimits l;
        l.max_timers = 3;
        ScriptHost sh(l, sink);
        sh.set_clock(fake_now);
        g_now = 1000;
        CHECK(sh.run("local n = 0\n"
                     "local t1 = on_tick(100, function() n = n + 1 log('tick', n) end)\n"
                     "local t2 = after(250, function() log('once') end)\n"
                     "log('ids', t1, t2)\n",
                     "=tick"));
        CHECK(has_line(sh, Kind::Log, "ids 1 2"));
        CHECK(has_prefix(sh, Kind::Info, "started tick -- 0 on_packet handler(s), 2 timer(s); watchdog:"));
        CHECK(sh.stats().timers == 2 && sh.stats().ticks == 0);
        g_now = 1099;
        sh.begin_frame();
        sh.tick();
        CHECK(!has_prefix(sh, Kind::Log, "tick"));
        g_now = 1100;
        sh.begin_frame();
        sh.tick();
        CHECK(has_line(sh, Kind::Log, "tick 1"));
        g_now = 1350;
        sh.begin_frame();
        sh.tick();
        CHECK(has_line(sh, Kind::Log, "tick 2") && has_line(sh, Kind::Log, "once") &&
              !has_line(sh, Kind::Log, "tick 3"));
        CHECK(index_of(sh, "tick 2") < index_of(sh, "once"));
        CHECK(sh.stats().timers == 1 && sh.stats().ticks == 3);
        sh.begin_frame();
        sh.tick();
        CHECK(!has_line(sh, Kind::Log, "tick 3"));
        g_now = 1450;
        sh.begin_frame();
        sh.tick();
        CHECK(has_line(sh, Kind::Log, "tick 3") && sh.stats().ticks == 4);
        sh.stop("test");
        CHECK(sh.stats().timers == 0);
        g_now = 2000;
        sh.begin_frame();
        sh.tick();
        CHECK(!has_line(sh, Kind::Log, "tick 4") && sh.stats().ticks == 4);
        CHECK(sh.run("local id\n"
                     "id = on_tick(10, function() log('c', cancel_tick(id), cancel_tick(id)) end)\n"
                     "log('unknown', cancel_tick(42))\n",
                     "=cancel"));
        CHECK(has_line(sh, Kind::Log, "unknown false"));
        g_now = 2010;
        sh.begin_frame();
        sh.tick();
        CHECK(has_line(sh, Kind::Log, "c true false") && sh.stats().timers == 0);
        g_now = 2100;
        sh.begin_frame();
        sh.tick();
        CHECK(sh.stats().ticks == 1);
        CHECK(!sh.run("on_tick(0, function() end)", "=a1") && contains(sh.last_error(), "bad argument #1") &&
              contains(sh.last_error(), "ms: 1..86400000"));
        CHECK(!sh.run("after(10)", "=a2") && contains(sh.last_error(), "bad argument #2"));
        CHECK(!sh.run("for i = 1, 4 do on_tick(10, function() end) end", "=a3"));
        CHECK(contains(sh.last_error(),
                       "on_tick: more than 3 timers at once -- cancel_tick the ones you no longer need"));
        CHECK(sh.run("on_tick(10, function() error('tock') end)", "=terr"));
        g_now = 3000;
        sh.begin_frame();
        sh.tick();
        CHECK(sh.state() == ScriptState::Failed && contains(sh.last_error(), "terr:1: tock"));
        CHECK(has_prefix(sh, Kind::Error, "FAILED (in on_tick #1 (every 10 ms)): terr:1: tock"));
    }
    {
        ScriptHost sh(small_limits(), sink);
        sh.set_clock(fake_now);
        g_now = 0;
        CHECK(sh.run("after(5, function() while true do end end)", "=trun"));
        g_now = 5;
        const auto t0 = std::chrono::steady_clock::now();
        sh.begin_frame();
        sh.tick();
        CHECK(sh.state() == ScriptState::Tripped && ms_since(t0) < 5000.0);
        CHECK(contains(sh.last_error(), "(in after #1 (5 ms))"));
    }
    {
        ScriptLimits l;
        l.frame_ms = 1;
        l.max_ms = 10000;
        l.max_instructions = 1000000000ull;
        ScriptHost sh(l, sink);
        sh.set_clock(fake_now);
        g_now = 0;
        CHECK(sh.run("on_tick(1, function() for i = 1, 5000000 do end end)\n"
                     "on_tick(2, function() log('second') end)\n",
                     "=budget"));
        g_now = 2;
        sh.begin_frame();
        sh.tick();
        CHECK(sh.stats().ticks == 1 && !has_line(sh, Kind::Log, "second"));
        sh.begin_frame();
        sh.tick();
        CHECK(sh.stats().ticks == 2 && has_line(sh, Kind::Log, "second") && sh.running());
    }
    std::printf("script: ticks done\n");

    if (g_fail) {
        std::printf("FAILED (%d failure(s))\n", g_fail);
    } else {
        std::printf("PASSED (0 failure(s))\n");
    }
    return g_fail ? 1 : 0;
}
