#include "build/build_profile.h"
#include "hooks/hooks.h"
#include "hooks/rules_file.h"
#include "proto/decode.h"
#include "proto/packet_db.h"
#include "proto/packet_text.h"
#include "ui/ui.h"
#include "util/log.h"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <atomic>
#include <filesystem>
#include <string>
#include <vector>

namespace {
HMODULE g_self = nullptr;
std::atomic<bool> g_running{true};

rfte::PacketDb g_db;
bool g_haveDb = false;

std::filesystem::path module_dir(HMODULE m) {
    wchar_t buf[MAX_PATH]{};
    const DWORD n = GetModuleFileNameW(m, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        return {};
    }
    return std::filesystem::path(buf).parent_path();
}

void load_packet_db(const char* host) {
    const std::filesystem::path dir = module_dir(g_self);
    std::string err = "module path unavailable";
    g_haveDb = !dir.empty() && g_db.load(dir / L"packet_db.json", &err);
    if (g_haveDb) {
        rfte::logmsg("packet db: %zu structs, %zu opcode mappings -- packets are labelled + decoded",
                     g_db.struct_count(), g_db.opcode_count());
        if (g_db.has_client() && g_db.client_build() != host) {
            rfte::logmsg("packet db: its client dispatch is the %s client's -- on this %s client the route "
                         "lines are a reference (dim, no NO HANDLER warnings)",
                         g_db.client_build().c_str(), host);
        }
        if (g_db.has_server() && g_db.server_build() != host) {
            rfte::logmsg("packet db: its server dispatch is the %s zone server's -- on this %s client the server "
                         "lines are a reference (dim, no NO HANDLER warnings)",
                         g_db.server_build().c_str(), host);
        }
    } else {
        rfte::logmsg("packet db: not loaded (%s) -- packets are logged raw; put packet_db.json "
                     "next to the DLL",
                     err.c_str());
    }
}

std::filesystem::path g_rulesPath;
std::vector<rfte::PatchRule> g_startRules;

rfte::RulesLoad read_rules() {
    return rfte::load_rules_file(g_rulesPath);
}

void load_rules() {
    const std::filesystem::path dir = module_dir(g_self);
    if (!dir.empty()) {
        g_rulesPath = dir / rfte::kRulesFile;
    }
    const rfte::RulesLoad L = read_rules();
    for (const std::string& s : rfte::describe_load(L)) {
        rfte::logmsg("rules: %s", s.c_str());
    }
    const size_t n = rfte::set_rules(L.rules);
    if (!L.rules.empty()) {
        rfte::logmsg("rules: %zu active -- DISARMED: tick Rules in the tool window to apply them (it asks first)", n);
    }
    g_startRules = L.rules;
}

bool save_rules(const std::vector<rfte::PatchRule>& rules, std::string* err) {
    return rfte::save_rules_file(g_rulesPath, rules, err);
}

BOOL CALLBACK find_game_window(HWND w, LPARAM out) {
    DWORD pid = 0;
    const DWORD tid = GetWindowThreadProcessId(w, &pid);
    if (pid != GetCurrentProcessId() || !IsWindowVisible(w)) {
        return TRUE;
    }
    *(DWORD*)out = tid;
    return FALSE;
}

DWORD game_window_thread() {
    DWORD tid = 0;
    EnumWindows(find_game_window, (LPARAM)&tid);
    return tid;
}

uint64_t g_logged = 0, g_dropped_total = 0;

void dump_captures(int64_t qpc_base, double qpc_per_ms) {
    std::vector<rfte::PacketRec> batch;
    std::string text;
    for (;;) {
        batch.clear();
        text.clear();
        uint64_t dropped = 0;
        const size_t n = rfte::drain_captures(batch, 256, dropped);
        if (dropped) {
            g_dropped_total += dropped;
            rfte::logmsg("capture ring overflow: %llu packet(s) dropped (total %llu)", (unsigned long long)dropped,
                         (unsigned long long)g_dropped_total);
        }
        for (const rfte::PacketRec& r : batch) {
            const double t = (double)((int64_t)r.ts_qpc - qpc_base) / qpc_per_ms;
            if (g_haveDb) {
                const rfte::Decoded d = g_db.classify(r.dir, r.main, r.sub, r.size);
                text += rfte::format_packet(r, t, rfte::describe(d, r.size), d.layout);
            } else {
                text += rfte::format_packet(r, t);
            }
        }
        if (!text.empty()) {
            rfte::lograw(text.data(), text.size());
        }
        g_logged += n;
        if (n < 256) {
            return;
        }
    }
}

bool unload_hotkey_down() {
    if (!(GetAsyncKeyState(VK_CONTROL) & 0x8000) || !(GetAsyncKeyState(VK_SHIFT) & 0x8000) ||
        !(GetAsyncKeyState(VK_END) & 0x8000)) {
        return false;
    }
    DWORD pid = 0;
    GetWindowThreadProcessId(GetForegroundWindow(), &pid);
    return pid == GetCurrentProcessId();
}

std::wstring ui_title(const rfte::ResolvedProfile& r) {
    std::wstring t = L"pktnik -- ";
    for (const char* p = r.profile->name; *p; ++p) {
        t += (wchar_t)(unsigned char)*p;
    }
    t += L" -- pid " + std::to_wstring(GetCurrentProcessId());
    return t;
}

void monitor(int64_t qpc_base, double qpc_per_ms, bool ui_up) {
    bool said_send = false, said_recv = false, said_both = false;
    uint32_t last_send = 0, last_recv = 0;
    ULONGLONG last_report = GetTickCount64();
    while (g_running.load()) {
        Sleep(100);
        const rfte::HookStats s = rfte::hook_stats();
        if (!said_send && s.send_tid && s.have_send_args) {
            if (rfte::active_profile().profile->send_stack_args == 4) {
                rfte::logmsg("first SendNetMessage: this=%p tid=%u dwClientIndex=%u (no nNetProcessIdx on this build)",
                             s.send_self, s.send_tid, s.client_idx);
            } else {
                rfte::logmsg("first SendNetMessage: this=%p tid=%u dwClientIndex=%u nNetProcessIdx=%d", s.send_self,
                             s.send_tid, s.client_idx, s.net_proc_idx);
            }
            said_send = true;
        }
        if (!said_recv && s.recv_tid) {
            rfte::logmsg("first AnalysisZoneServerPacket: this=%p tid=%u", s.recv_self, s.recv_tid);
            said_recv = true;
        }
        if (!said_both && said_send && said_recv) {
            rfte::logmsg("send/recv same thread: %s; same this: %s; game window thread: tid=%u",
                         s.send_tid == s.recv_tid ? "yes" : "NO", s.send_self == s.recv_self ? "yes" : "NO",
                         (unsigned)game_window_thread());
            said_both = true;
        }
        const ULONGLONG now = GetTickCount64();
        if (now - last_report >= 5000 && (s.n_send != last_send || s.n_recv != last_recv)) {
            rfte::logmsg("calls: C2S %u  S2C %u", s.n_send, s.n_recv);
            last_send = s.n_send;
            last_recv = s.n_recv;
            last_report = now;
        }
        if (!ui_up) {
            dump_captures(qpc_base, qpc_per_ms);
        }
        if (unload_hotkey_down()) {
            rfte::logmsg("unload: Ctrl+Shift+End");
            g_running.store(false);
        } else if (rfte::ui_unload_requested()) {
            rfte::logmsg("unload: UI button");
            g_running.store(false);
        }
    }
}

void unload_and_exit(int64_t qpc_base, double qpc_per_ms) {
    rfte::ui_stop();
    const bool safe = rfte::uninstall_hooks(30000);
    dump_captures(qpc_base, qpc_per_ms);
    const rfte::HookStats s = rfte::hook_stats();
    const rfte::UiStats u = rfte::ui_stats();
    rfte::logmsg("%s: C2S %u S2C %u calls; %llu packets logged, %llu dropped", safe ? "unloaded" : "unload incomplete",
                 s.n_send, s.n_recv, (unsigned long long)(g_logged + u.ingested),
                 (unsigned long long)(g_dropped_total + u.dropped));
    if (!safe) {
        return;
    }
    rfte::log_close();
    FreeLibraryAndExitThread(g_self, 0);
}

DWORD WINAPI init_thread(LPVOID) {
    rfte::log_init(g_self);
    rfte::logmsg("RFTrafficEditor loaded (pid %u) -- built " __DATE__ " " __TIME__, (unsigned)GetCurrentProcessId());
    LARGE_INTEGER f, q;
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&q);
    const rfte::ResolvedProfile& r = rfte::active_profile();
    if (!r.profile) {
        rfte::logmsg("inert: no hooks installed");
        return 0;
    }
    load_packet_db(r.profile->name);
    if (!rfte::install_hooks()) {
        rfte::logmsg("inert: no hooks installed");
        return 0;
    }
    load_rules();
    const double qpc_per_ms = (double)f.QuadPart / 1000.0;
    rfte::logmsg("capture: every packet is dumped below (t = ms since load; label = struct + status, "
                 "then one line per field); Ctrl+Shift+End with the game focused unloads");
    rfte::UiConfig ui;
    ui.module = g_self;
    ui.db = g_haveDb ? &g_db : nullptr;
    ui.qpc_base = q.QuadPart;
    ui.qpc_per_ms = qpc_per_ms;
    ui.title = ui_title(r);
    ui.host_build = r.profile->name;
    ui.drain = &rfte::drain_captures;
    ui.log_packets = &rfte::lograw;
    ui.set_capture = &rfte::set_capture_enabled;
    ui.queue_action = &rfte::queue_action;
    ui.cancel_actions = &rfte::cancel_actions;
    ui.action_stats = &rfte::action_stats;
    ui.rules = g_startRules;
    ui.set_rules = &rfte::set_rules;
    ui.arm_rules = &rfte::arm_rules;
    ui.rule_stats = &rfte::rule_stats;
    ui.reload_rules = &read_rules;
    ui.save_rules = &save_rules;
    ui.script_dir = module_dir(g_self).wstring();
    const bool ui_up = rfte::ui_start(ui);
    if (!ui_up && !g_startRules.empty()) {
        rfte::logmsg("rules: no tool window -- the patch rules stay disarmed");
    }
    monitor(q.QuadPart, qpc_per_ms, ui_up);
    unload_and_exit(q.QuadPart, qpc_per_ms);
    return 0;
}
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_self = hInst;
        DisableThreadLibraryCalls(hInst);
        CreateThread(nullptr, 0, init_thread, nullptr, 0, nullptr);
    } else if (reason == DLL_PROCESS_DETACH) {
    }
    return TRUE;
}
