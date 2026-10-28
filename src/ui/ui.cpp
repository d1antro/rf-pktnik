#include "ui/ui.h"
#include "hooks/patch_rules.h"
#include "hooks/rules_file.h"
#include "proto/decode.h"
#include "proto/packet_db.h"
#include "proto/packet_text.h"
#include "script/script_host.h"
#include "ui/field_edit.h"
#include "ui/filter.h"
#include "ui/packet_model.h"
#include "ui/packet_view.h"
#include "ui/rule_edit.h"
#include "util/log.h"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>
#include <imgui.h>
#include <imgui_impl_dx11.h>
#include <imgui_impl_win32.h>
#include <algorithm>
#include <atomic>
#include <cfloat>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <future>
#include <iterator>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace rfte {
namespace {

constexpr wchar_t kClass[] = L"RFTrafficEditorUI";
constexpr uint64_t kNoSel = ~0ull;
constexpr size_t kBatch = 256, kRounds = 8;
constexpr float kSplitH = 6.0f;
constexpr float kMinPane = 120.0f;
constexpr int kMaxNest = 4;
constexpr size_t kTextBudget = 1000;

std::thread g_thread;
std::atomic<bool> g_run{false};
std::atomic<bool> g_unload{false};
std::atomic<uint64_t> g_iter{0}, g_frames{0}, g_ingested{0}, g_dropped{0}, g_rows{0};
std::atomic<uint64_t> g_detailFrames{0}, g_detailSeq{~0ull}, g_detailRows{0};
std::atomic<uint64_t> g_shown{0}, g_pending{0};
std::atomic<uint64_t> g_composerFrames{0}, g_queued{0}, g_rejected{0}, g_confirmAsks{0};
std::atomic<uint64_t> g_resends{0}, g_editorFields{0}, g_fieldEdits{0};
std::atomic<int> g_detailRoute{-1}, g_composerRoute{-1};
std::atomic<uint64_t> g_routeWarns{0};
std::atomic<int> g_detailServer{-1}, g_composerServer{-1};
std::atomic<uint64_t> g_serverWarns{0};
std::atomic<uint64_t> g_ruleAsks{0}, g_ruleArms{0};
std::atomic<uint64_t> g_rulesEditorFrames{0}, g_editorRules{0}, g_rulesAdded{0};
std::atomic<uint64_t> g_ruleApplies{0}, g_ruleApplyAsks{0}, g_ruleSaves{0};
std::atomic<int> g_detailEdits{-1};
std::atomic<int> g_scriptState{0};
std::atomic<uint64_t> g_scriptRuns{0}, g_scriptAsks{0}, g_scriptPackets{0}, g_scriptCallbacks{0};
std::atomic<uint64_t> g_scriptSkipped{0}, g_scriptTrips{0}, g_scriptErrors{0}, g_scriptLines{0}, g_scriptFrames{0};
std::atomic<uint64_t> g_scriptSent{0}, g_scriptInjected{0}, g_scriptHeld{0}, g_scriptRefused{0};
std::atomic<uint64_t> g_scriptTicks{0}, g_scriptTimers{0}, g_ruleScriptChanges{0}, g_ruleScriptDisarms{0},
    g_ruleScriptUndos{0};

std::mutex g_snapMtx;
std::condition_variable g_snapCv;
uint64_t g_snapAsked = 0, g_snapServed = 0;
std::vector<uint32_t> g_snapPx;
int g_snapW = 0, g_snapH = 0;

HWND g_hwnd = nullptr;
ID3D11Device* g_dev = nullptr;
ID3D11DeviceContext* g_ctx = nullptr;
IDXGISwapChain* g_swap = nullptr;
ID3D11RenderTargetView* g_rtv = nullptr;
UINT g_resizeW = 0, g_resizeH = 0;

void serve_snapshot() {
    std::lock_guard<std::mutex> lk(g_snapMtx);
    if (g_snapServed >= g_snapAsked) {
        return;
    }
    g_snapPx.clear();
    ID3D11Texture2D* back = nullptr;
    if (SUCCEEDED(g_swap->GetBuffer(0, __uuidof(ID3D11Texture2D), (void**)&back))) {
        D3D11_TEXTURE2D_DESC td{};
        back->GetDesc(&td);
        td.Usage = D3D11_USAGE_STAGING;
        td.BindFlags = 0;
        td.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
        td.MiscFlags = 0;
        ID3D11Texture2D* staging = nullptr;
        if (SUCCEEDED(g_dev->CreateTexture2D(&td, nullptr, &staging))) {
            g_ctx->CopyResource(staging, back);
            D3D11_MAPPED_SUBRESOURCE m{};
            if (SUCCEEDED(g_ctx->Map(staging, 0, D3D11_MAP_READ, 0, &m))) {
                g_snapW = (int)td.Width;
                g_snapH = (int)td.Height;
                g_snapPx.resize((size_t)td.Width * td.Height);
                for (UINT y = 0; y < td.Height; ++y) {
                    const uint8_t* row = (const uint8_t*)m.pData + (size_t)y * m.RowPitch;
                    for (UINT x = 0; x < td.Width; ++x) {
                        const uint8_t* p = row + x * 4;
                        g_snapPx[(size_t)y * td.Width + x] =
                            0xFF000000u | (uint32_t)p[0] << 16 | (uint32_t)p[1] << 8 | p[2];
                    }
                }
                g_ctx->Unmap(staging, 0);
            }
            staging->Release();
        }
        back->Release();
    }
    g_snapServed = g_snapAsked;
    g_snapCv.notify_all();
}

const ImVec4 kC2S(0.45f, 0.70f, 1.00f, 1.0f);
const ImVec4 kS2C(0.80f, 0.60f, 1.00f, 1.0f);
const ImVec4 kOk(0.55f, 0.90f, 0.55f, 1.0f);
const ImVec4 kVar(0.45f, 0.85f, 0.90f, 1.0f);
const ImVec4 kMismatch(1.00f, 0.45f, 0.35f, 1.0f);
const ImVec4 kTrigger(0.85f, 0.75f, 0.55f, 1.0f);
const ImVec4 kDim(0.55f, 0.55f, 0.55f, 1.0f);
const ImVec4 kEdited(1.00f, 0.85f, 0.30f, 1.0f);
const ImVec4 kWarn(1.00f, 0.60f, 0.30f, 1.0f);
const ImVec4 kTool(0.95f, 0.55f, 0.85f, 1.0f);
const ImVec4 kBadField(0.45f, 0.15f, 0.12f, 1.0f);
const ImU32 kMismatchBg = IM_COL32(90, 30, 25, 255);
const ImU32 kFieldBgA = IM_COL32(45, 70, 110, 255);
const ImU32 kFieldBgB = IM_COL32(40, 95, 80, 255);
const ImU32 kGapBg = IM_COL32(60, 60, 60, 255);
const ImU32 kExtraBg = IM_COL32(110, 40, 35, 255);
const ImU32 kHlBg = IM_COL32(190, 140, 30, 255);
const ImU32 kHlRow = IM_COL32(110, 85, 25, 255);

struct ListState {
    bool follow = true;
    bool capture = true;
    uint64_t selected = kNoSel;
    float detail_h = 0.0f;
    uint64_t resend = kNoSel;
    bool resend_other = false;
    uint64_t load = kNoSel;
    uint64_t rule_row = kNoSel;
};

struct FilterBar {
    Filter edit;
    char opcode[24] = "";
    char name[64] = "";
    char text[128] = "";
    bool opcode_ok = true;
};

FilterBar make_filter_bar(const Filter& f) {
    FilterBar fb;
    fb.edit = f;
    if (f.main >= 0 && f.sub >= 0) {
        std::snprintf(fb.opcode, sizeof fb.opcode, "%d,%d", f.main, f.sub);
    } else if (f.main >= 0) {
        std::snprintf(fb.opcode, sizeof fb.opcode, "%d", f.main);
    }
    std::snprintf(fb.name, sizeof fb.name, "%s", f.name.c_str());
    std::snprintf(fb.text, sizeof fb.text, "%s", f.text.c_str());
    fb.edit.name = fb.name;
    fb.edit.text = fb.text;
    return fb;
}

constexpr size_t kHexChars = 3 * (size_t)kMaxAction + 256;
constexpr size_t kFieldChars = 4 * (size_t)kMaxAction + 64;

struct Draft {
    bool ok = false;
    std::string err;
    Dir dir = Dir::C2S;
    uint8_t main = 0, sub = 0;
    std::vector<uint8_t> bytes;
    Status status = Status::Unknown;
    std::string label;
    std::string from;
    bool script = false;
};

struct Composer {
    bool open = false;
    int dir = 0;
    char opcode[24] = "";
    std::vector<char> hex = std::vector<char>(kHexChars, '\0');
    bool armed[2] = {false, false};
    Draft pending;
    bool submit_once = false;
    std::string status;
    bool status_bad = false;
    bool ask = false;
    double flash_until = 0.0;
    int pick = -1;
    uint32_t pick_key = ~0u;
    std::vector<char> fbuf = std::vector<char>(kFieldChars, '\0');
    bool fill_once = false;
    std::vector<std::pair<std::string, std::string>> edits_once;
    bool confirming = false;
    int answer_once = 0;
};

Composer make_composer(const ComposeInit& in) {
    Composer c;
    c.open = in.open;
    c.dir = in.dir == Dir::C2S ? 0 : 1;
    std::snprintf(c.opcode, sizeof c.opcode, "%s", in.opcode.c_str());
    std::snprintf(c.hex.data(), c.hex.size(), "%s", in.hex.c_str());
    c.armed[0] = c.armed[1] = in.confirmed;
    c.submit_once = in.submit;
    c.fill_once = in.fill;
    c.edits_once = in.edits;
    c.answer_once = in.answer;
    return c;
}

void load_row(Composer& c, const Row& r) {
    c.dir = r.rec.dir == Dir::C2S ? 0 : 1;
    std::snprintf(c.opcode, sizeof c.opcode, "%u,%u", (unsigned)r.rec.main, (unsigned)r.rec.sub);
    const std::string h = hex_line(r.rec.bytes.data(), r.rec.bytes.size());
    std::snprintf(c.hex.data(), c.hex.size(), "%s", h.c_str());
    char buf[96];
    c.status_bad = r.rec.bytes.size() < r.rec.size;
    if (c.status_bad) {
        std::snprintf(buf, sizeof buf, "loaded #%llu -- captured prefix only (%zu of %u bytes)",
                      (unsigned long long)r.rec.seq, r.rec.bytes.size(), (unsigned)r.rec.size);
    } else {
        std::snprintf(buf, sizeof buf, "loaded #%llu", (unsigned long long)r.rec.seq);
    }
    c.status = buf;
}

Draft check_draft(const Composer& c, const PacketDb* db) {
    Draft d;
    d.dir = c.dir == 0 ? Dir::C2S : Dir::S2C;
    int mn = -1, sb = -1;
    if (!parse_opcode(c.opcode, mn, sb) || mn < 0 || sb < 0) {
        d.err = "opcode: enter main,sub -- both, 0..255 (e.g. 4,1 or 0x04,0x01)";
        return d;
    }
    d.main = (uint8_t)mn;
    d.sub = (uint8_t)sb;
    size_t bad = 0;
    if (!parse_hex(c.hex.data(), d.bytes, (size_t)kMaxAction, &bad)) {
        char buf[128];
        std::snprintf(buf, sizeof buf, "payload: not hex bytes (or over %d bytes) at character %zu", kMaxAction,
                      bad + 1);
        d.err = buf;
        return d;
    }
    if (db) {
        const Decoded dc = db->classify(d.dir, d.main, d.sub, (uint16_t)d.bytes.size());
        d.status = dc.status;
        d.label = describe(dc, (uint16_t)d.bytes.size());
    }
    d.ok = true;
    return d;
}

struct RulesUi {
    std::vector<PatchRule> list;
    std::vector<std::string> err;
    size_t active = 0;
    bool armed = false;
    bool confirmed = false;
    bool ask = false;
    bool tick_once = false;
    bool script_ok = false;
    bool script_changed = false;
    std::vector<PatchRule> script_base;
    std::string script_by;
};

void set_rule_list(RulesUi& ru, std::vector<PatchRule> list) {
    ru.list = std::move(list);
    ru.err.clear();
    ru.active = 0;
    for (size_t i = 0; i < ru.list.size(); ++i) {
        ru.err.push_back(check_rule(ru.list[i]));
        if (i < kMaxRules && ru.list[i].enabled && ru.err.back().empty()) {
            ++ru.active;
        }
    }
}

RulesUi make_rules_ui(const UiConfig& cfg) {
    RulesUi ru;
    set_rule_list(ru, cfg.rules);
    ru.confirmed = cfg.rules_confirmed;
    ru.tick_once = cfg.rules_tick;
    ru.script_ok = cfg.rules_script_ok;
    return ru;
}

constexpr size_t kRowRuleBytes = 8;

struct RulesEditor {
    bool open = false;
    std::vector<PatchRule> list;
    std::vector<PatchRule> saved;
    int sel = -1;
    int form_for = -1;
    RuleForm form;
    std::string status;
    bool status_bad = false;
    bool ask_apply = false;
    bool ask_reload = false;
    uint64_t from_row_once = kNoSel;
    std::string from_field_once;
    bool apply_once = false, save_once = false;
};

RulesEditor make_rules_editor(const UiConfig& cfg) {
    RulesEditor ed;
    ed.open = cfg.rules_edit.open;
    ed.list = ed.saved = cfg.rules;
    ed.from_row_once = cfg.rules_edit.from_row;
    ed.from_field_once = cfg.rules_edit.from_field;
    ed.apply_once = cfg.rules_edit.apply;
    ed.save_once = cfg.rules_edit.save;
    return ed;
}

bool editor_unsaved(const RulesEditor& ed) {
    return ed.list != ed.saved;
}

void editor_reset(RulesEditor& ed, const std::vector<PatchRule>& rules) {
    ed.list = ed.saved = rules;
    if (ed.sel >= (int)ed.list.size()) {
        ed.sel = (int)ed.list.size() - 1;
    }
    ed.form_for = -1;
}

void add_rule(RulesEditor& ed, PatchRule r, const std::string& note) {
    ed.status =
        "new rule #" + std::to_string(ed.list.size() + 1) + ": " + describe_rule(r) + note + " -- edit it, then Apply";
    ed.status_bad = false;
    ed.list.push_back(std::move(r));
    ed.sel = (int)ed.list.size() - 1;
    ed.form_for = -1;
    ed.open = true;
    g_rulesAdded.fetch_add(1);
}

PatchRule row_rule(const Row& r) {
    char nm[32];
    std::snprintf(nm, sizeof nm, "%s (%u,%u)", dir_name(r.rec.dir), (unsigned)r.rec.main, (unsigned)r.rec.sub);
    return rule_from_bytes(r.rec.dir, r.rec.main, r.rec.sub, 0, r.rec.bytes.data(),
                           std::min(r.rec.bytes.size(), kRowRuleBytes), r.name.empty() ? std::string(nm) : r.name);
}

PatchRule field_rule(const Row& r, int off, int len, const std::string& name, bool* cut) {
    const size_t n = r.rec.bytes.size();
    const size_t have = off >= 0 && (size_t)off < n ? std::min((size_t)std::max(len, 0), n - (size_t)off) : 0;
    *cut = have > kMaxRuleBytes;
    return rule_from_bytes(r.rec.dir, r.rec.main, r.rec.sub, off, have ? r.rec.bytes.data() + off : nullptr, have,
                           name);
}

constexpr size_t kMaxScriptFile = size_t(4) << 20;

struct ScriptUi {
    bool available = false;
    bool open = false;
    std::vector<std::wstring> files;
    int sel = -1;
    std::string name;
    std::string chunk;
    std::string code;
    bool loaded = false;
    std::string syntax;
    bool confirmed = false;
    bool ask = false;
    bool follow = true;
    uint64_t seen = 0;
};

std::string utf8(const std::wstring& w) {
    if (w.empty()) {
        return {};
    }
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s((size_t)std::max(n, 0), '\0');
    if (n > 0) {
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), n, nullptr, nullptr);
    }
    return s;
}

std::vector<std::wstring> list_scripts(const std::wstring& dir) {
    std::vector<std::wstring> out;
    if (dir.empty()) {
        return out;
    }
    WIN32_FIND_DATAW fd;
    const HANDLE f = FindFirstFileW((dir + L"\\*.lua").c_str(), &fd);
    if (f == INVALID_HANDLE_VALUE) {
        return out;
    }
    do {
        const size_t n = wcslen(fd.cFileName);
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && n > 4 &&
            _wcsicmp(fd.cFileName + n - 4, L".lua") == 0) {
            out.emplace_back(fd.cFileName);
        }
    } while (FindNextFileW(f, &fd));
    FindClose(f);
    std::sort(out.begin(), out.end());
    return out;
}

bool read_script(const std::filesystem::path& p, std::string& out, std::string* err) {
    std::ifstream f(p, std::ios::binary);
    if (!f) {
        *err = "cannot open it";
        return false;
    }
    std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (s.size() > kMaxScriptFile) {
        *err = "it is over 4 MB";
        return false;
    }
    if (s.rfind("\xEF\xBB\xBF", 0) == 0) {
        s.erase(0, 3);
    }
    out = std::move(s);
    return true;
}

void load_script(const UiConfig& cfg, ScriptUi& su, ScriptHost& sh, int idx) {
    if (sh.running()) {
        sh.stop("its file was reloaded");
    }
    su.sel = idx;
    su.name = utf8(su.files[(size_t)idx]);
    su.chunk = "@" + su.name;
    su.code.clear();
    su.confirmed = false;
    std::string err;
    su.loaded = read_script(std::filesystem::path(cfg.script_dir) / su.files[(size_t)idx], su.code, &err);
    if (!su.loaded) {
        su.syntax = "cannot read " + su.name + ": " + err;
        sh.note(su.syntax);
        return;
    }
    su.syntax = ScriptHost::check(su.code, su.chunk);
    sh.note("loaded " + su.name + " (" + std::to_string(su.code.size()) +
            " B): " + (su.syntax.empty() ? std::string("syntax ok") : "SYNTAX ERROR: " + su.syntax) +
            " -- nothing runs until you tick Run script (it asks first)");
}

void rescan(const UiConfig& cfg, ScriptUi& su, ScriptHost& sh) {
    const std::wstring cur = su.sel >= 0 && su.sel < (int)su.files.size() ? su.files[(size_t)su.sel] : std::wstring();
    su.files = list_scripts(cfg.script_dir);
    su.sel = -1;
    for (size_t i = 0; i < su.files.size(); ++i) {
        if (su.files[i] == cur) {
            su.sel = (int)i;
        }
    }
    std::string names;
    for (const std::wstring& f : su.files) {
        names += (names.empty() ? "" : ", ") + utf8(f);
    }
    sh.note(su.files.empty()
                ? std::string("no .lua file next to the DLL -- put one there (RFTrafficEditor.example.lua shows the "
                              "API), then Rescan in the Scripts window")
                : std::to_string(su.files.size()) + " .lua file(s) next to the DLL: " + names);
}

bool can_run(const ScriptUi& su) {
    return su.loaded && su.syntax.empty();
}

void run_now(ScriptUi& su, ScriptHost& sh) {
    sh.run(su.code, su.chunk);
}

void request_run(ScriptUi& su, ScriptHost& sh) {
    if (!can_run(su) || sh.running()) {
        return;
    }
    if (su.confirmed) {
        run_now(su, sh);
        return;
    }
    su.ask = true;
    g_scriptAsks.fetch_add(1);
}

ScriptUi make_script_ui(const UiConfig& cfg, ScriptHost& sh) {
    ScriptUi su;
    su.open = cfg.script.open;
    if (!cfg.script.code.empty()) {
        su.available = true;
        su.name = "(test script)";
        su.chunk = "=test";
        su.code = cfg.script.code;
        su.loaded = true;
        su.syntax = ScriptHost::check(su.code, su.chunk);
        su.confirmed = cfg.script.confirmed;
        if (cfg.script.run) {
            request_run(su, sh);
        }
        return su;
    }
    if (cfg.script_dir.empty()) {
        return su;
    }
    su.available = true;
    rescan(cfg, su, sh);
    for (size_t i = 0; i < su.files.size(); ++i) {
        if (_wcsicmp(su.files[i].c_str(), L"RFTrafficEditor.lua") == 0) {
            su.sel = (int)i;
        }
    }
    if (su.sel < 0 && !su.files.empty()) {
        su.sel = 0;
    }
    if (su.sel >= 0) {
        load_script(cfg, su, sh, su.sel);
    }
    return su;
}

ScriptPacket script_packet(const Row& r) {
    ScriptPacket p;
    p.seq = r.rec.seq;
    p.t_ms = r.t_ms;
    p.dir = r.rec.dir;
    p.main = r.rec.main;
    p.sub = r.rec.sub;
    p.size = r.rec.size;
    p.edited = r.rec.edited;
    p.tool = r.rec.tool;
    p.bytes = r.rec.bytes.data();
    p.len = r.rec.bytes.size();
    p.name = r.name.c_str();
    p.status = status_name(r.status);
    p.layout = r.layout ? r.layout->name.c_str() : "";
    return p;
}

void script_sink(const char* line) {
    logmsg("script: %s", line);
}

void publish_script(const ScriptHost& sh) {
    const ScriptStats s = sh.stats();
    g_scriptState.store((int)s.state);
    g_scriptRuns.store(s.runs);
    g_scriptPackets.store(s.packets);
    g_scriptCallbacks.store(s.callbacks);
    g_scriptSkipped.store(s.skipped);
    g_scriptTrips.store(s.trips);
    g_scriptErrors.store(s.errors);
    g_scriptLines.store(s.lines);
    g_scriptSent.store(s.sent);
    g_scriptInjected.store(s.injected);
    g_scriptHeld.store(s.held);
    g_scriptRefused.store(s.refused);
    g_scriptTicks.store(s.ticks);
    g_scriptTimers.store(s.timers);
}

Draft row_draft(const Row& r, bool other, const PacketDb* db) {
    Draft d;
    d.dir = other ? (r.rec.dir == Dir::C2S ? Dir::S2C : Dir::C2S) : r.rec.dir;
    d.main = r.rec.main;
    d.sub = r.rec.sub;
    char buf[128];
    if (r.rec.bytes.size() < r.rec.size) {
        std::snprintf(buf, sizeof buf, "#%llu was captured truncated (%zu of %u bytes) -- it cannot be resent whole",
                      (unsigned long long)r.rec.seq, r.rec.bytes.size(), (unsigned)r.rec.size);
        d.err = buf;
        return d;
    }
    d.bytes = r.rec.bytes;
    if (db) {
        const Decoded dc = db->classify(d.dir, d.main, d.sub, (uint16_t)d.bytes.size());
        d.status = dc.status;
        d.label = describe(dc, (uint16_t)d.bytes.size());
    }
    if (other) {
        std::snprintf(buf, sizeof buf, "#%llu %s to the other side", (unsigned long long)r.rec.seq,
                      dir_name(r.rec.dir));
    } else {
        std::snprintf(buf, sizeof buf, "resend of #%llu", (unsigned long long)r.rec.seq);
    }
    d.from = buf;
    d.ok = true;
    return d;
}

struct Range {
    int off = -1, len = 0;

    bool has(size_t b) const {
        return off >= 0 && (int)b >= off && (int)b < off + len;
    }

    bool operator==(const Range&) const = default;
};

struct DetailState {
    PacketView view;
    Range pinned;
    Range hover;
    Range shown;
    int rows = 0;
    double copied_until = 0.0;
    const char* copied = "";
    Range rule_range;
    std::string rule_name;
};

bool create_rtv() {
    ID3D11Texture2D* back = nullptr;
    if (FAILED(g_swap->GetBuffer(0, __uuidof(ID3D11Texture2D), (void**)&back)) || !back) {
        return false;
    }
    const HRESULT hr = g_dev->CreateRenderTargetView(back, nullptr, &g_rtv);
    back->Release();
    return SUCCEEDED(hr) && g_rtv;
}

void release_rtv() {
    if (g_rtv) {
        g_rtv->Release();
        g_rtv = nullptr;
    }
}

void release_device() {
    release_rtv();
    if (g_swap) {
        g_swap->Release();
        g_swap = nullptr;
    }
    if (g_ctx) {
        g_ctx->Release();
        g_ctx = nullptr;
    }
    if (g_dev) {
        g_dev->Release();
        g_dev = nullptr;
    }
}

HRESULT create_device(HWND hwnd, const char** drv, D3D_FEATURE_LEVEL* fl) {
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hwnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    const D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};
    const D3D_DRIVER_TYPE types[] = {D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_WARP};
    const char* names[] = {"hardware", "WARP"};
    HRESULT hr = E_FAIL;
    for (int i = 0; i < 2; ++i) {
        hr = D3D11CreateDeviceAndSwapChain(nullptr, types[i], nullptr, 0, levels, 2, D3D11_SDK_VERSION, &sd, &g_swap,
                                           &g_dev, fl, &g_ctx);
        if (SUCCEEDED(hr)) {
            *drv = names[i];
            return hr;
        }
    }
    return hr;
}

LRESULT WINAPI wnd_proc(HWND h, UINT msg, WPARAM w, LPARAM l) {
    if (ImGui_ImplWin32_WndProcHandler(h, msg, w, l)) {
        return 1;
    }
    switch (msg) {
    case WM_SIZE:
        if (w != SIZE_MINIMIZED) {
            g_resizeW = (UINT)LOWORD(l);
            g_resizeH = (UINT)HIWORD(l);
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((w & 0xFFF0) == SC_KEYMENU) {
            return 0;
        }
        break;
    case WM_CLOSE:
        ShowWindow(h, SW_MINIMIZE);
        return 0;
    }
    return DefWindowProcW(h, msg, w, l);
}

void add_font(ImGuiIO& io) {
    wchar_t path[MAX_PATH];
    const UINT n = GetWindowsDirectoryW(path, MAX_PATH);
    if (n > 0 && n + 20 < MAX_PATH) {
        wcscat(path, L"\\Fonts\\consola.ttf");
        char u8[MAX_PATH * 3];
        if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES &&
            WideCharToMultiByte(CP_UTF8, 0, path, -1, u8, (int)sizeof u8, nullptr, nullptr) > 0 &&
            io.Fonts->AddFontFromFileTTF(u8, 15.0f)) {
            return;
        }
    }
    io.Fonts->AddFontDefault();
}

void drain(PacketModel& m, const UiConfig& cfg, std::vector<PacketRec>& batch, std::string& text, ScriptHost& sh) {
    sh.begin_frame();
    for (size_t round = 0; round < kRounds; ++round) {
        batch.clear();
        text.clear();
        uint64_t dropped = 0;
        const size_t n = cfg.drain(batch, kBatch, dropped);
        if (dropped) {
            m.add_dropped(dropped);
            logmsg("capture ring overflow: %llu packet(s) dropped (total %llu)", (unsigned long long)dropped,
                   (unsigned long long)m.ring_dropped());
        }
        for (PacketRec& r : batch) {
            m.push(std::move(r), cfg.log_packets ? &text : nullptr);
        }
        if (cfg.log_packets && !text.empty()) {
            cfg.log_packets(text.data(), text.size());
        }
        if (sh.running()) {
            for (size_t i = m.size() - std::min(n, m.size()); i < m.size(); ++i) {
                sh.on_packet(script_packet(m.at(i)));
            }
        }
        if (n < kBatch) {
            return;
        }
    }
}

void publish(const PacketModel& m) {
    g_ingested.store(m.ingested());
    g_dropped.store(m.ring_dropped());
    g_rows.store(m.size());
    g_iter.fetch_add(1);
}

void switch_capture(const UiConfig& cfg, bool on) {
    if (!cfg.set_capture) {
        return;
    }
    cfg.set_capture(on);
    if (on) {
        logmsg("capture: on (UI) -- packets are captured, listed and logged again");
    } else {
        logmsg("capture: off (UI) -- the hooks stop snapshotting packets: nothing is listed or logged until it "
               "is switched back on; the game's traffic passes through untouched");
    }
}

void dir_cell(Dir d) {
    const ImVec4& c = d == Dir::C2S ? kC2S : kS2C;
    const ImU32 col = ImGui::GetColorU32(c);
    const float h = ImGui::GetTextLineHeight(), w = h * 0.7f;
    const ImVec2 p = ImGui::GetCursorScreenPos();
    const float l = p.x, r = p.x + w, cx = p.x + w * 0.5f, top = p.y + h * 0.2f, bot = p.y + h * 0.8f;
    ImDrawList* dl = ImGui::GetWindowDrawList();
    if (d == Dir::C2S) {
        dl->AddTriangleFilled(ImVec2(cx, top), ImVec2(r, bot), ImVec2(l, bot), col);
    } else {
        dl->AddTriangleFilled(ImVec2(l, top), ImVec2(r, top), ImVec2(cx, bot), col);
    }
    ImGui::Dummy(ImVec2(w, h));
    ImGui::SameLine();
    ImGui::TextColored(c, "%s", dir_name(d));
}

const ImVec4& status_color(Status s) {
    return s == Status::Ok         ? kOk
           : s == Status::Var      ? kVar
           : s == Status::Mismatch ? kMismatch
           : s == Status::Trigger  ? kTrigger
                                   : kDim;
}

void status_cell(const Row& r) {
    ImGui::TextColored(status_color(r.status), "%s", status_name(r.status));
    if (r.rec.edited) {
        ImGui::SameLine();
        ImGui::TextColored(kEdited, "edited");
    }
    if (r.rec.tool) {
        ImGui::SameLine();
        ImGui::TextColored(kTool, "tool");
    }
}

int route_line(const UiConfig& cfg, Dir dir, uint8_t main, uint8_t sub) {
    const PacketDb* db = cfg.db;
    if (!db || dir != Dir::S2C || !db->has_client()) {
        return -1;
    }
    const ClientRoute r = db->client_route(main, sub);
    const bool warn = r.refused() && route_on_host(r, cfg.host_build);
    if (warn) {
        g_routeWarns.fetch_add(1);
    }
    ImGui::TextColored(warn ? kWarn : kDim, "%s", route_text(r, main, sub, cfg.host_build).c_str());
    return (int)r.kind;
}

int server_line(const UiConfig& cfg, Dir dir, uint8_t main, uint8_t sub) {
    const PacketDb* db = cfg.db;
    if (!db || dir != Dir::C2S || !db->has_server()) {
        return -1;
    }
    const ServerRoute r = db->server_route(main, sub);
    const bool warn = r.refused() && route_on_host(r, cfg.host_build);
    if (warn) {
        g_serverWarns.fetch_add(1);
    }
    ImGui::TextColored(warn ? kWarn : kDim, "%s", server_text(r, main, sub, cfg.host_build).c_str());
    return (int)r.kind;
}

const struct {
    const char* label;
    CopyKind kind;
    const char* what;
} kCopy[] = {{"Copy hex", CopyKind::Hex, "hex"},
             {"Copy decoded", CopyKind::Decoded, "decoded"},
             {"Copy snippet", CopyKind::Snippet, "snippet"}};

std::string mute_label(uint32_t k, const PacketDb* db) {
    const Dir d = (k >> 16) ? Dir::S2C : Dir::C2S;
    const uint8_t mn = (uint8_t)(k >> 8), sb = (uint8_t)k;
    char buf[32];
    std::snprintf(buf, sizeof buf, "%s (%u,%u)", dir_name(d), (unsigned)mn, (unsigned)sb);
    std::string s = buf;
    if (db) {
        const Decoded dc = db->classify(d, mn, sb, 0);
        for (size_t i = 0; i < dc.candidates.size(); ++i) {
            s += i ? " | " : " ";
            s += dc.candidates[i];
        }
        if (dc.candidates.empty() && !dc.name.empty()) {
            s += " " + dc.name;
        }
    }
    return s;
}

void resend_items(const Row& r, const UiConfig& cfg, ListState& st, bool menu) {
    const bool c2s = r.rec.dir == Dir::C2S;
    const bool whole = r.rec.bytes.size() >= r.rec.size;
    const bool can = cfg.queue_action && whole;
    for (int k = 0; k < 2; ++k) {
        const bool other = k == 1;
        const Dir to = other ? (c2s ? Dir::S2C : Dir::C2S) : r.rec.dir;
        const char* label = menu ? (other ? (c2s ? "Inject to client (other side)" : "Send to server (other side)")
                                          : (c2s ? "Resend to server" : "Re-inject to client"))
                                 : (other ? "To other side"
                                    : c2s ? "Resend"
                                          : "Re-inject");
        bool hit = false;
        if (menu) {
            hit = ImGui::MenuItem(label, nullptr, false, can);
        } else {
            ImGui::SameLine();
            ImGui::BeginDisabled(!can);
            hit = ImGui::Button(label);
            ImGui::EndDisabled();
        }
        if (hit && can) {
            st.resend = r.rec.seq;
            st.resend_other = other;
        }
        if (!ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip | ImGuiHoveredFlags_AllowWhenDisabled)) {
            continue;
        }
        char buf[192];
        if (!cfg.queue_action) {
            ImGui::SetTooltip("No action queue: the hooks are not installed.");
        } else if (!whole) {
            ImGui::SetTooltip("Captured %u of %u bytes (4 KB cap): it cannot be sent whole.",
                              (unsigned)r.rec.bytes.size(), (unsigned)r.rec.size);
        } else {
            std::snprintf(buf, sizeof buf, "Queue these %u bytes as %s (%u,%u): %s", (unsigned)r.rec.bytes.size(),
                          dir_name(to), (unsigned)r.rec.main, (unsigned)r.rec.sub,
                          to == Dir::C2S ? "send to the server (CNetworkMgr::SendNetMessage)"
                                         : "inject into the client (CNetworkMgr::AnalysisZoneServerPacket)");
            std::string t = buf;
            if (cfg.db) {
                t += "\nThe list will label it: " +
                     describe(cfg.db->classify(to, r.rec.main, r.rec.sub, (uint16_t)r.rec.bytes.size()),
                              (uint16_t)r.rec.bytes.size());
            }
            if (to == Dir::S2C && cfg.db && cfg.db->has_client()) {
                t += "\n" +
                     route_text(cfg.db->client_route(r.rec.main, r.rec.sub), r.rec.main, r.rec.sub, cfg.host_build);
            }
            if (to == Dir::C2S && cfg.db && cfg.db->has_server()) {
                t += "\n" +
                     server_text(cfg.db->server_route(r.rec.main, r.rec.sub), r.rec.main, r.rec.sub, cfg.host_build);
            }
            t += "\nThe first send / inject of the session asks first.";
            ImGui::SetTooltip("%s", t.c_str());
        }
    }
}

void row_menu(const Row& r, const UiConfig& cfg, ListState& st, Filter& edit) {
    for (const auto& c : kCopy) {
        if (ImGui::MenuItem(c.label)) {
            PacketView v;
            build_view(v, r, cfg.db);
            ImGui::SetClipboardText(copy_text(v, r, c.kind).c_str());
        }
    }
    ImGui::Separator();
    resend_items(r, cfg, st, true);
    if (ImGui::MenuItem("Open in composer")) {
        st.load = r.rec.seq;
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip)) {
        ImGui::SetTooltip("Its direction, opcode and captured bytes into the Composer -- edit them there, then send.");
    }
    if (ImGui::MenuItem("New patch rule from this row")) {
        st.rule_row = r.rec.seq;
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip)) {
        ImGui::SetTooltip("A rule for %s (%u,%u) in the Rules editor: write its first bytes at +0000 -- their current\n"
                          "values, so it changes nothing until you edit it there. Then Apply (and arm Rules).",
                          dir_name(r.rec.dir), (unsigned)r.rec.main, (unsigned)r.rec.sub);
    }
    ImGui::Separator();
    const uint32_t k = mute_key(r.rec.dir, r.rec.main, r.rec.sub);
    if (ImGui::MenuItem(("Mute " + mute_label(k, cfg.db)).c_str())) {
        set_muted(edit, k, true);
    }
}

std::string row_tooltip(const Row& r, const UiConfig& cfg) {
    const PacketDb* db = cfg.db;
    char buf[96];
    std::snprintf(buf, sizeof buf, "#%llu  %s (%u,%u)  size=%u\n", (unsigned long long)r.rec.seq, dir_name(r.rec.dir),
                  (unsigned)r.rec.main, (unsigned)r.rec.sub, (unsigned)r.rec.size);
    std::string t = buf;
    t += r.label.empty() ? "no packet db: raw" : r.label;
    if (r.rec.dir == Dir::S2C && db && db->has_client()) {
        t += "\n" + route_text(db->client_route(r.rec.main, r.rec.sub), r.rec.main, r.rec.sub, cfg.host_build);
    }
    if (r.rec.dir == Dir::C2S && db && db->has_server()) {
        t += "\n" + server_text(db->server_route(r.rec.main, r.rec.sub), r.rec.main, r.rec.sub, cfg.host_build);
    }
    if (r.rec.bytes.size() < r.rec.size) {
        std::snprintf(buf, sizeof buf, "\ncaptured %u of %u bytes (4 KB cap)", (unsigned)r.rec.bytes.size(),
                      (unsigned)r.rec.size);
        t += buf;
    }
    if (r.rec.edited) {
        size_t n = 0;
        for (const EditRun& e : edit_runs(r.rec.before, r.rec.bytes)) {
            n += e.len;
        }
        t += r.rec.before.empty() ? std::string("\nedited by a patch rule (no before-image)")
                                  : "\nedited by a patch rule: " + std::to_string(n) + " captured byte(s) changed";
    }
    if (r.rec.tool) {
        t += r.rec.dir == Dir::C2S ? "\nsent by the composer (not the game)"
                                   : "\ninjected by the composer (not the server)";
    }
    return t;
}

void draw_row(const Row& r, ListState& st, const UiConfig& cfg, Filter& edit) {
    ImGui::TableNextRow();
    if (r.status == Status::Mismatch) {
        ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, kMismatchBg);
    }
    const bool dim = r.status == Status::Unknown;
    if (dim) {
        ImGui::PushStyleColor(ImGuiCol_Text, kDim);
    }
    char buf[32];
    ImGui::TableNextColumn();
    std::snprintf(buf, sizeof buf, "%llu", (unsigned long long)r.rec.seq);
    if (ImGui::Selectable(buf, st.selected == r.rec.seq, ImGuiSelectableFlags_SpanAllColumns)) {
        st.selected = st.selected == r.rec.seq ? kNoSel : r.rec.seq;
    }
    if (ImGui::BeginPopupContextItem()) {
        if (dim) {
            ImGui::PopStyleColor();
        }
        row_menu(r, cfg, st, edit);
        if (dim) {
            ImGui::PushStyleColor(ImGuiCol_Text, kDim);
        }
        ImGui::EndPopup();
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip)) {
        ImGui::SetTooltip("%s", row_tooltip(r, cfg).c_str());
    }
    ImGui::TableNextColumn();
    ImGui::Text("%.3f", r.t_ms / 1000.0);
    ImGui::TableNextColumn();
    dir_cell(r.rec.dir);
    ImGui::TableNextColumn();
    ImGui::Text("(%u,%u)", (unsigned)r.rec.main, (unsigned)r.rec.sub);
    ImGui::TableNextColumn();
    ImGui::TextUnformatted(r.name.empty() ? "-" : r.name.c_str());
    ImGui::TableNextColumn();
    ImGui::Text("%u%s", (unsigned)r.rec.size, r.rec.bytes.size() < r.rec.size ? "*" : "");
    ImGui::TableNextColumn();
    status_cell(r);
    if (dim) {
        ImGui::PopStyleColor();
    }
}

void draw_list(const PacketModel& m, const FilterView& fv, ListState& st, Filter& edit, const UiConfig& cfg, bool grew,
               float height) {
    const ImGuiTableFlags tf = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersV |
                               ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingFixedFit;
    if (!ImGui::BeginTable("packets", 7, tf, ImVec2(0.0f, height))) {
        return;
    }
    auto w = [](const char* s) {
        return ImGui::CalcTextSize(s).x;
    };
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, w("0000000"));
    ImGui::TableSetupColumn("time (s)", ImGuiTableColumnFlags_WidthFixed, w("00000.000"));
    ImGui::TableSetupColumn("dir", ImGuiTableColumnFlags_WidthFixed, w("MM C2S"));
    ImGui::TableSetupColumn("(main,sub)", ImGuiTableColumnFlags_WidthFixed, w("(main,sub)"));
    ImGui::TableSetupColumn("name", ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableSetupColumn("size", ImGuiTableColumnFlags_WidthFixed, w("00000*"));
    ImGui::TableSetupColumn("status", ImGuiTableColumnFlags_WidthFixed, w("mismatch edited tool"));
    ImGui::TableHeadersRow();
    const bool stick = st.follow && ImGui::GetScrollY() >= ImGui::GetScrollMaxY();
    ImGuiListClipper clip;
    clip.Begin((int)fv.size());
    while (clip.Step()) {
        for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
            if (const Row* r = m.find(fv.seq((size_t)i))) {
                draw_row(*r, st, cfg, edit);
            }
        }
    }
    if (stick && grew) {
        ImGui::SetScrollHereY(1.0f);
    }
    ImGui::EndTable();
}

void capture_toggle(const UiConfig& cfg, ListState& st) {
    ImGui::BeginDisabled(!cfg.set_capture);
    if (ImGui::Checkbox("Capture", &st.capture)) {
        switch_capture(cfg, st.capture);
    }
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip | ImGuiHoveredFlags_AllowWhenDisabled)) {
        ImGui::SetTooltip("Off: the hooks stop snapshotting packets -- no new rows, no new log lines.\n"
                          "The game's traffic passes through (armed patch rules still edit it).");
    }
}

void draw_filter_bar(FilterBar& fb, const PacketDb* db) {
    Filter& f = fb.edit;
    const ImGuiStyle& sty = ImGui::GetStyle();
    auto w = [&](const char* s) {
        return ImGui::CalcTextSize(s).x + sty.FramePadding.x * 2.0f;
    };
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("show");
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, kC2S);
    ImGui::Checkbox("C2S", &f.dir[(size_t)Dir::C2S]);
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, kS2C);
    ImGui::Checkbox("S2C", &f.dir[(size_t)Dir::S2C]);
    ImGui::PopStyleColor();
    for (const Status s : {Status::Ok, Status::Var, Status::Mismatch, Status::Trigger, Status::Unknown}) {
        ImGui::SameLine();
        ImGui::PushStyleColor(ImGuiCol_Text, status_color(s));
        ImGui::Checkbox(status_name(s), &f.status[(size_t)s]);
        ImGui::PopStyleColor();
        if (s == Status::Trigger && ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip)) {
            ImGui::SetTooltip("C2S opcodes the server's handler reads no payload of -- named by that handler");
        }
    }
    ImGui::SameLine();
    ImGui::Checkbox("edited only", &f.edited_only);
    ImGui::SameLine();
    ImGui::TextDisabled("  opcode");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(w("(255,255)  "));
    const bool bad = !fb.opcode_ok;
    if (bad) {
        ImGui::PushStyleColor(ImGuiCol_FrameBg, kBadField);
    }
    ImGui::InputTextWithHint("##opcode", "main[,sub]", fb.opcode, sizeof fb.opcode);
    if (bad) {
        ImGui::PopStyleColor();
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip)) {
        ImGui::SetTooltip("4 = main 4, any sub;  4,1 or (4,1) = exactly (4,1);  0x1F hex is fine");
    }
    fb.opcode_ok = parse_opcode(fb.opcode, f.main, f.sub);
    if (!fb.opcode_ok) {
        f.main = f.sub = -1;
    }
    ImGui::SameLine();
    ImGui::TextDisabled("  size");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(w("000000"));
    ImGui::InputInt("##smin", &f.size_min, 0, 0);
    ImGui::SameLine();
    ImGui::TextDisabled("..");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(w("000000"));
    ImGui::InputInt("##smax", &f.size_max, 0, 0);
    f.size_min = std::clamp(f.size_min, 0, 0xFFFF);
    f.size_max = std::clamp(f.size_max, 0, 0xFFFF);
    ImGui::SetNextItemWidth(w("_base_download_result_zocl"));
    ImGui::InputTextWithHint("##name", "name contains", fb.name, sizeof fb.name);
    f.name = fb.name;
    ImGui::SameLine();
    ImGui::SetNextItemWidth(
        std::max(ImGui::GetContentRegionAvail().x - w("Muted (000)") - w("Reset") - sty.ItemSpacing.x * 2.0f, 150.0f));
    ImGui::InputTextWithHint("##text", "search the decode: fields, values, labels, hex (e.g. 00 00 80 3F)", fb.text,
                             sizeof fb.text);
    f.text = fb.text;
    ImGui::SameLine();
    char mb[32];
    std::snprintf(mb, sizeof mb, "Muted (%zu)###muted", f.muted.size());
    if (ImGui::Button(mb)) {
        ImGui::OpenPopup("muted");
    }
    if (ImGui::BeginPopup("muted")) {
        uint32_t unmute = ~0u;
        bool all = false;
        if (f.muted.empty()) {
            ImGui::TextDisabled("nothing muted -- right-click a row: Mute");
        }
        for (const uint32_t k : f.muted) {
            ImGui::PushID((int)k);
            if (ImGui::SmallButton("unmute")) {
                unmute = k;
            }
            ImGui::SameLine();
            ImGui::TextUnformatted(mute_label(k, db).c_str());
            ImGui::PopID();
        }
        if (!f.muted.empty() && ImGui::Button("Unmute all")) {
            all = true;
        }
        ImGui::EndPopup();
        if (unmute != ~0u) {
            set_muted(f, unmute, false);
        }
        if (all) {
            f.muted.clear();
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Reset")) {
        std::vector<uint32_t> keep = std::move(f.muted);
        f = Filter{};
        f.muted = std::move(keep);
        fb.opcode[0] = fb.name[0] = fb.text[0] = '\0';
        fb.opcode_ok = true;
    }
}

double now_ms(const UiConfig& cfg) {
    LARGE_INTEGER q;
    QueryPerformanceCounter(&q);
    return (double)(q.QuadPart - cfg.qpc_base) / cfg.qpc_per_ms;
}

std::string rate_text(double pkts, double bytes) {
    char buf[48];
    if (bytes < 1024.0) {
        std::snprintf(buf, sizeof buf, "%.1f/s %.0f B/s", pkts, bytes);
    } else {
        std::snprintf(buf, sizeof buf, "%.1f/s %.1f KB/s", pkts, bytes / 1024.0);
    }
    return buf;
}

void draw_status(PacketModel& m, const FilterView& fv, size_t pending, const UiConfig& cfg, const ListState& st,
                 const RulesUi& ru, const ScriptUi& su, const ScriptHost& sh) {
    ImGui::Text("shown %zu of %zu rows (C2S %zu / S2C %zu)   ok %zu  var %zu  mismatch %zu  trigger %zu  unknown %zu   "
                "seen %llu  evicted %llu   ",
                fv.size(), m.size(), m.count(Dir::C2S), m.count(Dir::S2C), m.count(Status::Ok), m.count(Status::Var),
                m.count(Status::Mismatch), m.count(Status::Trigger), m.count(Status::Unknown),
                (unsigned long long)m.ingested(), (unsigned long long)m.evicted());
    ImGui::SameLine(0.0f, 0.0f);
    ImGui::TextColored(m.ring_dropped() ? kWarn : ImGui::GetStyleColorVec4(ImGuiCol_Text), "ring dropped %llu",
                       (unsigned long long)m.ring_dropped());
    if (pending) {
        ImGui::SameLine();
        ImGui::TextColored(kWarn, "  filtering... %zu rows left", pending);
    }
    if (st.capture) {
        ImGui::TextColored(kOk, "capture on");
    } else {
        ImGui::TextColored(kWarn, "CAPTURE OFF");
    }
    if (cfg.arm_rules) {
        ImGui::SameLine();
        if (ru.armed) {
            const RuleStats rs = cfg.rule_stats ? cfg.rule_stats() : RuleStats{};
            ImGui::TextColored(kEdited, "   rules ARMED %zu (edited C2S %llu  S2C %llu)", ru.active,
                               (unsigned long long)rs.edited[0], (unsigned long long)rs.edited[1]);
        } else {
            ImGui::TextDisabled("   rules off (%zu active of %zu)", ru.active, ru.list.size());
        }
        if (ru.script_changed) {
            ImGui::SameLine(0.0f, 0.0f);
            ImGui::TextColored(kWarn, " (script %s)", ru.script_by.c_str());
        }
    }
    if (su.available) {
        ImGui::SameLine();
        switch (sh.state()) {
        case ScriptState::Running:
            ImGui::TextColored(kEdited, "   script RUNNING %s", su.name.c_str());
            break;
        case ScriptState::Tripped:
            ImGui::TextColored(kWarn, "   script TRIPPED (watchdog) -- see Scripts");
            break;
        case ScriptState::Failed:
            ImGui::TextColored(kMismatch, "   script FAILED -- see Scripts");
            break;
        default:
            ImGui::TextDisabled("   script off");
            break;
        }
    }
    const Rates rt = m.rates(now_ms(cfg));
    ImGui::SameLine();
    ImGui::Text("   rate  C2S %s   S2C %s", rate_text(rt.pkts[0], rt.bytes[0]).c_str(),
                rate_text(rt.pkts[1], rt.bytes[1]).c_str());
    ImGui::SameLine();
    if (cfg.db) {
        ImGui::Text("   db %zu structs / %zu mappings", cfg.db->struct_count(), cfg.db->opcode_count());
        if (cfg.db->has_client()) {
            ImGui::SameLine();
            ImGui::TextDisabled("   client %s dispatch: %zu cases / %zu arms", cfg.db->client_build().c_str(),
                                cfg.db->client_category_count(), cfg.db->client_arm_count());
            if (!cfg.host_build.empty() && cfg.host_build != cfg.db->client_build()) {
                ImGui::SameLine(0.0f, 0.0f);
                ImGui::TextDisabled(" -- a reference, this client is %s", cfg.host_build.c_str());
            }
        }
        if (cfg.db->has_server()) {
            ImGui::SameLine();
            ImGui::TextDisabled("   server %s dispatch: %zu cases / %zu arms (%zu triggers)",
                                cfg.db->server_build().c_str(), cfg.db->server_category_count(),
                                cfg.db->server_arm_count(), cfg.db->server_trigger_count());
            if (!cfg.host_build.empty() && cfg.host_build != cfg.db->server_build()) {
                ImGui::SameLine(0.0f, 0.0f);
                ImGui::TextDisabled(" -- a reference, this client is %s", cfg.host_build.c_str());
            }
        }
    } else {
        ImGui::TextColored(kWarn, "   db not loaded -- raw");
    }
}

void splitter(ListState& st) {
    ImGui::InvisibleButton("##split", ImVec2(std::max(ImGui::GetContentRegionAvail().x, 1.0f), kSplitH));
    if (ImGui::IsItemHovered() || ImGui::IsItemActive()) {
        ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeNS);
    }
    if (ImGui::IsItemActive()) {
        st.detail_h -= ImGui::GetIO().MouseDelta.y;
    }
    const ImVec2 a = ImGui::GetItemRectMin(), b = ImGui::GetItemRectMax();
    const float y = (a.y + b.y) * 0.5f;
    ImGui::GetWindowDrawList()->AddLine(ImVec2(a.x, y), ImVec2(b.x, y), ImGui::GetColorU32(ImGuiCol_Separator), 2.0f);
}

void track(Range rg, DetailState& d) {
    if (ImGui::IsItemHovered()) {
        d.hover = rg;
    }
    if (ImGui::IsItemClicked() && !ImGui::IsItemToggledOpen()) {
        d.pinned = d.pinned == rg ? Range{} : rg;
    }
}

void span_cells(int off, int size, const char* type, const char* value, bool absent) {
    ImGui::TableNextColumn();
    ImGui::Text("+%04X", (unsigned)off);
    ImGui::TableNextColumn();
    ImGui::Text("%d", size);
    ImGui::TableNextColumn();
    ImGui::TextUnformatted(type);
    ImGui::TableNextColumn();
    if (absent) {
        ImGui::TextDisabled("%s", value);
    } else {
        ImGui::TextUnformatted(value);
    }
}

void field_menu(const Row& r, Range rg, const std::string& name, DetailState& d) {
    if (!ImGui::BeginPopupContextItem()) {
        return;
    }
    const bool have = rg.off >= 0 && (size_t)rg.off < r.rec.bytes.size();
    char label[192];
    std::snprintf(label, sizeof label, "New patch rule: write %s (+%04X, %d B)", name.c_str(),
                  (unsigned)std::max(rg.off, 0), std::min(rg.len, (int)kMaxRuleBytes));
    if (ImGui::MenuItem(label, nullptr, false, have)) {
        d.rule_range = rg;
        d.rule_name = name;
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip | ImGuiHoveredFlags_AllowWhenDisabled)) {
        ImGui::SetTooltip(
            "%s", have ? "Adds a rule to the Rules editor: on this opcode, write these bytes at this offset --\n"
                         "their current values, so it changes nothing until you edit them there. Then Apply."
                       : "The captured payload does not reach this field.");
    }
    ImGui::EndPopup();
}

void span_rows(const std::vector<FieldSpan>& spans, const Row& r, DetailState& d, const UiConfig& cfg, int depth,
               const std::string& path) {
    const uint8_t* p = r.rec.bytes.data();
    const size_t n = r.rec.bytes.size();
    for (size_t k = 0; k < spans.size(); ++k) {
        const FieldSpan& sp = spans[k];
        const bool field = sp.kind == FieldSpan::Kind::Field;
        const Struct* elem = field && cfg.db && !sp.field->ref.empty() ? cfg.db->get(sp.field->ref) : nullptr;
        const bool nested = elem && elem->size > 0 && depth < kMaxNest;
        const Range rg{sp.offset, sp.size};
        ImGui::PushID((int)k);
        ImGui::TableNextRow();
        ++d.rows;
        if (d.shown == rg) {
            ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, kHlRow);
        }
        ImGui::TableNextColumn();
        std::string name = field ? sp.field->name : sp.kind == FieldSpan::Kind::Gap ? "(unmapped)" : "(beyond sizeof)";
        if (field && sp.field->count > 1) {
            name += "[" + std::to_string(sp.field->count) + "]";
        }
        ImGuiTreeNodeFlags tf = ImGuiTreeNodeFlags_SpanAllColumns;
        tf |= nested ? ImGuiTreeNodeFlags_OpenOnArrow | ImGuiTreeNodeFlags_OpenOnDoubleClick
                     : ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen;
        if (nested && cfg.open_nested) {
            ImGui::SetNextItemOpen(true, ImGuiCond_Once);
        }
        if (!field) {
            ImGui::PushStyleColor(ImGuiCol_Text, sp.kind == FieldSpan::Kind::Gap ? kDim : kMismatch);
        }
        const bool open = ImGui::TreeNodeEx("##f", tf, "%s", name.c_str());
        if (!field) {
            ImGui::PopStyleColor();
        }
        track(rg, d);
        if (field) {
            field_menu(r, rg, path + sp.field->name, d);
        }
        span_cells(sp.offset, sp.size, field ? sp.field->type.c_str() : "", sp.value.c_str(), sp.avail == 0);
        if (nested && open) {
            for (int i = 0; i < sp.field->count; ++i) {
                const std::vector<FieldSpan> el = map_element(*elem, sp, i, p, n);
                if (sp.field->count == 1) {
                    span_rows(el, r, d, cfg, depth + 1, path + sp.field->name + ".");
                    continue;
                }
                const Range er{sp.offset + i * elem->size, elem->size};
                const std::string ename = path + sp.field->name + "[" + std::to_string(i) + "]";
                ImGui::PushID(i);
                ImGui::TableNextRow();
                ++d.rows;
                if (d.shown == er) {
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, kHlRow);
                }
                ImGui::TableNextColumn();
                if (cfg.open_nested) {
                    ImGui::SetNextItemOpen(true, ImGuiCond_Once);
                }
                const bool eopen =
                    ImGui::TreeNodeEx("##e",
                                      ImGuiTreeNodeFlags_SpanAllColumns | ImGuiTreeNodeFlags_OpenOnArrow |
                                          ImGuiTreeNodeFlags_OpenOnDoubleClick,
                                      "[%d]", i);
                track(er, d);
                field_menu(r, er, ename, d);
                const bool absent = er.off >= (int)n;
                span_cells(er.off, er.len, sp.field->type.c_str(), absent ? "<absent>" : "", absent);
                if (eopen) {
                    span_rows(el, r, d, cfg, depth + 1, ename + ".");
                    ImGui::TreePop();
                }
                ImGui::PopID();
            }
            ImGui::TreePop();
        }
        ImGui::PopID();
    }
}

ImU32 byte_bg(const PacketView& v, Range shown, size_t i) {
    if (shown.has(i)) {
        return kHlBg;
    }
    const int o = i < v.owner.size() ? v.owner[i] : -1;
    if (o < 0) {
        return 0;
    }
    const FieldSpan::Kind k = v.spans[(size_t)o].kind;
    return k == FieldSpan::Kind::Gap     ? kGapBg
           : k == FieldSpan::Kind::Extra ? kExtraBg
           : (o & 1)                     ? kFieldBgB
                                         : kFieldBgA;
}

Range byte_range(const PacketView& v, size_t i) {
    const int o = i < v.owner.size() ? v.owner[i] : -1;
    if (o < 0) {
        return Range{(int)i, 1};
    }
    return Range{v.spans[(size_t)o].offset, v.spans[(size_t)o].size};
}

void hex_cell(const char* text, int len, size_t i, DetailState& d, float w, float h) {
    const ImVec2 p = ImGui::GetCursorScreenPos();
    const ImVec2 q(p.x + w, p.y + h);
    if (const ImU32 bg = byte_bg(d.view, d.shown, i)) {
        ImGui::GetWindowDrawList()->AddRectFilled(p, q, bg);
    }
    ImGui::TextUnformatted(text, text + len);
    if (ImGui::IsWindowHovered() && ImGui::IsMouseHoveringRect(p, q)) {
        const Range rg = byte_range(d.view, i);
        d.hover = rg;
        if (ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            d.pinned = d.pinned == rg ? Range{} : rg;
        }
    }
}

void draw_hex(const Row& r, DetailState& d) {
    ImGui::BeginChild("hex", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders, ImGuiWindowFlags_HorizontalScrollbar);
    static const char kHex[] = "0123456789ABCDEF";
    const std::vector<uint8_t>& b = r.rec.bytes;
    const float cw = ImGui::CalcTextSize("0").x, lh = ImGui::GetTextLineHeight();
    if (b.empty()) {
        ImGui::TextDisabled("(empty payload)");
    }
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0.0f, ImGui::GetStyle().ItemSpacing.y));
    ImGuiListClipper clip;
    clip.Begin((int)((b.size() + 15) / 16));
    while (clip.Step()) {
        for (int row = clip.DisplayStart; row < clip.DisplayEnd; ++row) {
            const size_t first = (size_t)row * 16, end = std::min(b.size(), first + 16);
            const float x0 = ImGui::GetCursorPosX();
            ImGui::TextDisabled("%04X  ", (unsigned)first);
            for (size_t i = first; i < end; ++i) {
                ImGui::SameLine();
                const char t[3] = {kHex[b[i] >> 4], kHex[b[i] & 0xF], ' '};
                const bool join = i + 1 < end && byte_bg(d.view, d.shown, i + 1) == byte_bg(d.view, d.shown, i);
                hex_cell(t, 3, i, d, cw * (join ? 3.0f : 2.0f), lh);
            }
            ImGui::SameLine(x0 + cw * 55.0f);
            for (size_t i = first; i < end; ++i) {
                if (i > first) {
                    ImGui::SameLine();
                }
                const char c = b[i] >= 0x20 && b[i] < 0x7F ? (char)b[i] : '.';
                hex_cell(&c, 1, i, d, cw, lh);
            }
        }
    }
    ImGui::PopStyleVar();
    ImGui::EndChild();
}

int edit_line(const Row& r) {
    std::string t;
    int n = 0;
    if (r.rec.before.empty()) {
        t = "edited by a patch rule -- no before-image (lost to capture-ring overflow)";
    } else {
        const std::vector<EditRun> runs = edit_runs(r.rec.before, r.rec.bytes);
        size_t bytes = 0;
        for (const EditRun& e : runs) {
            bytes += e.len;
        }
        if (runs.empty()) {
            t = "edited by a patch rule -- no captured byte differs (past the 4 KB capture, or a later rule undid it)";
        } else {
            t = "edited by a patch rule (" + std::to_string(bytes) + " B):";
        }
        for (size_t i = 0; i < runs.size() && i < 3; ++i) {
            t += "   " + edit_run_text(r.rec, runs[i]);
        }
        if (runs.size() > 3) {
            t += "   ... " + std::to_string(runs.size() - 3) + " more (Copy decoded lists them all)";
        }
        n = (int)runs.size();
    }
    ImGui::PushStyleColor(ImGuiCol_Text, kEdited);
    ImGui::TextWrapped("%s", t.c_str());
    ImGui::PopStyleColor();
    return n;
}

void detail_header(const Row& r, DetailState& d, const UiConfig& cfg, ListState& st) {
    const PacketView& v = d.view;
    const Struct* lay = v.pick >= 0 ? v.layouts[(size_t)v.pick] : nullptr;
    ImGui::Text("#%llu", (unsigned long long)r.rec.seq);
    ImGui::SameLine();
    dir_cell(r.rec.dir);
    ImGui::SameLine();
    ImGui::Text("(%u,%u)  size=%u", (unsigned)r.rec.main, (unsigned)r.rec.sub, (unsigned)r.rec.size);
    ImGui::SameLine();
    ImGui::TextColored(status_color(r.status), "%s", r.label.empty() ? "raw" : r.label.c_str());
    if (r.rec.edited) {
        ImGui::SameLine();
        ImGui::TextColored(kEdited, "edited");
    }
    if (r.rec.tool) {
        ImGui::SameLine();
        ImGui::TextColored(kTool, "tool");
    }
    if (!cfg.db) {
        ImGui::TextColored(kWarn, "no packet db -- raw bytes only");
    } else if (r.status == Status::Unknown) {
        ImGui::TextColored(kDim, "unknown: no layout for this opcode -- raw bytes only");
    } else if (r.status == Status::Mismatch && !r.layout) {
        ImGui::TextColored(kMismatch,
                           "SIZE MISMATCH: %u B fits none of the %zu candidate layouts -- try them under \"decode as\"",
                           (unsigned)r.rec.size, v.layouts.size());
    } else if (r.status == Status::Mismatch) {
        ImGui::TextColored(kMismatch,
                           "SIZE MISMATCH: payload %u B, sizeof %d B -- best-effort map; "
                           "(beyond sizeof) and <absent> mark the difference",
                           (unsigned)r.rec.size, r.layout->size);
    } else if (r.status == Status::Var) {
        ImGui::TextColored(
            kVar, "var: a variable-length struct sent shorter than sizeof -- fields past the payload read <absent>");
    } else if (r.status == Status::Trigger) {
        ImGui::TextColored(kTrigger, "trigger: the server's %s reads no payload -- nothing to decode (raw bytes only)",
                           r.name.c_str());
    }
    if (v.trial && lay) {
        ImGui::TextColored(kWarn, "trial decode as %s (sizeof %d) -- not the classified layout", lay->name.c_str(),
                           lay->size);
    }
    if (r.rec.bytes.size() < r.rec.size) {
        ImGui::TextColored(kWarn, "captured %u of %u bytes (4 KB cap) -- the rest is not shown",
                           (unsigned)r.rec.bytes.size(), (unsigned)r.rec.size);
    }
    if (r.rec.edited) {
        g_detailEdits.store(edit_line(r));
    }
    if (const int k = route_line(cfg, r.rec.dir, r.rec.main, r.rec.sub); k >= 0) {
        g_detailRoute.store(k);
    }
    if (const int k = server_line(cfg, r.rec.dir, r.rec.main, r.rec.sub); k >= 0) {
        g_detailServer.store(k);
    }
    for (size_t i = 0; i < std::size(kCopy); ++i) {
        if (i) {
            ImGui::SameLine();
        }
        if (ImGui::Button(kCopy[i].label)) {
            ImGui::SetClipboardText(copy_text(v, r, kCopy[i].kind).c_str());
            d.copied = kCopy[i].what;
            d.copied_until = ImGui::GetTime() + 1.5;
        }
    }
    resend_items(r, cfg, st, false);
    int want = -1;
    if (v.layouts.size() > 1 || v.trial) {
        ImGui::SameLine();
        ImGui::SetNextItemWidth(ImGui::CalcTextSize("_base_download_result_zocl (258 B, var)").x +
                                ImGui::GetFrameHeight());
        if (ImGui::BeginCombo("decode as", lay ? lay->name.c_str() : "-")) {
            for (size_t i = 0; i < v.layouts.size(); ++i) {
                const Struct* s = v.layouts[i];
                char item[192];
                std::snprintf(item, sizeof item, "%s (%d B%s)", s->name.c_str(), s->size, s->var ? ", var" : "");
                ImGui::PushID((int)i);
                if (ImGui::Selectable(item, (int)i == v.pick)) {
                    want = (int)i;
                }
                ImGui::PopID();
            }
            ImGui::EndCombo();
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Close")) {
        st.selected = kNoSel;
    }
    if (ImGui::GetTime() < d.copied_until) {
        ImGui::SameLine();
        ImGui::TextDisabled("copied %s", d.copied);
    }
    if (want >= 0) {
        build_view(d.view, r, cfg.db, want);
        d.pinned = Range{};
    }
}

void draw_detail(const Row& r, DetailState& d, const UiConfig& cfg, ListState& st, float footer) {
    d.shown = d.hover.off >= 0 ? d.hover : d.pinned;
    d.hover = Range{};
    d.rows = 0;
    ImGui::BeginChild("detail", ImVec2(0.0f, -footer), ImGuiChildFlags_Borders);
    detail_header(r, d, cfg, st);
    const ImGuiStyle& s = ImGui::GetStyle();
    const float hex_w = ImGui::CalcTextSize("0").x * 72.0f + s.WindowPadding.x * 2.0f + s.ScrollbarSize;
    const float fields_w = std::max(ImGui::GetContentRegionAvail().x - hex_w - s.ItemSpacing.x, 200.0f);
    if (d.view.spans.empty()) {
        ImGui::BeginChild("fields", ImVec2(fields_w, 0.0f), ImGuiChildFlags_Borders);
        ImGui::TextDisabled("%s", cfg.db ? "no layout -- raw bytes only (hex view)"
                                         : "no packet db -- raw bytes only (hex view)");
        ImGui::EndChild();
    } else {
        const ImGuiTableFlags tf = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersV |
                                   ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingFixedFit;
        if (ImGui::BeginTable("fields", 5, tf, ImVec2(fields_w, 0.0f))) {
            auto w = [](const char* t) {
                return ImGui::CalcTextSize(t).x;
            };
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("field", ImGuiTableColumnFlags_WidthFixed, w("dwAccountSerial[100]   "));
            ImGui::TableSetupColumn("offset", ImGuiTableColumnFlags_WidthFixed, w("+0000"));
            ImGui::TableSetupColumn("size", ImGuiTableColumnFlags_WidthFixed, w("00000"));
            ImGui::TableSetupColumn("type", ImGuiTableColumnFlags_WidthFixed, w("_list_embellish  "));
            ImGui::TableSetupColumn("value", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();
            span_rows(d.view.spans, r, d, cfg, 0, std::string());
            ImGui::EndTable();
        }
    }
    ImGui::SameLine();
    draw_hex(r, d);
    ImGui::EndChild();
}

void unload_popup() {
    if (!ImGui::BeginPopupModal("Unload RFTrafficEditor?", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        return;
    }
    ImGui::TextUnformatted("Restores the original bytes of the two hooked functions and unloads the DLL.\n"
                           "The client keeps running and stays connected.");
    if (ImGui::Button("Unload")) {
        g_unload.store(true);
        ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel")) {
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

void flash(Composer& c, std::string text, bool bad) {
    c.status = std::move(text);
    c.status_bad = bad;
    c.flash_until = ImGui::GetTime() + 4.0;
}

Queued submit(Composer& c, const UiConfig& cfg, const Draft& d) {
    const Queued q = cfg.queue_action(d.dir, d.main, d.sub, d.bytes.data(), d.bytes.size());
    char head[48];
    std::snprintf(head, sizeof head, "%s (%u,%u) %zu B", dir_name(d.dir), (unsigned)d.main, (unsigned)d.sub,
                  d.bytes.size());
    const char* when = d.dir == Dir::C2S ? "goes out with the next packet the game sends or receives"
                                         : "runs right after the next packet the server sends";
    const char* sep = d.from.empty() ? "" : " -- ";
    if (q == Queued::Ok) {
        g_queued.fetch_add(1);
        flash(c, std::string("queued ") + head, false);
        logmsg("composer: queued %s%s%s%s%s -- %s", head, d.label.empty() ? "" : " ", d.label.c_str(), sep,
               d.from.c_str(), when);
        return q;
    }
    g_rejected.fetch_add(1);
    char why[96];
    if (q == Queued::Full) {
        std::snprintf(why, sizeof why, "the queue is full (%zu pending) -- wait, or Cancel queued", kActionSlots);
    } else if (q == Queued::TooLong) {
        std::snprintf(why, sizeof why, "longer than %d bytes", kMaxAction);
    } else {
        std::snprintf(why, sizeof why, "no action queue (hooks not installed)");
    }
    flash(c, std::string("NOT queued ") + head + ": " + why, true);
    logmsg("composer: NOT queued %s%s%s: %s", head, sep, d.from.c_str(), why);
    return q;
}

void request(Composer& c, const UiConfig& cfg, const Draft& d) {
    if (!d.ok || !cfg.queue_action) {
        return;
    }
    if (c.armed[(size_t)d.dir]) {
        submit(c, cfg, d);
        return;
    }
    if (c.confirming) {
        flash(c, "a Confirm is already open -- answer it first", true);
        return;
    }
    c.pending = d;
    c.ask = true;
    c.confirming = true;
    g_confirmAsks.fetch_add(1);
}

void confirm_popup(Composer& c, const UiConfig& cfg, ScriptHost& sh) {
    if (!ImGui::BeginPopupModal("Confirm", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        c.confirming = false;
        return;
    }
    const Draft& d = c.pending;
    const bool send = d.dir == Dir::C2S;
    ImGui::TextUnformatted(send ? "Send this packet to the SERVER?" : "Inject this packet into the CLIENT?");
    ImGui::Text("%s (%u,%u)  %zu B  %s", dir_name(d.dir), (unsigned)d.main, (unsigned)d.sub, d.bytes.size(),
                d.label.c_str());
    if (!d.from.empty()) {
        ImGui::TextDisabled("%s", d.from.c_str());
    }
    ImGui::TextUnformatted(
        send ? "It goes out on the game's own connection (CNetworkMgr::SendNetMessage) with the\n"
               "next packet the game sends or receives; the server handles it like any client packet."
             : "The client handles it exactly as if the server had sent it\n"
               "(CNetworkMgr::AnalysisZoneServerPacket), right after the next packet the server sends.");
    if (d.script) {
        ImGui::TextColored(kWarn,
                           "From a running script: Send also lets its later %s through this session;\n"
                           "Cancel drops this packet and STOPS the script.",
                           send ? "sends" : "injects");
    }
    ImGui::TextDisabled("Asked once per session for each direction.");
    const bool yes = ImGui::Button(send ? "Send" : "Inject") || c.answer_once == 1;
    ImGui::SameLine();
    const bool no = ImGui::Button(d.script ? "Cancel (stops the script)" : "Cancel") || c.answer_once == 2;
    c.answer_once = 0;
    if (yes) {
        c.armed[(size_t)d.dir] = true;
        c.confirming = false;
        logmsg("composer: first %s of the session confirmed", send ? "send to the server" : "inject to the client");
        submit(c, cfg, d);
        ImGui::CloseCurrentPopup();
    } else if (no) {
        c.confirming = false;
        if (d.script) {
            sh.stop(send ? "its first send to the server was not confirmed"
                         : "its first inject to the client was not confirmed");
        }
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

ScriptSend script_request(Composer& c, const UiConfig& cfg, const std::string& who, Dir dir, uint8_t main, uint8_t sub,
                          const uint8_t* p, size_t len) {
    if (!cfg.queue_action) {
        return ScriptSend::Unavailable;
    }
    if (len > (size_t)kMaxAction) {
        return ScriptSend::TooLong;
    }
    Draft d;
    d.dir = dir;
    d.main = main;
    d.sub = sub;
    if (len) {
        d.bytes.assign(p, p + len);
    }
    if (cfg.db) {
        const Decoded dc = cfg.db->classify(dir, main, sub, (uint16_t)len);
        d.status = dc.status;
        d.label = describe(dc, (uint16_t)len);
    }
    d.from = "script " + who;
    d.script = true;
    d.ok = true;
    if (c.armed[(size_t)dir]) {
        switch (submit(c, cfg, d)) {
        case Queued::Ok:
            return ScriptSend::Queued;
        case Queued::Full:
            return ScriptSend::Full;
        case Queued::TooLong:
            return ScriptSend::TooLong;
        default:
            return ScriptSend::Unavailable;
        }
    }
    if (c.confirming) {
        return ScriptSend::Waiting;
    }
    request(c, cfg, d);
    return ScriptSend::Held;
}

void arm_now(const UiConfig& cfg, RulesUi& ru) {
    cfg.arm_rules(true);
    ru.armed = true;
    g_ruleArms.fetch_add(1);
    logmsg("rules: ARMED (UI) -- %zu rule(s) now edit live traffic inside the hooks, before the server / the "
           "client handles it",
           ru.active);
}

void disarm_rules(const UiConfig& cfg, RulesUi& ru, const char* why) {
    if (!ru.armed || !cfg.arm_rules) {
        return;
    }
    cfg.arm_rules(false);
    ru.armed = false;
    logmsg("rules: disarmed (%s) -- traffic passes unedited", why);
}

void request_arm(const UiConfig& cfg, RulesUi& ru) {
    if (!cfg.arm_rules || ru.active == 0) {
        return;
    }
    if (ru.confirmed) {
        arm_now(cfg, ru);
        return;
    }
    ru.ask = true;
    g_ruleAsks.fetch_add(1);
}

void editor_follow(RulesEditor& ed, bool follow, const std::vector<PatchRule>& live) {
    if (!follow) {
        return;
    }
    ed.list = live;
    if (ed.sel >= (int)ed.list.size()) {
        ed.sel = (int)ed.list.size() - 1;
    }
    ed.form_for = -1;
}

std::vector<PatchRule> active_of(const std::vector<PatchRule>& l) {
    std::vector<PatchRule> out;
    for (size_t i = 0; i < l.size() && i < kMaxRules; ++i) {
        if (l[i].enabled && check_rule(l[i]).empty()) {
            out.push_back(l[i]);
        }
    }
    return out;
}

void forget_script_rules(RulesUi& ru, const char* by) {
    if (!ru.script_changed) {
        return;
    }
    ru.script_changed = false;
    ru.script_base.clear();
    logmsg("rules: %s replaces the list -- script %s's rule changes are no longer undone when it stops", by,
           ru.script_by.c_str());
}

ScriptRules script_rules(const UiConfig& cfg, RulesUi& ru, RulesEditor& ed, const std::string& who,
                         std::vector<PatchRule> list, const std::string& change) {
    if (!cfg.set_rules) {
        return ScriptRules::Unavailable;
    }
    if (!ru.script_changed) {
        ru.script_changed = true;
        ru.script_base = ru.list;
        ru.script_by = who;
    }
    const bool disarm = ru.armed && !ru.script_ok;
    if (disarm) {
        disarm_rules(cfg, ru, "a script changed the rules -- arming the new list asks first");
        g_ruleScriptDisarms.fetch_add(1);
    }
    const bool follow = ed.list == ru.list;
    cfg.set_rules(list);
    set_rule_list(ru, std::move(list));
    editor_follow(ed, follow, ru.list);
    if (ru.armed && ru.active == 0) {
        disarm_rules(cfg, ru, "the list has no active rule");
    }
    ru.confirmed = ru.armed;
    g_ruleScriptChanges.fetch_add(1);
    logmsg("rules: script %s %s -- %zu rule(s), %zu active, %s", who.c_str(), change.c_str(), ru.list.size(), ru.active,
           ru.armed ? "ARMED: they edit live traffic from the next packet on" : "disarmed");
    return disarm ? ScriptRules::Disarmed : ScriptRules::Applied;
}

void restore_script_rules(const UiConfig& cfg, RulesUi& ru, RulesEditor& ed) {
    if (!ru.script_changed) {
        return;
    }
    ru.script_changed = false;
    std::vector<PatchRule> base = std::move(ru.script_base);
    ru.script_base.clear();
    if (!cfg.set_rules) {
        return;
    }
    if (ru.armed) {
        const std::vector<PatchRule> now = active_of(ru.list);
        for (const PatchRule& r : active_of(base)) {
            if (std::find(now.begin(), now.end(), r) == now.end()) {
                disarm_rules(cfg, ru, "undoing a script's rule changes would arm rules not armed now");
                break;
            }
        }
    }
    const bool follow = ed.list == ru.list;
    cfg.set_rules(base);
    set_rule_list(ru, std::move(base));
    editor_follow(ed, follow, ru.list);
    if (ru.armed && ru.active == 0) {
        disarm_rules(cfg, ru, "the list has no active rule");
    }
    ru.confirmed = ru.armed;
    g_ruleScriptUndos.fetch_add(1);
    logmsg("rules: script %s stopped -- its rule changes are undone: %zu rule(s), %zu active, %s", ru.script_by.c_str(),
           ru.list.size(), ru.active, ru.armed ? "ARMED" : "disarmed");
}

void do_reload(const UiConfig& cfg, RulesUi& ru, RulesEditor& ed) {
    forget_script_rules(ru, "Reload rules");
    disarm_rules(cfg, ru, "Reload rules");
    const RulesLoad L = cfg.reload_rules();
    for (const std::string& s : describe_load(L)) {
        logmsg("rules: %s", s.c_str());
    }
    const size_t n = cfg.set_rules(L.rules);
    set_rule_list(ru, L.rules);
    ru.confirmed = false;
    logmsg("rules: reloaded -- %zu active, disarmed: tick Rules to apply them (it asks first)", n);
    editor_reset(ed, L.rules);
}

std::string rules_tooltip(const UiConfig& cfg, const RulesUi& ru) {
    std::string t =
        ru.list.empty()
            ? "No patch rules. Put RFTrafficEditor.rules.json next to the DLL (RFTrafficEditor.rules.example.json\n"
              "shows the format), then Reload rules."
            : "Patch rules from RFTrafficEditor.rules.json (next to the DLL):";
    const RuleStats s = cfg.rule_stats ? cfg.rule_stats() : RuleStats{};
    for (size_t i = 0; i < ru.list.size(); ++i) {
        const PatchRule& r = ru.list[i];
        t += "\n  ";
        if (!r.error.empty()) {
            t += rule_label(i, r) + ": INVALID: " + r.error;
            continue;
        }
        t += rule_title(i, r);
        if (!ru.err[i].empty()) {
            t += " -- INVALID: " + ru.err[i];
        } else if (i >= kMaxRules) {
            t += " -- ignored (only the first 64 are used)";
        } else if (!r.enabled) {
            t += " -- disabled";
        } else if (cfg.rule_stats) {
            t += " -- hits " + std::to_string(s.hits[i]);
        }
    }
    if (ru.script_changed) {
        t += "\nScript " + ru.script_by + " changed this list -- its changes are undone when it stops.";
    }
    t += ru.armed ? "\nARMED: they edit live packets inside the hooks, before the server / the client handles them."
                  : "\nTick to arm them (the first time this session -- and after a Reload -- it asks first).";
    return t;
}

void rules_toggle(const UiConfig& cfg, RulesUi& ru, RulesEditor& ed) {
    char label[32];
    std::snprintf(label, sizeof label, "Rules (%zu)###rules", ru.active);
    bool on = ru.armed;
    ImGui::BeginDisabled(!cfg.arm_rules || (!ru.armed && ru.active == 0));
    bool clicked = ImGui::Checkbox(label, &on);
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip | ImGuiHoveredFlags_AllowWhenDisabled)) {
        ImGui::SetTooltip("%s", rules_tooltip(cfg, ru).c_str());
    }
    if (ru.tick_once) {
        clicked = true;
        on = true;
        ru.tick_once = false;
    }
    if (clicked) {
        if (on) {
            request_arm(cfg, ru);
        } else {
            disarm_rules(cfg, ru, "UI");
        }
    }
    if (cfg.reload_rules && cfg.set_rules) {
        ImGui::SameLine();
        if (ImGui::Button("Reload rules")) {
            if (editor_unsaved(ed)) {
                ed.ask_reload = true;
            } else {
                do_reload(cfg, ru, ed);
            }
        }
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip)) {
            ImGui::SetTooltip("Re-read RFTrafficEditor.rules.json (next to the DLL). Disarms; arming asks again.\n"
                              "The Rules editor then shows the file's list (unsaved changes there: it asks first).");
        }
    }
}

void rules_popup(const UiConfig& cfg, RulesUi& ru, const char* script) {
    if (!ImGui::BeginPopupModal("Arm patch rules?", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        return;
    }
    ImGui::TextUnformatted("Apply these patch rules to LIVE traffic?");
    for (size_t i = 0; i < ru.list.size() && i < kMaxRules; ++i) {
        if (ru.list[i].enabled && ru.err[i].empty()) {
            ImGui::BulletText("%s", rule_title(i, ru.list[i]).c_str());
        }
    }
    ImGui::TextUnformatted("Each one rewrites the real packet inside the hook, before the server (C2S) or the\n"
                           "client (S2C) handles it -- same length, bytes changed in place. Edited rows are\n"
                           "marked `edited`; the log shows every change (before -> after).");
    if (script) {
        ImGui::TextColored(kWarn,
                           "A script is running (%s): arming also lets it add / enable / disable / remove rules\n"
                           "while armed, this session -- its changes edit live traffic from the next packet on\n"
                           "(they are undone when it stops).",
                           script);
    }
    ImGui::TextDisabled("Asked once per session (again after Reload rules). Untick Rules to stop.");
    if (ImGui::Button("Arm")) {
        ru.confirmed = true;
        if (script && !ru.script_ok) {
            ru.script_ok = true;
            logmsg("rules: armed while script %s runs -- scripts may change the armed rules this session", script);
        }
        arm_now(cfg, ru);
        ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel")) {
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

void reload_popup(const UiConfig& cfg, RulesUi& ru, RulesEditor& ed) {
    if (!ImGui::BeginPopupModal("Reload rules?", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        return;
    }
    ImGui::TextUnformatted("The Rules editor has unsaved changes. Reload rules re-reads RFTrafficEditor.rules.json\n"
                           "and replaces the editor's list with it -- the changes are lost (Save first to keep them).");
    if (ImGui::Button("Reload (discard the changes)")) {
        do_reload(cfg, ru, ed);
        ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel")) {
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

void apply_editor(const UiConfig& cfg, RulesUi& ru, RulesEditor& ed) {
    forget_script_rules(ru, "the Rules editor's Apply");
    for (const std::string& s : describe_rules(ed.list)) {
        logmsg("rules: %s", s.c_str());
    }
    const size_t n = cfg.set_rules(ed.list);
    set_rule_list(ru, ed.list);
    ru.confirmed = ru.armed;
    g_ruleApplies.fetch_add(1);
    ed.status = "applied: " + std::to_string(n) + " active" + (ru.armed ? " -- ARMED" : " -- disarmed");
    ed.status_bad = false;
    if (ru.armed) {
        logmsg("rules: applied from the editor -- %zu active, ARMED: they edit live traffic from the next packet on",
               n);
    } else {
        logmsg("rules: applied from the editor -- %zu active, disarmed: tick Rules to arm them (it asks first)", n);
    }
}

void request_apply(const UiConfig& cfg, RulesUi& ru, RulesEditor& ed) {
    if (!cfg.set_rules) {
        return;
    }
    if (ru.armed && active_rules(ed.list) > 0) {
        ed.ask_apply = true;
        g_ruleApplyAsks.fetch_add(1);
        return;
    }
    disarm_rules(cfg, ru, "the applied list has no active rule");
    apply_editor(cfg, ru, ed);
}

void apply_popup(const UiConfig& cfg, RulesUi& ru, RulesEditor& ed) {
    if (!ImGui::BeginPopupModal("Apply edited rules?", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        return;
    }
    ImGui::TextUnformatted("Rules is ARMED. Replace the live patch rules with the editor's list?");
    for (size_t i = 0; i < ed.list.size() && i < kMaxRules; ++i) {
        if (ed.list[i].enabled && check_rule(ed.list[i]).empty()) {
            ImGui::BulletText("%s", rule_title(i, ed.list[i]).c_str());
        }
    }
    ImGui::TextUnformatted("From the next packet on they rewrite it inside the hook, before the server (C2S) or the\n"
                           "client (S2C) handles it. Hit counts restart.");
    if (ImGui::Button("Apply")) {
        apply_editor(cfg, ru, ed);
        ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button("Apply disarmed")) {
        disarm_rules(cfg, ru, "Apply disarmed");
        apply_editor(cfg, ru, ed);
        ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel")) {
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

void save_editor(const UiConfig& cfg, RulesEditor& ed) {
    std::string err;
    if (cfg.save_rules(ed.list, &err)) {
        ed.saved = ed.list;
        g_ruleSaves.fetch_add(1);
        ed.status = "saved " + std::to_string(ed.list.size()) + " rule(s) to RFTrafficEditor.rules.json";
        ed.status_bad = false;
        logmsg("rules: saved %zu rule(s) to RFTrafficEditor.rules.json (a previous file is kept as "
               "RFTrafficEditor.rules.json.bak) -- saving does not apply them: Apply does",
               ed.list.size());
    } else {
        ed.status = "NOT saved: " + err;
        ed.status_bad = true;
        logmsg("rules: NOT saved: %s", err.c_str());
    }
}

const ImVec4& state_colour(ScriptState s) {
    switch (s) {
    case ScriptState::Running:
        return kEdited;
    case ScriptState::Tripped:
        return kWarn;
    case ScriptState::Failed:
        return kMismatch;
    default:
        return kDim;
    }
}

std::string script_tooltip(const ScriptUi& su, const ScriptHost& sh) {
    const ScriptLimits& lim = sh.limits();
    std::string t = su.loaded ? "Runs " + su.name + " (Lua) on the tool's UI thread -- never inside the game's hooks."
                              : std::string("No script loaded -- open Scripts.");
    t += "\nIts on_packet handlers see a read-only copy of every captured packet and its timers (on_tick / after) run"
         "\nfrom the UI loop; it can log, read fields by name, build payloads (make), send / inject through the action"
         "\nqueue -- the first of each direction per session asks (Confirm) -- and change the patch rules (rules.*:"
         "\nthey edit traffic only while Rules is armed; undone when it stops). Watchdog: a callback past " +
         std::to_string(lim.max_instructions) + " instructions or " + std::to_string(lim.max_ms) +
         " ms is aborted\nand the script stopped.";
    if (!su.syntax.empty()) {
        t += "\nNOT runnable: " + su.syntax;
    }
    t += sh.running() ? "\nRUNNING -- untick to stop it."
                      : "\nTick to run it (the first run of a script this session asks first).";
    if (sh.state() == ScriptState::Failed || sh.state() == ScriptState::Tripped) {
        t += "\nLast stop: " + sh.last_error();
    }
    return t;
}

void script_toggle(ScriptUi& su, ScriptHost& sh) {
    bool on = sh.running();
    ImGui::BeginDisabled(!on && !can_run(su));
    const bool clicked = ImGui::Checkbox("Run script###runscript", &on);
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip | ImGuiHoveredFlags_AllowWhenDisabled)) {
        ImGui::SetTooltip("%s", script_tooltip(su, sh).c_str());
    }
    if (clicked) {
        if (on) {
            request_run(su, sh);
        } else {
            sh.stop("UI");
        }
    }
    ImGui::SameLine();
    ImGui::Checkbox("Scripts", &su.open);
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip)) {
        ImGui::SetTooltip(
            "The Scripts window: pick a .lua next to the DLL, Reload, Run / Stop, its output and counters.");
    }
}

void run_popup(ScriptUi& su, ScriptHost& sh) {
    if (!ImGui::BeginPopupModal("Run script?", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        return;
    }
    const ScriptLimits& lim = sh.limits();
    ImGui::Text("Run %s?", su.name.c_str());
    ImGui::TextUnformatted(
        "It runs on the tool's UI thread -- never inside the game's hooks. Its on_packet handlers see a\n"
        "read-only copy of every captured packet; its timers (on_tick / after) run from the UI loop. It can\n"
        "log, SEND packets to the server and INJECT packets into the client (send_to_server /\n"
        "inject_to_client) through the action queue -- the first send and the first inject of the session\n"
        "still ask (Confirm) -- and add / enable / disable / remove PATCH RULES (rules.*): they edit live\n"
        "traffic only while Rules is armed (arming stays yours), and they are undone when it stops.");
    ImGui::Text("Watchdog: a callback past %llu instructions or %u ms is aborted and the script stopped;\n"
                "its memory is capped at %u MB; at most %u sends / injects and %u rule changes per second, %u timers.",
                (unsigned long long)lim.max_instructions, (unsigned)lim.max_ms, (unsigned)(lim.max_bytes >> 20),
                (unsigned)lim.max_actions_per_s, (unsigned)lim.max_rule_changes_per_s, (unsigned)lim.max_timers);
    ImGui::TextDisabled("Asked once per script per session (again after Reload). Untick Run script to stop it.");
    if (ImGui::Button("Run")) {
        su.confirmed = true;
        run_now(su, sh);
        ImGui::CloseCurrentPopup();
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel")) {
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

void draw_scripts(ScriptUi& su, ScriptHost& sh, const UiConfig& cfg) {
    if (!su.available || !su.open) {
        return;
    }
    ImGui::SetNextWindowSize(ImVec2(760.0f, 460.0f), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Scripts", &su.open)) {
        ImGui::End();
        return;
    }
    g_scriptFrames.fetch_add(1);
    if (!cfg.script.code.empty()) {
        ImGui::TextUnformatted("(test script)");
    } else {
        if (su.files.empty()) {
            ImGui::TextDisabled(
                "no *.lua next to the DLL -- put one there (RFTrafficEditor.example.lua shows the API)");
        } else {
            ImGui::SetNextItemWidth(320.0f);
            const std::string cur = su.sel >= 0 ? utf8(su.files[(size_t)su.sel]) : std::string("-");
            if (ImGui::BeginCombo("script", cur.c_str())) {
                for (size_t i = 0; i < su.files.size(); ++i) {
                    const std::string n = utf8(su.files[i]);
                    if (ImGui::Selectable(n.c_str(), (int)i == su.sel) && (int)i != su.sel) {
                        load_script(cfg, su, sh, (int)i);
                    }
                }
                ImGui::EndCombo();
            }
            ImGui::SameLine();
            ImGui::BeginDisabled(su.sel < 0);
            if (ImGui::Button("Reload")) {
                load_script(cfg, su, sh, su.sel);
            }
            ImGui::EndDisabled();
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip)) {
                ImGui::SetTooltip("Re-read the file. A running script stops; Run asks again.");
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Rescan")) {
            rescan(cfg, su, sh);
        }
    }
    if (can_run(su)) {
        ImGui::TextColored(kOk, "%s: syntax ok (%zu B)", su.name.c_str(), su.code.size());
    } else if (!su.syntax.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, kMismatch);
        ImGui::TextWrapped("%s", su.syntax.c_str());
        ImGui::PopStyleColor();
    }
    ImGui::BeginDisabled(sh.running() || !can_run(su));
    if (ImGui::Button("Run")) {
        request_run(su, sh);
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(!sh.running());
    if (ImGui::Button("Stop")) {
        sh.stop("UI");
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    const ScriptStats s = sh.stats();
    ImGui::TextColored(state_colour(s.state), "%s", script_state_name(s.state));
    if (s.state == ScriptState::Failed || s.state == ScriptState::Tripped) {
        ImGui::PushStyleColor(ImGuiCol_Text, state_colour(s.state));
        ImGui::TextWrapped("%s", sh.last_error().c_str());
        ImGui::PopStyleColor();
    }
    ImGui::Text("on_packet %u handler(s)   packets %llu   callbacks %llu   skipped %llu   log lines %llu   "
                "slowest %.1f ms   memory %zu KB",
                s.handlers, (unsigned long long)s.packets, (unsigned long long)s.callbacks,
                (unsigned long long)s.skipped, (unsigned long long)s.lines, s.slowest_ms, s.mem_bytes / 1024);
    ImGui::Text("sent %llu   injected %llu   held for Confirm %llu   not queued %llu", (unsigned long long)s.sent,
                (unsigned long long)s.injected, (unsigned long long)s.held, (unsigned long long)s.refused);
    ImGui::Text("timers %u   ticks %llu   rule changes %llu   rules not changed %llu", s.timers,
                (unsigned long long)s.ticks, (unsigned long long)s.rule_changes, (unsigned long long)s.rules_refused);
    const ScriptLimits& lim = sh.limits();
    ImGui::TextDisabled(
        "watchdog: %llu instructions or %u ms per callback, %u ms of script per drain, %u MB of memory, "
        "%u sends / injects per second, %u rule changes per second, %u timers",
        (unsigned long long)lim.max_instructions, (unsigned)lim.max_ms, (unsigned)lim.frame_ms,
        (unsigned)(lim.max_bytes >> 20), (unsigned)lim.max_actions_per_s, (unsigned)lim.max_rule_changes_per_s,
        (unsigned)lim.max_timers);
    if (ImGui::Button("Clear output")) {
        sh.clear_lines();
    }
    ImGui::SameLine();
    if (ImGui::Button("Copy output")) {
        std::string all;
        for (const ScriptLine& l : sh.lines()) {
            all += l.text + "\n";
        }
        ImGui::SetClipboardText(all.c_str());
    }
    ImGui::SameLine();
    ImGui::Checkbox("Follow", &su.follow);
    ImGui::BeginChild("##out", ImVec2(0.0f, 0.0f), ImGuiChildFlags_Borders, ImGuiWindowFlags_HorizontalScrollbar);
    for (const ScriptLine& l : sh.lines()) {
        const bool tint = l.kind != ScriptLine::Kind::Log;
        if (tint) {
            ImGui::PushStyleColor(ImGuiCol_Text, l.kind == ScriptLine::Kind::Error ? kMismatch : kDim);
        }
        ImGui::TextUnformatted(l.text.c_str());
        if (tint) {
            ImGui::PopStyleColor();
        }
    }
    if (su.follow && sh.line_seq() != su.seen) {
        ImGui::SetScrollHereY(1.0f);
    }
    su.seen = sh.line_seq();
    ImGui::EndChild();
    ImGui::End();
}

void row_actions(const PacketModel& m, const UiConfig& cfg, ListState& st, Composer& c) {
    if (st.resend != kNoSel) {
        if (const Row* r = m.find(st.resend)) {
            g_resends.fetch_add(1);
            const Draft d = row_draft(*r, st.resend_other, cfg.db);
            if (d.ok) {
                request(c, cfg, d);
            } else {
                flash(c, d.err, true);
            }
        }
        st.resend = kNoSel;
    }
    if (st.load != kNoSel) {
        if (const Row* r = m.find(st.load)) {
            c.open = true;
            load_row(c, *r);
        }
        st.load = kNoSel;
    }
}

void rule_actions(const PacketModel& m, ListState& st, DetailState& d, RulesEditor& ed) {
    if (ed.from_row_once != kNoSel) {
        st.rule_row = ed.from_row_once;
        ed.from_row_once = kNoSel;
    }
    if (st.rule_row != kNoSel) {
        if (const Row* r = m.find(st.rule_row)) {
            add_rule(ed, row_rule(*r), "");
        }
        st.rule_row = kNoSel;
    }
    if (!ed.from_field_once.empty()) {
        for (const FieldSpan& sp : d.view.spans) {
            if (sp.kind == FieldSpan::Kind::Field && sp.field->name == ed.from_field_once) {
                d.rule_range = Range{sp.offset, sp.size};
                d.rule_name = sp.field->name;
            }
        }
        ed.from_field_once.clear();
    }
    if (d.rule_range.off >= 0) {
        if (const Row* r = m.find(d.view.seq)) {
            const Struct* lay = d.view.pick >= 0 ? d.view.layouts[(size_t)d.view.pick] : nullptr;
            bool cut = false;
            PatchRule pr = field_rule(*r, d.rule_range.off, d.rule_range.len,
                                      lay ? lay->name + "." + d.rule_name : d.rule_name, &cut);
            add_rule(ed, std::move(pr),
                     cut ? " (the field's first 64 of " + std::to_string(d.rule_range.len) + " bytes)" : "");
        }
        d.rule_range = Range{};
        d.rule_name.clear();
    }
}

const char* edit_hint(const EditField& f) {
    if (f.text) {
        return "text -- \\\\ for a backslash, \\xNN for any byte; the rest of the field is zero-filled";
    }
    switch (f.prim) {
    case Prim::U:
        return "unsigned -- decimal, or 0x hex";
    case Prim::S:
        return "signed -- decimal, or 0x hex (the bit pattern)";
    case Prim::Bool:
        return "true / false (or 0..255)";
    case Prim::F32:
    case Prim::F64:
        return "a number -- 1.5, -2, 1e3, inf, nan";
    default:
        return "hex bytes -- exactly this field's size (edits never change the packet's length)";
    }
}

void draw_fields(Composer& c, const UiConfig& cfg, Draft& d, float height) {
    if (!cfg.db || !d.ok) {
        return;
    }
    const uint32_t key = mute_key(d.dir, d.main, d.sub);
    if (key != c.pick_key) {
        c.pick_key = key;
        c.pick = -1;
    }
    std::vector<const Struct*> lays;
    const int def = layout_choices(*cfg.db, d.dir, d.main, d.sub, (uint16_t)d.bytes.size(), lays);
    if (def < 0) {
        if (d.status == Status::Trigger) {
            ImGui::TextDisabled("a trigger: the server's handler reads no payload -- an empty payload is enough");
        } else {
            ImGui::TextDisabled("no layout for %s (%u,%u) in the packet db -- hex only", dir_name(d.dir),
                                (unsigned)d.main, (unsigned)d.sub);
        }
        c.fill_once = false;
        c.edits_once.clear();
        return;
    }
    const int pick = c.pick >= 0 && c.pick < (int)lays.size() ? c.pick : def;
    const Struct& s = *lays[(size_t)pick];
    bool changed = false;
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("fields as");
    ImGui::SameLine();
    if (lays.size() > 1) {
        ImGui::SetNextItemWidth(ImGui::CalcTextSize("_base_download_result_zocl (258 B, var)").x +
                                ImGui::GetFrameHeight());
        if (ImGui::BeginCombo("##lay", s.name.c_str())) {
            for (size_t i = 0; i < lays.size(); ++i) {
                char item[192];
                std::snprintf(item, sizeof item, "%s (%d B%s)", lays[i]->name.c_str(), lays[i]->size,
                              lays[i]->var ? ", var" : "");
                ImGui::PushID((int)i);
                if (ImGui::Selectable(item, (int)i == pick)) {
                    c.pick = (int)i;
                }
                ImGui::PopID();
            }
            ImGui::EndCombo();
        }
    } else {
        ImGui::Text("%s (%d B%s)", s.name.c_str(), s.size, s.var ? ", var" : "");
    }
    if (s.size > 0 && d.bytes.size() < (size_t)s.size) {
        ImGui::SameLine();
        char fl[48];
        std::snprintf(fl, sizeof fl, "Fill to sizeof (%d B)", s.size);
        if (ImGui::Button(fl) || c.fill_once) {
            d.bytes.resize((size_t)s.size, 0);
            changed = true;
        }
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip)) {
            ImGui::SetTooltip("Append zero bytes up to sizeof(%s): every field becomes editable.", s.name.c_str());
        }
    }
    c.fill_once = false;
    const std::vector<EditField> leaves = edit_fields(s, cfg.db, d.bytes.data(), d.bytes.size());
    g_editorFields.store(leaves.size());
    for (const auto& e : c.edits_once) {
        const auto it = std::find_if(leaves.begin(), leaves.end(), [&](const EditField& f) {
            return f.name == e.first;
        });
        std::string err = "no such field";
        if (it != leaves.end() && set_field(*it, e.second, d.bytes, &err)) {
            changed = true;
            g_fieldEdits.fetch_add(1);
        } else {
            flash(c, e.first + ": " + err, true);
        }
    }
    c.edits_once.clear();
    const ImGuiTableFlags tf = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersV |
                               ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingFixedFit;
    if (ImGui::BeginTable("editor", 5, tf, ImVec2(0.0f, height))) {
        auto w = [](const char* t) {
            return ImGui::CalcTextSize(t).x;
        };
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("field", ImGuiTableColumnFlags_WidthFixed, w("EquipList[0].wItemIndex  "));
        ImGui::TableSetupColumn("offset", ImGuiTableColumnFlags_WidthFixed, w("+0000"));
        ImGui::TableSetupColumn("size", ImGuiTableColumnFlags_WidthFixed, w("00000"));
        ImGui::TableSetupColumn("type", ImGuiTableColumnFlags_WidthFixed, w("unsigned short  "));
        ImGui::TableSetupColumn("value", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();
        ImGuiListClipper clip;
        clip.Begin((int)leaves.size());
        while (clip.Step()) {
            for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
                const EditField& f = leaves[(size_t)i];
                ImGui::PushID(i);
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                if (f.type.empty()) {
                    ImGui::TextDisabled("%s", f.name.c_str());
                } else {
                    ImGui::TextUnformatted(f.name.c_str());
                }
                ImGui::TableNextColumn();
                ImGui::Text("+%04X", (unsigned)f.offset);
                ImGui::TableNextColumn();
                ImGui::Text("%d", f.size);
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(f.type.c_str());
                ImGui::TableNextColumn();
                if (!present(f, d.bytes.size())) {
                    ImGui::TextDisabled("<absent> -- the payload ends at %zu B", d.bytes.size());
                } else {
                    const std::string v = field_text(f, d.bytes.data(), d.bytes.size());
                    std::snprintf(c.fbuf.data(), c.fbuf.size(), "%s", v.c_str());
                    ImGui::SetNextItemWidth(-FLT_MIN);
                    ImGui::InputText("##v", c.fbuf.data(), c.fbuf.size(), ImGuiInputTextFlags_AutoSelectAll);
                    if (ImGui::IsItemDeactivatedAfterEdit()) {
                        std::string err;
                        if (set_field(f, c.fbuf.data(), d.bytes, &err)) {
                            changed = true;
                            g_fieldEdits.fetch_add(1);
                        } else {
                            flash(c, f.name + ": " + err, true);
                        }
                    }
                    if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip) && !ImGui::IsItemActive()) {
                        ImGui::SetTooltip("%s\nEnter, Tab or a click elsewhere applies it; Esc reverts.", edit_hint(f));
                    }
                }
                ImGui::PopID();
            }
        }
        ImGui::EndTable();
    }
    if (changed) {
        const std::string h = hex_line(d.bytes.data(), d.bytes.size());
        std::snprintf(c.hex.data(), c.hex.size(), "%s", h.c_str());
        d = check_draft(c, cfg.db);
    }
}

void draw_composer(Composer& c, const UiConfig& cfg, const Row* sel) {
    if (!c.open) {
        return;
    }
    ImGui::SetNextWindowSize(ImVec2(720.0f, 600.0f), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Composer", &c.open)) {
        ImGui::End();
        return;
    }
    g_composerFrames.fetch_add(1);
    const ImGuiStyle& sty = ImGui::GetStyle();
    ImGui::AlignTextToFramePadding();
    ImGui::PushStyleColor(ImGuiCol_Text, kC2S);
    ImGui::RadioButton("C2S send to server", &c.dir, 0);
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, kS2C);
    ImGui::RadioButton("S2C inject to client", &c.dir, 1);
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::TextDisabled("  opcode");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(ImGui::CalcTextSize("(255,255)  ").x + sty.FramePadding.x * 2.0f);
    ImGui::InputTextWithHint("##cop", "main,sub", c.opcode, sizeof c.opcode);
    ImGui::SameLine();
    ImGui::BeginDisabled(!sel);
    if (ImGui::Button("Load selected row") && sel) {
        load_row(c, *sel);
    }
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip | ImGuiHoveredFlags_AllowWhenDisabled)) {
        ImGui::SetTooltip("Direction, opcode and payload (its captured bytes) from the row selected in the list.");
    }
    const float below = ImGui::GetFrameHeightWithSpacing() + ImGui::GetTextLineHeightWithSpacing() * 4.0f;
    const float avail = ImGui::GetContentRegionAvail().y - below;
    ImGui::InputTextMultiline("##hex", c.hex.data(), c.hex.size(),
                              ImVec2(-FLT_MIN, cfg.db ? std::max(avail * 0.3f, 60.0f) : std::max(avail, 60.0f)));
    Draft d = check_draft(c, cfg.db);
    if (!d.ok) {
        ImGui::TextColored(kMismatch, "%s", d.err.c_str());
    } else if (!cfg.db) {
        ImGui::Text("%zu B -- no packet db: the size is not checked", d.bytes.size());
    } else {
        ImGui::TextColored(status_color(d.status), "%zu B -- the list will label it: %s", d.bytes.size(),
                           d.label.c_str());
    }
    if (d.ok) {
        const int k = route_line(cfg, d.dir, d.main, d.sub);
        if (k >= 0) {
            g_composerRoute.store(k);
        }
        const int ks = server_line(cfg, d.dir, d.main, d.sub);
        if (ks >= 0) {
            g_composerServer.store(ks);
        }
    }
    if (d.ok && cfg.db) {
        draw_fields(c, cfg, d,
                    std::max(ImGui::GetContentRegionAvail().y - below - ImGui::GetFrameHeightWithSpacing(), 80.0f));
    }
    ImGui::BeginDisabled(!d.ok || !cfg.queue_action);
    bool press = ImGui::Button(c.dir == 0 ? "Send to server" : "Inject to client");
    ImGui::EndDisabled();
    if (!cfg.queue_action && ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip | ImGuiHoveredFlags_AllowWhenDisabled)) {
        ImGui::SetTooltip("No action queue: the hooks are not installed.");
    }
    press = press || c.submit_once;
    c.submit_once = false;
    if (press) {
        request(c, cfg, d);
    }
    if (!c.status.empty()) {
        ImGui::SameLine();
        ImGui::TextColored(c.status_bad ? kWarn : kOk, "%s", c.status.c_str());
    }
    if (cfg.action_stats) {
        const ActionStats s = cfg.action_stats();
        ImGui::AlignTextToFramePadding();
        ImGui::Text("queued C2S %u  S2C %u    sent %llu (failed %llu)    injected %llu (refused %llu)", s.pending[0],
                    s.pending[1], (unsigned long long)s.done[0], (unsigned long long)s.failed[0],
                    (unsigned long long)s.done[1], (unsigned long long)s.failed[1]);
        if (cfg.cancel_actions) {
            ImGui::SameLine();
            ImGui::BeginDisabled(s.pending[0] + s.pending[1] == 0);
            if (ImGui::Button("Cancel queued")) {
                const size_t n = cfg.cancel_actions();
                logmsg("composer: %zu queued action(s) cancelled -- never executed", n);
                c.status = "cancelled " + std::to_string(n) + " queued";
                c.status_bad = true;
            }
            ImGui::EndDisabled();
        }
        if (s.pending[0]) {
            ImGui::TextColored(kWarn, "%s",
                               s.calls[0] || s.calls[1]
                                   ? "a queued send goes out with the next packet the game sends or receives -- move "
                                     "or chat if it is idle"
                                   : "no packet seen yet -- a queued send waits for the game's first one");
        }
        if (s.pending[1]) {
            ImGui::TextColored(kWarn, "%s",
                               s.calls[1] ? "a queued inject runs right after the next packet the server sends"
                                          : "no server packet seen yet -- a queued inject waits for the first one");
        }
    }
    ImGui::TextDisabled("Sends / injects run inside the two hooks on the game's thread -- never from this window.");
    ImGui::End();
}

const char* const kOffTip = "13 (decimal), 0x0D or +000D (hex -- as the detail pane shows offsets)";
const char* const kHexTip = "hex bytes, e.g. 39 30 ?? ?? -- ?? = any byte (pattern / find) or keep the original\n"
                            "(write / replace); at most 64. Rules are length-preserving.";

bool form_box(const char* id, const char* hint, char* buf, size_t cap, float w, bool ok, const char* tip) {
    if (!ok) {
        ImGui::PushStyleColor(ImGuiCol_FrameBg, kBadField);
    }
    ImGui::SetNextItemWidth(w);
    const bool ch = ImGui::InputTextWithHint(id, hint, buf, cap);
    if (!ok) {
        ImGui::PopStyleColor();
    }
    if (tip && ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip) && !ImGui::IsItemActive()) {
        ImGui::SetTooltip("%s", tip);
    }
    return ch;
}

void rule_form(RulesEditor& ed) {
    RuleForm& f = ed.form;
    const ImGuiStyle& sty = ImGui::GetStyle();
    const float num_w = ImGui::CalcTextSize("+0000000  ").x + sty.FramePadding.x * 2.0f;
    std::vector<uint16_t> pv;
    int iv = 0;
    bool ch = false;
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("name   ");
    ImGui::SameLine();
    ch |= form_box("##name", "free text (the log, the UI)", f.name, sizeof f.name, -FLT_MIN, true, nullptr);
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("packets");
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, kC2S);
    ch |= ImGui::RadioButton("C2S", &f.dir, 0);
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_Text, kS2C);
    ch |= ImGui::RadioButton("S2C", &f.dir, 1);
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::TextDisabled("  main");
    ImGui::SameLine();
    ch |= form_box("##main", "any", f.main, sizeof f.main, num_w, parse_part_text(f.main, &iv),
                   "0..255 (or 0x hex); blank or * = any");
    ImGui::SameLine();
    ImGui::TextDisabled("sub");
    ImGui::SameLine();
    ch |= form_box("##sub", "any", f.sub, sizeof f.sub, num_w, parse_part_text(f.sub, &iv),
                   "0..255 (or 0x hex); blank or * = any");
    ch |= ImGui::Checkbox("only when the payload holds", &f.gate);
    ImGui::BeginDisabled(!f.gate);
    ImGui::SameLine();
    const float mw = std::max(
        ImGui::GetContentRegionAvail().x - num_w - ImGui::CalcTextSize("at").x - sty.ItemSpacing.x * 2.0f, 120.0f);
    ch |= form_box("##mhex", "hex, ?? = any", f.match_hex, sizeof f.match_hex, mw,
                   !f.gate || parse_pattern_hex(f.match_hex, pv), kHexTip);
    ImGui::SameLine();
    ImGui::TextDisabled("at");
    ImGui::SameLine();
    ch |= form_box("##moff", "anywhere", f.match_off, sizeof f.match_off, num_w,
                   !f.gate || f.match_off[0] == '\0' || parse_offset_text(f.match_off, &iv), kOffTip);
    ImGui::EndDisabled();
    ImGui::AlignTextToFramePadding();
    ImGui::TextDisabled("action ");
    ImGui::SameLine();
    ch |= ImGui::RadioButton("write", &f.kind, 0);
    ImGui::SameLine();
    ch |= ImGui::RadioButton("find / replace (every occurrence)", &f.kind, 1);
    ImGui::AlignTextToFramePadding();
    if (f.kind == 0) {
        ImGui::TextDisabled("  at");
        ImGui::SameLine();
        ch |= form_box("##woff", "+0000", f.write_off, sizeof f.write_off, num_w, parse_offset_text(f.write_off, &iv),
                       kOffTip);
        ImGui::SameLine();
        ImGui::TextDisabled("write");
        ImGui::SameLine();
        ch |= form_box("##whex", "hex, ?? = keep", f.write_hex, sizeof f.write_hex, -FLT_MIN,
                       parse_pattern_hex(f.write_hex, pv), kHexTip);
    } else {
        const float hw = std::max((ImGui::GetContentRegionAvail().x - ImGui::CalcTextSize("  find with").x) * 0.5f -
                                      sty.ItemSpacing.x * 2.0f,
                                  120.0f);
        ImGui::TextDisabled("  find");
        ImGui::SameLine();
        ch |= form_box("##fhex", "hex, ?? = any", f.find_hex, sizeof f.find_hex, hw, parse_pattern_hex(f.find_hex, pv),
                       kHexTip);
        ImGui::SameLine();
        ImGui::TextDisabled("with");
        ImGui::SameLine();
        ch |= form_box("##rhex", "hex, ?? = keep (same count)", f.repl_hex, sizeof f.repl_hex, -FLT_MIN,
                       parse_pattern_hex(f.repl_hex, pv), kHexTip);
    }
    if (ch && ed.form_for >= 0 && ed.form_for < (int)ed.list.size()) {
        ed.list[(size_t)ed.form_for] = rule_of(f);
    }
    const PatchRule& r = ed.list[(size_t)ed.form_for];
    const std::string why = check_rule(r);
    if (!why.empty()) {
        ImGui::TextColored(kMismatch, "not applied: %s", why.c_str());
    } else if (!r.enabled) {
        ImGui::TextDisabled("disabled: %s", describe_rule(r).c_str());
    } else {
        ImGui::TextColored(kOk, "ok: %s", describe_rule(r).c_str());
    }
}

void draw_rules_editor(RulesEditor& ed, RulesUi& ru, const UiConfig& cfg) {
    if (!ed.open) {
        return;
    }
    ImGui::SetNextWindowSize(ImVec2(940.0f, 560.0f), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Rules editor", &ed.open)) {
        ImGui::End();
        return;
    }
    g_rulesEditorFrames.fetch_add(1);
    const size_t n = ed.list.size();
    if (ed.sel >= (int)n) {
        ed.sel = (int)n - 1;
    }
    const bool has = ed.sel >= 0;
    const bool not_applied = ed.list != ru.list;
    int bad = -1;
    for (size_t i = 0; i < n && bad < 0; ++i) {
        if (!ed.list[i].error.empty()) {
            bad = (int)i;
        }
    }
    int op = 0;
    if (ImGui::Button("Add")) {
        op = 1;
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip)) {
        ImGui::SetTooltip("A blank rule at the end -- fill it in below. Or right-click a packet row / a field in\n"
                          "the detail pane: New patch rule.");
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(!has);
    if (ImGui::Button("Duplicate")) {
        op = 2;
    }
    ImGui::SameLine();
    if (ImGui::Button("Delete")) {
        op = 3;
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(!has || ed.sel == 0);
    if (ImGui::ArrowButton("##up", ImGuiDir_Up)) {
        op = 4;
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(!has || ed.sel + 1 >= (int)n);
    if (ImGui::ArrowButton("##down", ImGuiDir_Down)) {
        op = 5;
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::TextDisabled("  |");
    ImGui::SameLine();
    const bool can_apply = cfg.set_rules && not_applied;
    ImGui::BeginDisabled(!can_apply);
    bool apply = ImGui::Button("Apply");
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip | ImGuiHoveredFlags_AllowWhenDisabled)) {
        ImGui::SetTooltip("%s",
                          !cfg.set_rules ? "No hooks: nothing to apply to."
                          : !not_applied
                              ? "The hooks hold exactly this list."
                              : "Hand this list to the hooks (it replaces the rules they hold; hit counts restart).\n"
                                "Disarmed: nothing edits traffic until you tick Rules (it asks first).\n"
                                "Armed: it asks first.");
    }
    ImGui::SameLine();
    ImGui::BeginDisabled(!not_applied);
    if (ImGui::Button("Revert")) {
        ed.list = ru.list;
        ed.form_for = -1;
    }
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip | ImGuiHoveredFlags_AllowWhenDisabled)) {
        ImGui::SetTooltip("Back to the list the hooks hold now (the last Apply / Reload rules).");
    }
    ImGui::SameLine();
    const bool can_save = cfg.save_rules && bad < 0;
    ImGui::BeginDisabled(!can_save);
    bool save = ImGui::Button("Save");
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip | ImGuiHoveredFlags_AllowWhenDisabled)) {
        if (bad >= 0) {
            ImGui::SetTooltip("%s did not parse (%s) -- edit it below (or Delete it) to Save.",
                              rule_label((size_t)bad, ed.list[(size_t)bad]).c_str(),
                              ed.list[(size_t)bad].error.c_str());
        } else {
            ImGui::SetTooltip(
                "Write this list to RFTrafficEditor.rules.json next to the DLL (the previous file is kept as\n"
                ".bak; comments are not kept). Saving does not apply it.");
        }
    }
    apply = (apply || ed.apply_once) && can_apply;
    save = (save || ed.save_once) && can_save;
    ed.apply_once = ed.save_once = false;
    if (!ed.status.empty()) {
        ImGui::SameLine();
        ImGui::TextColored(ed.status_bad ? kWarn : kOk, "%s", ed.status.c_str());
    }
    const float form_h = ImGui::GetFrameHeightWithSpacing() * 5.0f + ImGui::GetTextLineHeightWithSpacing() * 4.0f;
    const float list_h = std::max(ImGui::GetContentRegionAvail().y - form_h, 80.0f);
    const RuleStats rs = cfg.rule_stats ? cfg.rule_stats() : RuleStats{};
    const ImGuiTableFlags tf = ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersV |
                               ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingFixedFit;
    if (ImGui::BeginTable("rules", 6, tf, ImVec2(0.0f, list_h))) {
        auto w = [](const char* t) {
            return ImGui::CalcTextSize(t).x;
        };
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, w("000*"));
        ImGui::TableSetupColumn("on", ImGuiTableColumnFlags_WidthFixed, ImGui::GetFrameHeight());
        ImGui::TableSetupColumn("name", ImGuiTableColumnFlags_WidthFixed, w("received chat: first letter -> X"));
        ImGui::TableSetupColumn("rule", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("state", ImGuiTableColumnFlags_WidthFixed, w("disabled "));
        ImGui::TableSetupColumn("hits", ImGuiTableColumnFlags_WidthFixed, w("0000000"));
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < n; ++i) {
            PatchRule& r = ed.list[i];
            const bool same = i < ru.list.size() && r == ru.list[i];
            ImGui::PushID((int)i);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            char id[16];
            std::snprintf(id, sizeof id, "%zu%s", i + 1, same ? "" : "*");
            if (ImGui::Selectable(id, ed.sel == (int)i,
                                  ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap)) {
                ed.sel = (int)i;
            }
            if (!same && ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip)) {
                ImGui::SetTooltip("changed since the last Apply -- the hooks hold something else here");
            }
            ImGui::TableNextColumn();
            bool en = r.enabled;
            if (ImGui::Checkbox("##on", &en)) {
                r.enabled = en;
                if ((int)i == ed.form_for) {
                    ed.form.enabled = en;
                }
            }
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(r.name.empty() ? "-" : r.name.c_str());
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(describe_rule(r).c_str());
            ImGui::TableNextColumn();
            const std::string why = check_rule(r);
            if (!why.empty()) {
                ImGui::TextColored(kMismatch, "INVALID");
            } else if (i >= kMaxRules) {
                ImGui::TextColored(kWarn, "ignored");
            } else if (!r.enabled) {
                ImGui::TextDisabled("disabled");
            } else {
                ImGui::TextColored(kOk, "ok");
            }
            if ((!why.empty() || i >= kMaxRules) && ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip)) {
                ImGui::SetTooltip("%s", !why.empty() ? why.c_str() : "only the first 64 rules are used");
            }
            ImGui::TableNextColumn();
            if (cfg.rule_stats && same && i < kMaxRules) {
                ImGui::Text("%llu", (unsigned long long)rs.hits[i]);
            } else {
                ImGui::TextDisabled("-");
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    ImGui::Separator();
    if (ed.sel != ed.form_for) {
        ed.form = ed.sel >= 0 ? form_of(ed.list[(size_t)ed.sel]) : RuleForm{};
        ed.form_for = ed.sel;
    }
    if (ed.form_for >= 0) {
        rule_form(ed);
    } else {
        ImGui::TextDisabled(
            "Select a rule to edit it -- or Add one, or right-click a packet row / a field: New patch rule.");
    }
    ImGui::Text("%zu rule(s), %zu active", ed.list.size(), active_rules(ed.list));
    if (ed.list != ru.list) {
        ImGui::SameLine();
        ImGui::TextColored(kWarn, "   NOT APPLIED (* = changed) -- Apply hands them to the hooks");
    }
    if (editor_unsaved(ed)) {
        ImGui::SameLine();
        ImGui::TextColored(kWarn, "   unsaved -- Save writes RFTrafficEditor.rules.json");
    }
    ImGui::TextDisabled("Rules edit live packets only while Rules (toolbar) is ticked; arming a new list asks first.");
    if (ru.script_changed) {
        ImGui::TextColored(kWarn,
                           "Script %s changed the live list -- its changes are undone when it stops (Apply / Reload "
                           "rules make the list yours).",
                           ru.script_by.c_str());
    }
    switch (op) {
    case 1: {
        PatchRule r;
        r.name = "new rule";
        ed.list.push_back(std::move(r));
        ed.sel = (int)ed.list.size() - 1;
        ed.form_for = -1;
        break;
    }
    case 2: {
        PatchRule r = ed.list[(size_t)ed.sel];
        r.name += " (copy)";
        ed.list.insert(ed.list.begin() + ed.sel + 1, std::move(r));
        ++ed.sel;
        ed.form_for = -1;
        break;
    }
    case 3:
        ed.list.erase(ed.list.begin() + ed.sel);
        ed.sel = std::min(ed.sel, (int)ed.list.size() - 1);
        ed.form_for = -1;
        break;
    case 4:
        std::swap(ed.list[(size_t)ed.sel], ed.list[(size_t)ed.sel - 1]);
        --ed.sel;
        ed.form_for = ed.sel;
        break;
    case 5:
        std::swap(ed.list[(size_t)ed.sel], ed.list[(size_t)ed.sel + 1]);
        ++ed.sel;
        ed.form_for = ed.sel;
        break;
    default:
        break;
    }
    if (apply) {
        request_apply(cfg, ru, ed);
    }
    if (save) {
        save_editor(cfg, ed);
    }
    g_editorRules.store(ed.list.size());
    ImGui::End();
}

void watch_actions(const UiConfig& cfg, uint64_t seen[2]) {
    if (!cfg.action_stats) {
        return;
    }
    const ActionStats s = cfg.action_stats();
    if (s.failed[0] > seen[0]) {
        logmsg("composer: %llu queued send(s) ran but SendNetMessage returned 0 (total %llu) -- not connected, "
               "or the net layer refused it (NetLog\\Client-Net.log says which)",
               (unsigned long long)(s.failed[0] - seen[0]), (unsigned long long)s.failed[0]);
    }
    if (s.failed[1] > seen[1]) {
        logmsg("composer: %llu queued inject(s) ran but AnalysisZoneServerPacket returned 0 (total %llu) -- the "
               "client has no handler for that opcode (\"Unknown Message\" in NetLog\\Client-Net.log)",
               (unsigned long long)(s.failed[1] - seen[1]), (unsigned long long)s.failed[1]);
    }
    seen[0] = s.failed[0];
    seen[1] = s.failed[1];
}

void draw(PacketModel& m, const UiConfig& cfg, ListState& st, FilterBar& fb, FilterView& fv, DetailState& d,
          Composer& c, RulesUi& ru, RulesEditor& ed, ScriptUi& su, ScriptHost& sh, bool grew) {
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(vp->WorkSize);
    ImGui::Begin("##rfte", nullptr,
                 ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings |
                     ImGuiWindowFlags_NoBringToFrontOnFocus);
    ImGui::Checkbox("Follow newest", &st.follow);
    ImGui::SameLine();
    if (ImGui::Button("Clear")) {
        m.clear();
        st.selected = kNoSel;
    }
    ImGui::SameLine();
    capture_toggle(cfg, st);
    ImGui::SameLine();
    ImGui::Checkbox("Composer", &c.open);
    ImGui::SameLine();
    rules_toggle(cfg, ru, ed);
    ImGui::SameLine();
    ImGui::Checkbox("Edit rules", &ed.open);
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip)) {
        ImGui::SetTooltip("The Rules editor: add / edit / delete / reorder the patch rules, Apply them to the hooks, "
                          "Save them to\nRFTrafficEditor.rules.json.");
    }
    if (su.available) {
        ImGui::SameLine();
        script_toggle(su, sh);
    }
    ImGui::SameLine();
    if (ImGui::Button("Unload...")) {
        ImGui::OpenPopup("Unload RFTrafficEditor?");
    }
    if (ImGui::GetTime() < c.flash_until) {
        ImGui::SameLine();
        ImGui::TextColored(c.status_bad ? kWarn : kOk, "%s", c.status.c_str());
    }
    unload_popup();
    if (c.ask) {
        ImGui::OpenPopup("Confirm");
        c.ask = false;
    }
    confirm_popup(c, cfg, sh);
    if (ru.ask) {
        ImGui::OpenPopup("Arm patch rules?");
        ru.ask = false;
    }
    rules_popup(cfg, ru, sh.running() ? su.name.c_str() : nullptr);
    if (ed.ask_apply) {
        ImGui::OpenPopup("Apply edited rules?");
        ed.ask_apply = false;
    }
    apply_popup(cfg, ru, ed);
    if (ed.ask_reload) {
        ImGui::OpenPopup("Reload rules?");
        ed.ask_reload = false;
    }
    reload_popup(cfg, ru, ed);
    if (su.ask) {
        ImGui::OpenPopup("Run script?");
        su.ask = false;
    }
    run_popup(su, sh);
    draw_filter_bar(fb, cfg.db);
    if (fb.edit != fv.filter()) {
        fv.reset(fb.edit);
    }
    const size_t pending = fv.update(m, fv.filter().text.empty() ? 0 : kTextBudget);
    g_shown.store(fv.size());
    g_pending.store(pending);
    const float footer = ImGui::GetTextLineHeightWithSpacing() * 2.0f;
    const Row* sel = st.selected == kNoSel ? nullptr : m.find(st.selected);
    if (!sel) {
        st.selected = kNoSel;
    }
    float list_h = -footer;
    if (sel) {
        const float avail = ImGui::GetContentRegionAvail().y - footer;
        if (st.detail_h <= 0.0f) {
            st.detail_h = avail * 0.5f;
        }
        st.detail_h = std::clamp(st.detail_h, kMinPane, std::max(kMinPane, avail - kMinPane));
        list_h = std::max(avail - st.detail_h - kSplitH - ImGui::GetStyle().ItemSpacing.y * 2.0f, kMinPane * 0.5f);
    }
    draw_list(m, fv, st, fb.edit, cfg, grew, list_h);
    if (sel && st.selected == sel->rec.seq) {
        if (d.view.seq != sel->rec.seq) {
            build_view(d.view, *sel, cfg.db);
            d.pinned = d.hover = Range{};
        }
        splitter(st);
        draw_detail(*sel, d, cfg, st, footer);
        g_detailFrames.fetch_add(1);
        g_detailSeq.store(sel->rec.seq);
        g_detailRows.store((uint64_t)d.rows);
    }
    row_actions(m, cfg, st, c);
    rule_actions(m, st, d, ed);
    draw_status(m, fv, pending, cfg, st, ru, su, sh);
    ImGui::End();
    draw_composer(c, cfg, st.selected == kNoSel ? nullptr : m.find(st.selected));
    draw_rules_editor(ed, ru, cfg);
    draw_scripts(su, sh, cfg);
}

void ui_main(UiConfig cfg, std::promise<bool> ready) {
    HINSTANCE inst = (HINSTANCE)cfg.module;
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof wc;
    wc.style = CS_CLASSDC;
    wc.lpfnWndProc = wnd_proc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = kClass;
    if (!RegisterClassExW(&wc)) {
        logmsg("ui: RegisterClassExW failed (error %lu) -- no window; packets go to the log only",
               (unsigned long)GetLastError());
        ready.set_value(false);
        return;
    }
    const char* fail = nullptr;
    HRESULT hr = S_OK;
    const char* drv = "";
    D3D_FEATURE_LEVEL fl{};
    bool imgui = false, win32 = false;
    g_hwnd = CreateWindowExW(0, kClass, cfg.title.c_str(), WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1280, 800,
                             nullptr, nullptr, inst, nullptr);
    if (!g_hwnd) {
        fail = "CreateWindowExW";
        hr = HRESULT_FROM_WIN32(GetLastError());
    } else if (FAILED(hr = create_device(g_hwnd, &drv, &fl))) {
        fail = "D3D11CreateDeviceAndSwapChain (hardware and WARP)";
    } else if (!create_rtv()) {
        fail = "CreateRenderTargetView";
        hr = E_FAIL;
    }
    if (!fail) {
        IDXGIFactory* f = nullptr;
        if (SUCCEEDED(g_swap->GetParent(__uuidof(IDXGIFactory), (void**)&f)) && f) {
            f->MakeWindowAssociation(g_hwnd, DXGI_MWA_NO_ALT_ENTER);
            f->Release();
        }
        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        imgui = true;
        ImGuiIO& io = ImGui::GetIO();
        io.IniFilename = nullptr;
        io.LogFilename = nullptr;
        ImGui::StyleColorsDark();
        add_font(io);
        if (!(win32 = ImGui_ImplWin32_Init(g_hwnd))) {
            fail = "ImGui_ImplWin32_Init";
        } else if (!ImGui_ImplDX11_Init(g_dev, g_ctx)) {
            fail = "ImGui_ImplDX11_Init";
        }
    }
    if (fail) {
        logmsg("ui: %s failed (hr 0x%08lX) -- no window; packets go to the log only", fail, (unsigned long)hr);
        if (win32) {
            ImGui_ImplWin32_Shutdown();
        }
        if (imgui) {
            ImGui::DestroyContext();
        }
        release_device();
        if (g_hwnd) {
            DestroyWindow(g_hwnd);
            g_hwnd = nullptr;
        }
        UnregisterClassW(kClass, inst);
        ready.set_value(false);
        return;
    }
    if (cfg.show) {
        ShowWindow(g_hwnd, SW_SHOWNOACTIVATE);
    }
    logmsg("ui: window up (D3D11 %s, feature level %u_%u) -- the UI drains the capture ring: packets are "
           "listed there and still logged here; X minimizes, Unload... or Ctrl+Shift+End unloads",
           drv, (unsigned)fl >> 12, ((unsigned)fl >> 8) & 0xFu);
    ready.set_value(true);
    {
        ScriptHost sh(cfg.script.limits, &script_sink);
        PacketModel model(cfg.db, cfg.qpc_base, cfg.qpc_per_ms);
        ListState st;
        st.selected = cfg.select_seq;
        st.resend = cfg.resend_seq;
        st.resend_other = cfg.resend_other;
        st.capture = cfg.capture || !cfg.set_capture;
        if (!st.capture) {
            switch_capture(cfg, false);
        }
        FilterBar fb = make_filter_bar(cfg.filter);
        FilterView fv;
        DetailState d;
        Composer comp = make_composer(cfg.compose);
        RulesUi ru = make_rules_ui(cfg);
        RulesEditor ed = make_rules_editor(cfg);
        ScriptIo sio;
        sio.db = cfg.db;
        sio.send = [&comp, &cfg](const std::string& who, Dir dir, uint8_t mn, uint8_t sb, const uint8_t* p, size_t n) {
            return script_request(comp, cfg, who, dir, mn, sb, p, n);
        };
        sio.rules = [&cfg, &ru]() {
            return ScriptRulesView{cfg.set_rules ? &ru.list : nullptr, ru.armed};
        };
        sio.set_rules = [&cfg, &ru, &ed](const std::string& who, std::vector<PatchRule> l, const std::string& change) {
            return script_rules(cfg, ru, ed, who, std::move(l), change);
        };
        sio.stopped = [&cfg, &ru, &ed]() {
            restore_script_rules(cfg, ru, ed);
        };
        sh.set_io(std::move(sio));
        ScriptUi su = make_script_ui(cfg, sh);
        uint64_t failed_seen[2] = {0, 0};
        if (cfg.action_stats) {
            const ActionStats s0 = cfg.action_stats();
            failed_seen[0] = s0.failed[0];
            failed_seen[1] = s0.failed[1];
        }
        std::vector<PacketRec> batch;
        std::string text;
        bool occluded = false, lost = false;
        while (g_run.load()) {
            MSG msg;
            while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            const uint64_t before = model.ingested();
            drain(model, cfg, batch, text, sh);
            sh.tick();
            publish_script(sh);
            publish(model);
            watch_actions(cfg, failed_seen);
            if (lost || IsIconic(g_hwnd) ||
                (occluded && g_swap->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED)) {
                Sleep(16);
                continue;
            }
            occluded = false;
            if (g_resizeW && g_resizeH) {
                release_rtv();
                g_swap->ResizeBuffers(0, g_resizeW, g_resizeH, DXGI_FORMAT_UNKNOWN, 0);
                g_resizeW = g_resizeH = 0;
                if (!create_rtv()) {
                    lost = true;
                    logmsg("ui: render target lost after a resize -- the window stops drawing; capture and logging "
                           "continue");
                    continue;
                }
            }
            ImGui_ImplDX11_NewFrame();
            ImGui_ImplWin32_NewFrame();
            ImGui::NewFrame();
            draw(model, cfg, st, fb, fv, d, comp, ru, ed, su, sh, model.ingested() != before);
            ImGui::Render();
            const float clear[4] = {0.06f, 0.06f, 0.07f, 1.0f};
            g_ctx->OMSetRenderTargets(1, &g_rtv, nullptr);
            g_ctx->ClearRenderTargetView(g_rtv, clear);
            ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
            serve_snapshot();
            const HRESULT pr = g_swap->Present(1, 0);
            g_frames.fetch_add(1);
            occluded = pr == DXGI_STATUS_OCCLUDED;
            if (pr == DXGI_ERROR_DEVICE_REMOVED || pr == DXGI_ERROR_DEVICE_RESET) {
                lost = true;
                logmsg("ui: D3D11 device lost (hr 0x%08lX) -- the window stops drawing; capture and logging continue",
                       (unsigned long)pr);
            }
        }
        if (!st.capture) {
            switch_capture(cfg, true);
        }
        disarm_rules(cfg, ru, "the UI closed");
        sh.stop("the UI closed");
        sh.set_io(ScriptIo{});
        if (editor_unsaved(ed)) {
            logmsg("rules: the Rules editor's unsaved changes are discarded (the UI closed)");
        }
        publish_script(sh);
        logmsg("ui: closing -- %llu packets taken from the capture ring, %llu rows listed, %llu frames",
               (unsigned long long)model.ingested(), (unsigned long long)model.size(),
               (unsigned long long)g_frames.load());
    }
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    release_device();
    DestroyWindow(g_hwnd);
    g_hwnd = nullptr;
    UnregisterClassW(kClass, inst);
}

}

bool ui_start(const UiConfig& cfg) {
    if (!cfg.drain || g_thread.joinable()) {
        return false;
    }
    g_run.store(true);
    g_unload.store(false);
    g_iter.store(0);
    g_frames.store(0);
    g_ingested.store(0);
    g_dropped.store(0);
    g_rows.store(0);
    g_detailFrames.store(0);
    g_detailSeq.store(~0ull);
    g_detailRows.store(0);
    g_shown.store(0);
    g_pending.store(0);
    g_composerFrames.store(0);
    g_queued.store(0);
    g_rejected.store(0);
    g_confirmAsks.store(0);
    g_resends.store(0);
    g_editorFields.store(0);
    g_fieldEdits.store(0);
    g_detailRoute.store(-1);
    g_composerRoute.store(-1);
    g_routeWarns.store(0);
    g_detailServer.store(-1);
    g_composerServer.store(-1);
    g_serverWarns.store(0);
    g_ruleAsks.store(0);
    g_ruleArms.store(0);
    g_detailEdits.store(-1);
    g_rulesEditorFrames.store(0);
    g_editorRules.store(0);
    g_rulesAdded.store(0);
    g_ruleApplies.store(0);
    g_ruleApplyAsks.store(0);
    g_ruleSaves.store(0);
    g_scriptState.store(0);
    g_scriptRuns.store(0);
    g_scriptAsks.store(0);
    g_scriptPackets.store(0);
    g_scriptCallbacks.store(0);
    g_scriptSkipped.store(0);
    g_scriptTrips.store(0);
    g_scriptErrors.store(0);
    g_scriptLines.store(0);
    g_scriptFrames.store(0);
    g_scriptSent.store(0);
    g_scriptInjected.store(0);
    g_scriptHeld.store(0);
    g_scriptRefused.store(0);
    g_scriptTicks.store(0);
    g_scriptTimers.store(0);
    g_ruleScriptChanges.store(0);
    g_ruleScriptDisarms.store(0);
    g_ruleScriptUndos.store(0);
    std::promise<bool> ready;
    std::future<bool> up = ready.get_future();
    g_thread = std::thread(ui_main, cfg, std::move(ready));
    if (up.get()) {
        return true;
    }
    g_run.store(false);
    g_thread.join();
    return false;
}

void ui_stop() {
    g_run.store(false);
    if (g_thread.joinable()) {
        g_thread.join();
    }
}

bool ui_unload_requested() {
    return g_unload.load();
}

bool ui_snapshot(std::vector<uint32_t>& pixels, int& width, int& height, unsigned timeout_ms) {
    std::unique_lock<std::mutex> lk(g_snapMtx);
    if (!g_run.load()) {
        return false;
    }
    const uint64_t ticket = ++g_snapAsked;
    if (!g_snapCv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                           [&] {
                               return g_snapServed >= ticket;
                           }) ||
        g_snapPx.empty()) {
        return false;
    }
    pixels = g_snapPx;
    width = g_snapW;
    height = g_snapH;
    return true;
}

UiStats ui_stats() {
    UiStats s;
    s.iterations = g_iter.load();
    s.frames = g_frames.load();
    s.ingested = g_ingested.load();
    s.dropped = g_dropped.load();
    s.rows = g_rows.load();
    s.detail_frames = g_detailFrames.load();
    s.detail_seq = g_detailSeq.load();
    s.detail_rows = g_detailRows.load();
    s.shown = g_shown.load();
    s.filter_pending = g_pending.load();
    s.composer_frames = g_composerFrames.load();
    s.queued = g_queued.load();
    s.rejected = g_rejected.load();
    s.confirm_asks = g_confirmAsks.load();
    s.resends = g_resends.load();
    s.editor_fields = g_editorFields.load();
    s.field_edits = g_fieldEdits.load();
    s.detail_route = g_detailRoute.load();
    s.composer_route = g_composerRoute.load();
    s.route_warns = g_routeWarns.load();
    s.detail_server = g_detailServer.load();
    s.composer_server = g_composerServer.load();
    s.server_warns = g_serverWarns.load();
    s.rule_asks = g_ruleAsks.load();
    s.rule_arms = g_ruleArms.load();
    s.detail_edits = g_detailEdits.load();
    s.rules_editor_frames = g_rulesEditorFrames.load();
    s.editor_rules = g_editorRules.load();
    s.rules_added = g_rulesAdded.load();
    s.rule_applies = g_ruleApplies.load();
    s.rule_apply_asks = g_ruleApplyAsks.load();
    s.rule_saves = g_ruleSaves.load();
    s.script_state = g_scriptState.load();
    s.script_runs = g_scriptRuns.load();
    s.script_asks = g_scriptAsks.load();
    s.script_packets = g_scriptPackets.load();
    s.script_callbacks = g_scriptCallbacks.load();
    s.script_skipped = g_scriptSkipped.load();
    s.script_trips = g_scriptTrips.load();
    s.script_errors = g_scriptErrors.load();
    s.script_lines = g_scriptLines.load();
    s.script_frames = g_scriptFrames.load();
    s.script_sent = g_scriptSent.load();
    s.script_injected = g_scriptInjected.load();
    s.script_held = g_scriptHeld.load();
    s.script_refused = g_scriptRefused.load();
    s.script_ticks = g_scriptTicks.load();
    s.script_timers = g_scriptTimers.load();
    s.rule_script_changes = g_ruleScriptChanges.load();
    s.rule_script_disarms = g_ruleScriptDisarms.load();
    s.rule_script_undos = g_ruleScriptUndos.load();
    return s;
}

}
