#pragma once
#include "hooks/hooks.h"
#include "hooks/rules_file.h"
#include "script/script_host.h"
#include "ui/filter.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace rfte {
class PacketDb;

using DrainFn = size_t (*)(std::vector<PacketRec>& out, size_t max, uint64_t& dropped);
using LogFn = void (*)(const char* text, size_t len);
using CaptureFn = void (*)(bool on);

using QueueFn = Queued (*)(Dir dir, uint8_t main, uint8_t sub, const uint8_t* payload, size_t len);
using CancelFn = size_t (*)();
using ActionStatsFn = ActionStats (*)();

using SetRulesFn = size_t (*)(const std::vector<PatchRule>& rules);
using ArmRulesFn = void (*)(bool on);
using RuleStatsFn = RuleStats (*)();
using ReloadRulesFn = RulesLoad (*)();
using SaveRulesFn = bool (*)(const std::vector<PatchRule>& rules, std::string* err);

struct ComposeInit {
    bool open = false;
    Dir dir = Dir::C2S;
    std::string opcode;
    std::string hex;
    bool confirmed = false;
    bool submit = false;
    bool fill = false;
    std::vector<std::pair<std::string, std::string>> edits;
    int answer = 0;
};

struct RulesEditInit {
    bool open = false;
    uint64_t from_row = ~0ull;
    std::string from_field;
    bool apply = false;
    bool save = false;
};

struct ScriptInit {
    std::string code;
    bool run = false;
    bool confirmed = false;
    bool open = false;
    ScriptLimits limits;
};

struct UiConfig {
    void* module = nullptr;
    const PacketDb* db = nullptr;
    int64_t qpc_base = 0;
    double qpc_per_ms = 1.0;
    std::wstring title = L"pktnik";
    std::string host_build;
    bool show = true;
    DrainFn drain = nullptr;
    LogFn log_packets = nullptr;
    uint64_t select_seq = ~0ull;
    bool open_nested = false;
    CaptureFn set_capture = nullptr;
    bool capture = true;
    Filter filter;
    QueueFn queue_action = nullptr;
    CancelFn cancel_actions = nullptr;
    ActionStatsFn action_stats = nullptr;
    ComposeInit compose;
    uint64_t resend_seq = ~0ull;
    bool resend_other = false;
    std::vector<PatchRule> rules;
    SetRulesFn set_rules = nullptr;
    ArmRulesFn arm_rules = nullptr;
    RuleStatsFn rule_stats = nullptr;
    ReloadRulesFn reload_rules = nullptr;
    bool rules_confirmed = false;
    bool rules_tick = false;
    bool rules_script_ok = false;
    SaveRulesFn save_rules = nullptr;
    RulesEditInit rules_edit;
    std::wstring script_dir;
    ScriptInit script;
};

struct UiStats {
    uint64_t iterations = 0;
    uint64_t frames = 0;
    uint64_t ingested = 0;
    uint64_t dropped = 0;
    uint64_t rows = 0;
    uint64_t detail_frames = 0;
    uint64_t detail_seq = ~0ull;
    uint64_t detail_rows = 0;
    uint64_t shown = 0;
    uint64_t filter_pending = 0;
    uint64_t composer_frames = 0;
    uint64_t queued = 0;
    uint64_t rejected = 0;
    uint64_t confirm_asks = 0;
    uint64_t resends = 0;
    uint64_t editor_fields = 0;
    uint64_t field_edits = 0;
    int detail_route = -1;
    int composer_route = -1;
    uint64_t route_warns = 0;
    int detail_server = -1;
    int composer_server = -1;
    uint64_t server_warns = 0;
    uint64_t rule_asks = 0;
    uint64_t rule_arms = 0;
    int detail_edits = -1;
    uint64_t rules_editor_frames = 0;
    uint64_t editor_rules = 0;
    uint64_t rules_added = 0;
    uint64_t rule_applies = 0;
    uint64_t rule_apply_asks = 0;
    uint64_t rule_saves = 0;
    int script_state = 0;
    uint64_t script_runs = 0;
    uint64_t script_asks = 0;
    uint64_t script_packets = 0;
    uint64_t script_callbacks = 0;
    uint64_t script_skipped = 0;
    uint64_t script_trips = 0;
    uint64_t script_errors = 0;
    uint64_t script_lines = 0;
    uint64_t script_frames = 0;
    uint64_t script_sent = 0;
    uint64_t script_injected = 0;
    uint64_t script_held = 0;
    uint64_t script_refused = 0;
    uint64_t script_ticks = 0;
    uint64_t script_timers = 0;
    uint64_t rule_script_changes = 0;
    uint64_t rule_script_disarms = 0;
    uint64_t rule_script_undos = 0;
};

bool ui_start(const UiConfig& cfg);
void ui_stop();
bool ui_unload_requested();
UiStats ui_stats();
bool ui_snapshot(std::vector<uint32_t>& pixels, int& width, int& height, unsigned timeout_ms = 2000);

}
