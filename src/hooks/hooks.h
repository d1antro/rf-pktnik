#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace rfte {

enum class Dir : uint8_t {
    C2S = 0,
    S2C = 1
};

inline constexpr int kMaxCapture = 4096;

struct PacketRec {
    uint64_t seq;
    uint64_t ts_qpc;
    Dir dir;
    uint8_t main;
    uint8_t sub;
    uint16_t size;
    bool edited;
    bool tool = false;
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> before;
};

bool install_hooks();
bool uninstall_hooks(unsigned wait_ms = 5000);

struct HookStats {
    void* send_self = nullptr;
    void* recv_self = nullptr;
    uint32_t send_tid = 0;
    uint32_t recv_tid = 0;
    bool have_send_args = false;
    uint32_t client_idx = 0;
    int32_t net_proc_idx = 0;
    uint32_t n_send = 0, n_recv = 0;
};

HookStats hook_stats();

size_t drain_captures(std::vector<PacketRec>& out, size_t max, uint64_t& dropped);
void set_capture_enabled(bool on);

inline constexpr int kMaxAction = kMaxCapture;
inline constexpr size_t kActionSlots = 128;

enum class Queued : uint8_t {
    Ok,
    Full,
    TooLong,
    Unavailable
};

Queued queue_action(Dir dir, uint8_t main, uint8_t sub, const uint8_t* payload, size_t len);
size_t cancel_actions();

struct ActionStats {
    uint32_t pending[2] = {0, 0};
    uint64_t done[2] = {0, 0};
    uint64_t failed[2] = {0, 0};
    uint32_t calls[2] = {0, 0};
};

ActionStats action_stats();

inline constexpr uint16_t kAnyByte = 0x100;
inline constexpr size_t kMaxRules = 64;
inline constexpr size_t kMaxRuleBytes = 64;

struct PatchRule {
    std::string name;
    bool enabled = true;
    Dir dir = Dir::C2S;
    int main = -1, sub = -1;
    int match_off = -1;
    std::vector<uint16_t> match_pat;
    enum class Kind : uint8_t {
        Write,
        Replace
    } kind = Kind::Write;
    int write_off = 0;
    std::vector<uint16_t> write_bytes;
    std::vector<uint16_t> find_bytes;
    std::vector<uint16_t> repl_bytes;
    std::string error;
    bool operator==(const PatchRule&) const = default;
};

struct RuleStats {
    bool armed = false;
    uint32_t active = 0;
    uint64_t edited[2] = {0, 0};
    uint64_t hits[kMaxRules] = {};
};

size_t set_rules(const std::vector<PatchRule>& rules);
void arm_rules(bool on);
RuleStats rule_stats();

}
