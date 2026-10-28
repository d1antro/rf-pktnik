#pragma once
#include "hooks/hooks.h"
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace rfte {

class PacketDb;

struct ScriptPacket {
    uint64_t seq = 0;
    double t_ms = 0;
    Dir dir = Dir::C2S;
    uint8_t main = 0, sub = 0;
    uint16_t size = 0;
    bool edited = false;
    bool tool = false;
    const uint8_t* bytes = nullptr;
    size_t len = 0;
    const char* name = "";
    const char* status = "unknown";
    const char* layout = "";
};

struct ScriptLimits {
    uint64_t max_instructions = 20'000'000;
    uint32_t max_ms = 100;
    uint32_t frame_ms = 250;
    size_t max_bytes = size_t(64) << 20;
    int hook_every = 10'000;
    size_t max_lines = 2000;
    uint32_t max_actions_per_s = 2000;
    uint32_t max_rule_changes_per_s = 20;
    uint32_t max_timers = 64;
};

enum class ScriptState : uint8_t {
    Stopped,
    Running,
    Failed,
    Tripped
};
const char* script_state_name(ScriptState s);

struct ScriptLine {
    enum class Kind : uint8_t {
        Log,
        Info,
        Error
    } kind = Kind::Log;
    std::string text;
};

struct ScriptStats {
    ScriptState state = ScriptState::Stopped;
    uint32_t handlers = 0;
    uint64_t packets = 0;
    uint64_t callbacks = 0;
    uint64_t skipped = 0;
    uint64_t lines = 0;
    double slowest_ms = 0;
    size_t mem_bytes = 0;
    uint64_t runs = 0;
    uint64_t trips = 0;
    uint64_t errors = 0;
    uint64_t sent = 0;
    uint64_t injected = 0;
    uint64_t held = 0;
    uint64_t refused = 0;
    uint64_t rule_changes = 0;
    uint64_t rules_refused = 0;
    uint64_t ticks = 0;
    uint32_t timers = 0;
};

enum class ScriptSend : uint8_t {
    Queued,
    Held,
    Waiting,
    Full,
    TooLong,
    Unavailable,
    RateLimited,
};
using ScriptSendFn = std::function<ScriptSend(const std::string& script, Dir dir, uint8_t main, uint8_t sub,
                                              const uint8_t* p, size_t len)>;
enum class ScriptRules : uint8_t {
    Applied,
    Disarmed,
    Unavailable,
};

struct ScriptRulesView {
    const std::vector<PatchRule>* list = nullptr;
    bool armed = false;
};

using ScriptSetRulesFn =
    std::function<ScriptRules(const std::string& script, std::vector<PatchRule> list, const std::string& change)>;

struct ScriptIo {
    const PacketDb* db = nullptr;
    ScriptSendFn send;
    std::function<ScriptRulesView()> rules;
    ScriptSetRulesFn set_rules;
    std::function<void()> stopped;
};

class ScriptHost {
public:
    using Sink = void (*)(const char* line);
    explicit ScriptHost(ScriptLimits lim = {}, Sink sink = nullptr);
    ~ScriptHost();
    ScriptHost(const ScriptHost&) = delete;
    ScriptHost& operator=(const ScriptHost&) = delete;

    static std::string check(std::string_view code, const std::string& chunk);
    bool run(std::string_view code, const std::string& chunk);
    void stop(const char* why);
    void begin_frame();
    void tick();
    void set_clock(double (*now_ms)());
    void on_packet(const ScriptPacket& p);
    void note(std::string text);
    void clear_lines();
    void set_io(ScriptIo io);

    ScriptState state() const;

    bool running() const {
        return state() == ScriptState::Running;
    }

    const std::deque<ScriptLine>& lines() const;
    uint64_t line_seq() const;
    const std::string& last_error() const;
    const ScriptLimits& limits() const;
    ScriptStats stats() const;

    struct Impl;

private:
    std::unique_ptr<Impl> d_;
};

}
