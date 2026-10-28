#include "script/script_host.h"
#include "hooks/patch_rules.h"
#include "hooks/rules_file.h"
#include "proto/packet_db.h"
#include "proto/packet_text.h"
#include "ui/field_edit.h"
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace rfte {

const char* script_state_name(ScriptState s) {
    switch (s) {
    case ScriptState::Running:
        return "RUNNING";
    case ScriptState::Failed:
        return "FAILED";
    case ScriptState::Tripped:
        return "TRIPPED";
    default:
        return "stopped";
    }
}

namespace {

using Clock = std::chrono::steady_clock;

double ms_since(Clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

constexpr char kHandlers[] = "rfte.on_packet";
constexpr char kPacketMt[] = "rfte.packet";
constexpr size_t kMaxLineChars = 4096;
constexpr int kMaxMakeDepth = 8;
constexpr char kTimers[] = "rfte.timers";
constexpr int kMaxRuleDepth = 4;
constexpr long long kMaxTickMs = 86'400'000;

struct Mem {
    size_t used = 0, cap = 0;
};

void* capped_alloc(void* ud, void* ptr, size_t osize, size_t nsize) {
    Mem* m = static_cast<Mem*>(ud);
    const size_t old = ptr ? osize : 0;
    if (nsize == 0) {
        std::free(ptr);
        m->used -= old;
        return nullptr;
    }
    if (nsize > old && m->used - old + nsize > m->cap) {
        return nullptr;
    }
    void* p = std::realloc(ptr, nsize);
    if (p) {
        m->used = m->used - old + nsize;
    }
    return p;
}

struct Panic : std::runtime_error {
    using std::runtime_error::runtime_error;
};

int on_panic(lua_State* L) {
    throw Panic(lua_type(L, -1) == LUA_TSTRING ? lua_tostring(L, -1) : "(error object is not a string)");
}

lua_State* new_state(Mem* mem) {
#if LUA_VERSION_NUM >= 505
    return lua_newstate(capped_alloc, mem, 0u);
#else
    return lua_newstate(capped_alloc, mem);
#endif
}

std::string display_name(const std::string& chunk) {
    return !chunk.empty() && (chunk[0] == '@' || chunk[0] == '=') ? chunk.substr(1) : chunk;
}

std::string first_line(const std::string& s) {
    return s.substr(0, s.find('\n'));
}

}

struct ScriptHost::Impl {
    ScriptLimits lim;
    Sink sink = nullptr;
    lua_State* L = nullptr;
    Mem mem;
    ScriptState state = ScriptState::Stopped;
    std::string name;
    std::deque<ScriptLine> lines;
    uint64_t line_seq = 0;
    std::string last_error;
    ScriptStats st;
    Clock::time_point start = Clock::now();
    uint64_t count = 0;
    bool tripped = false;
    std::string trip_why;
    Clock::time_point frame_start = Clock::now();
    bool said_skip = false;
    ScriptIo io;
    Clock::time_point rate_start = Clock::now();
    uint32_t rate_n = 0;
    bool said_refused = false;
    Clock::time_point rule_rate_start = Clock::now();
    uint32_t rule_rate_n = 0;
    bool said_rules = false;

    struct Timer {
        uint32_t id;
        double period;
        double due;
        bool once;
    };

    std::vector<Timer> timers;
    uint32_t next_timer = 0;
    double (*clock_fn)() = nullptr;
    Clock::time_point epoch = Clock::now();

    double now_ms() const {
        return clock_fn ? clock_fn() : ms_since(epoch);
    }

    void add(ScriptLine::Kind k, std::string text);
    void arm(lua_State* T);
    static void hook(lua_State* T, lua_Debug* ar);
    bool protect(lua_CFunction fn, void* arg, const std::string& what);
    void stopped_by(int status, const std::string& msg, const std::string& what);
    void close_vm();
    void abandon(const char* why);
    void gone();
};

namespace {

ScriptHost::Impl* impl(lua_State* L) {
    return *static_cast<ScriptHost::Impl**>(lua_getextraspace(L));
}

int l_log(lua_State* L) {
    const int n = lua_gettop(L);
    luaL_Buffer b;
    luaL_buffinit(L, &b);
    for (int i = 1; i <= n; ++i) {
        if (i > 1) {
            luaL_addchar(&b, ' ');
        }
        luaL_tolstring(L, i, nullptr);
        luaL_addvalue(&b);
    }
    luaL_pushresult(&b);
    size_t len = 0;
    const char* s = lua_tolstring(L, -1, &len);
    ScriptHost::Impl* h = impl(L);
    std::string text(s, std::min(len, kMaxLineChars));
    if (len > kMaxLineChars) {
        text += " ...(cut)";
    }
    ++h->st.lines;
    h->add(ScriptLine::Kind::Log, std::move(text));
    return 0;
}

int l_setmetatable(lua_State* L) {
    if (lua_type(L, 2) == LUA_TTABLE) {
        lua_pushliteral(L, "__gc");
        if (lua_rawget(L, 2) != LUA_TNIL) {
            return luaL_error(
                L, "setmetatable: __gc finalizers are not allowed in a script (Lua runs them outside the watchdog)");
        }
        lua_pop(L, 1);
    }
    lua_settop(L, 2);
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_insert(L, 1);
    lua_call(L, 2, 1);
    return 1;
}

int l_on_packet(lua_State* L) {
    luaL_checktype(L, 1, LUA_TFUNCTION);
    lua_getfield(L, LUA_REGISTRYINDEX, kHandlers);
    const lua_Integer n = (lua_Integer)lua_rawlen(L, -1);
    lua_pushvalue(L, 1);
    lua_rawseti(L, -2, n + 1);
    impl(L)->st.handlers = (uint32_t)(n + 1);
    return 0;
}

const unsigned char* payload(lua_State* L, size_t* len) {
    luaL_checktype(L, 1, LUA_TTABLE);
    lua_getfield(L, 1, "bytes");
    if (lua_type(L, -1) != LUA_TSTRING) {
        luaL_error(L, "packet: p.bytes is not a string");
    }
    return reinterpret_cast<const unsigned char*>(lua_tolstring(L, -1, len));
}

int read_at(lua_State* L, int width, char kind) {
    const lua_Integer off = luaL_checkinteger(L, 2);
    size_t len = 0;
    const unsigned char* b = payload(L, &len);
    if (off < 0 || (uint64_t)off + (uint64_t)width > (uint64_t)len) {
        lua_pushnil(L);
        return 1;
    }
    uint32_t v = 0;
    for (int i = width - 1; i >= 0; --i) {
        v = (v << 8) | b[(size_t)off + (size_t)i];
    }
    if (kind == 'f') {
        float f;
        std::memcpy(&f, &v, sizeof f);
        lua_pushnumber(L, (lua_Number)f);
    } else if (kind == 'i') {
        lua_pushinteger(L, width == 1   ? (lua_Integer)(int8_t)v
                           : width == 2 ? (lua_Integer)(int16_t)v
                                        : (lua_Integer)(int32_t)v);
    } else {
        lua_pushinteger(L, (lua_Integer)v);
    }
    return 1;
}

int p_u8(lua_State* L) {
    return read_at(L, 1, 'u');
}

int p_i8(lua_State* L) {
    return read_at(L, 1, 'i');
}

int p_u16(lua_State* L) {
    return read_at(L, 2, 'u');
}

int p_i16(lua_State* L) {
    return read_at(L, 2, 'i');
}

int p_u32(lua_State* L) {
    return read_at(L, 4, 'u');
}

int p_i32(lua_State* L) {
    return read_at(L, 4, 'i');
}

int p_f32(lua_State* L) {
    return read_at(L, 4, 'f');
}

int p_hex(lua_State* L) {
    lua_Integer off = luaL_optinteger(L, 2, 0);
    const lua_Integer n = luaL_optinteger(L, 3, LUA_MAXINTEGER);
    size_t len = 0;
    const unsigned char* b = payload(L, &len);
    const lua_Integer total = (lua_Integer)len;
    off = std::clamp(off, (lua_Integer)0, total);
    const lua_Integer end = off + std::min(std::max(n, (lua_Integer)0), total - off);
    static const char kHex[] = "0123456789ABCDEF";
    luaL_Buffer buf;
    luaL_buffinit(L, &buf);
    for (lua_Integer i = off; i < end; ++i) {
        if (i > off) {
            luaL_addchar(&buf, ' ');
        }
        luaL_addchar(&buf, kHex[b[i] >> 4]);
        luaL_addchar(&buf, kHex[b[i] & 15]);
    }
    luaL_pushresult(&buf);
    return 1;
}

struct Layout {
    const Struct* s = nullptr;
    std::string why;
};

Layout layout_of(const PacketDb* db, const char* name) {
    if (!db) {
        return {nullptr, "no packet db (packet_db.json was not loaded)"};
    }
    if (!name || !*name) {
        return {nullptr, "no layout: the packet db has none for this packet"};
    }
    const Struct* s = db->get(name);
    if (!s) {
        return {nullptr, std::string("no struct '") + name + "' in the packet db"};
    }
    return {s, std::string()};
}

const EditField* find_leaf(const std::vector<EditField>& v, std::string_view name) {
    for (const EditField& f : v) {
        if (!f.type.empty() && f.name == name) {
            return &f;
        }
    }
    for (const EditField& f : v) {
        if (!f.type.empty() && f.prim == Prim::None && !f.text && f.name.size() > name.size() + 2 &&
            f.name.compare(0, name.size(), name) == 0 && f.name[name.size()] == '[' && f.name.back() == ']') {
            return &f;
        }
    }
    return nullptr;
}

std::string field_list(const std::vector<EditField>& v) {
    std::string s;
    for (const EditField& f : v) {
        if (f.type.empty()) {
            continue;
        }
        if (s.size() > 400) {
            s += ", ...";
            break;
        }
        if (!s.empty()) {
            s += ", ";
        }
        s += f.name;
    }
    return s;
}

void push_leaf(lua_State* L, const EditField& f, const uint8_t* p) {
    const uint8_t* at = p + f.offset;
    if (f.prim == Prim::F32) {
        float x;
        std::memcpy(&x, at, 4);
        lua_pushnumber(L, (lua_Number)x);
        return;
    }
    if (f.prim == Prim::F64) {
        double x;
        std::memcpy(&x, at, 8);
        lua_pushnumber(L, (lua_Number)x);
        return;
    }
    if (f.prim != Prim::None) {
        uint64_t u = 0;
        std::memcpy(&u, at, (size_t)std::min(f.size, 8));
        if (f.prim == Prim::Bool && u <= 1) {
            lua_pushboolean(L, (int)u);
            return;
        }
        if (f.prim == Prim::S && f.size < 8) {
            const int sh = 64 - 8 * f.size;
            lua_pushinteger(L, (lua_Integer)((int64_t)(u << sh) >> sh));
            return;
        }
        lua_pushinteger(L, (lua_Integer)u);
        return;
    }
    size_t n = (size_t)f.size;
    if (f.text) {
        n = 0;
        while (n < (size_t)f.size && at[n]) {
            ++n;
        }
    }
    lua_pushlstring(L, reinterpret_cast<const char*>(at), n);
}

int p_field(lua_State* L) {
    const char* name = luaL_checkstring(L, 2);
    size_t len = 0;
    const unsigned char* b = payload(L, &len);
    lua_getfield(L, 1, "layout");
    const PacketDb* db = impl(L)->io.db;
    const Layout lay = layout_of(db, lua_tostring(L, -1));
    std::string why = lay.why;
    if (lay.s) {
        const std::vector<EditField> leaves = edit_fields(*lay.s, db, b, len);
        const EditField* f = find_leaf(leaves, name);
        if (!f) {
            why = std::string("no field '") + name + "' in " + lay.s->name + " -- p:fields() lists them";
        } else if (!present(*f, len)) {
            why = "the payload (" + std::to_string(len) + " B) ends before " + f->name;
        } else {
            push_leaf(L, *f, b);
            return 1;
        }
    }
    lua_pushnil(L);
    lua_pushlstring(L, why.data(), why.size());
    return 2;
}

int p_fields(lua_State* L) {
    size_t len = 0;
    const unsigned char* b = payload(L, &len);
    lua_getfield(L, 1, "layout");
    const PacketDb* db = impl(L)->io.db;
    const Layout lay = layout_of(db, lua_tostring(L, -1));
    std::vector<EditField> leaves;
    if (lay.s) {
        leaves = edit_fields(*lay.s, db, b, len);
    }
    lua_createtable(L, (int)leaves.size(), 0);
    int i = 0;
    for (const EditField& f : leaves) {
        if (f.type.empty()) {
            continue;
        }
        lua_pushlstring(L, f.name.data(), f.name.size());
        lua_rawseti(L, -2, ++i);
    }
    return 1;
}

const luaL_Reg kPacketMethods[] = {
    {"u8", p_u8},   {"i8", p_i8},   {"u16", p_u16},     {"i16", p_i16},       {"u32", p_u32},     {"i32", p_i32},
    {"f32", p_f32}, {"hex", p_hex}, {"field", p_field}, {"fields", p_fields}, {nullptr, nullptr},
};

void push_packet(lua_State* L, const ScriptPacket& p) {
    lua_createtable(L, 0, 13);
    lua_pushinteger(L, (lua_Integer)p.seq);
    lua_setfield(L, -2, "seq");
    lua_pushnumber(L, (lua_Number)p.t_ms);
    lua_setfield(L, -2, "t");
    lua_pushstring(L, p.dir == Dir::C2S ? "C2S" : "S2C");
    lua_setfield(L, -2, "dir");
    lua_pushinteger(L, p.main);
    lua_setfield(L, -2, "main");
    lua_pushinteger(L, p.sub);
    lua_setfield(L, -2, "sub");
    lua_pushinteger(L, p.size);
    lua_setfield(L, -2, "size");
    lua_pushinteger(L, (lua_Integer)p.len);
    lua_setfield(L, -2, "len");
    lua_pushstring(L, p.name ? p.name : "");
    lua_setfield(L, -2, "name");
    lua_pushstring(L, p.status ? p.status : "unknown");
    lua_setfield(L, -2, "status");
    lua_pushstring(L, p.layout ? p.layout : "");
    lua_setfield(L, -2, "layout");
    lua_pushboolean(L, p.edited);
    lua_setfield(L, -2, "edited");
    lua_pushboolean(L, p.tool);
    lua_setfield(L, -2, "tool");
    lua_pushlstring(L, reinterpret_cast<const char*>(p.bytes), p.bytes ? p.len : 0);
    lua_setfield(L, -2, "bytes");
    luaL_setmetatable(L, kPacketMt);
}

const char* send_fn(Dir d) {
    return d == Dir::C2S ? "send_to_server" : "inject_to_client";
}

std::string send_why(ScriptSend r, Dir d, const ScriptLimits& lim) {
    switch (r) {
    case ScriptSend::Held:
        return std::string("held: the first ") + (d == Dir::C2S ? "send to the server" : "inject to the client") +
               " this session waits for Confirm in the tool window -- queued if confirmed, Cancel stops the script";
    case ScriptSend::Waiting:
        return "not queued: a Confirm is open in the tool window";
    case ScriptSend::Full:
        return "not queued: the action queue is full (" + std::to_string(kActionSlots) +
               " pending) -- it drains as the game sends / receives";
    case ScriptSend::TooLong:
        return "not queued: longer than " + std::to_string(kMaxAction) + " bytes";
    case ScriptSend::RateLimited:
        return "not queued: over " + std::to_string(lim.max_actions_per_s) +
               " sends / injects per second from this script";
    default:
        return "not queued: no action queue (the hooks are not installed)";
    }
}

bool rate_ok(ScriptHost::Impl* h) {
    const Clock::time_point now = Clock::now();
    if (now - h->rate_start >= std::chrono::seconds(1)) {
        h->rate_start = now;
        h->rate_n = 0;
    }
    if (h->rate_n >= h->lim.max_actions_per_s) {
        return false;
    }
    ++h->rate_n;
    return true;
}

int send_dir(lua_State* L, Dir dir) {
    const lua_Integer mn = luaL_checkinteger(L, 1);
    const lua_Integer sb = luaL_checkinteger(L, 2);
    luaL_argcheck(L, mn >= 0 && mn <= 255, 1, "main: 0..255");
    luaL_argcheck(L, sb >= 0 && sb <= 255, 2, "sub: 0..255");
    size_t len = 0;
    const char* b = "";
    if (!lua_isnoneornil(L, 3)) {
        luaL_checktype(L, 3, LUA_TSTRING);
        b = lua_tolstring(L, 3, &len);
    }
    ScriptHost::Impl* h = impl(L);
    ScriptSend r;
    if (len > (size_t)kMaxAction) {
        r = ScriptSend::TooLong;
    } else if (!h->io.send) {
        r = ScriptSend::Unavailable;
    } else if (!rate_ok(h)) {
        r = ScriptSend::RateLimited;
    } else {
        r = h->io.send(h->name, dir, (uint8_t)mn, (uint8_t)sb, reinterpret_cast<const uint8_t*>(b), len);
    }
    if (r == ScriptSend::Queued) {
        ++(dir == Dir::C2S ? h->st.sent : h->st.injected);
        lua_pushboolean(L, 1);
        return 1;
    }
    const std::string why = send_why(r, dir, h->lim);
    char what[64];
    std::snprintf(what, sizeof what, "%s(%u,%u) %zu B", send_fn(dir), (unsigned)mn, (unsigned)sb, len);
    if (r == ScriptSend::Held) {
        ++h->st.held;
        h->add(ScriptLine::Kind::Info, std::string(what) + ": " + why);
    } else {
        ++h->st.refused;
        if (!h->said_refused) {
            h->said_refused = true;
            h->add(ScriptLine::Kind::Info,
                   std::string(what) + ": " + why + " -- the call returned false (said once per run)");
        }
    }
    lua_pushboolean(L, 0);
    lua_pushlstring(L, why.data(), why.size());
    return 2;
}

int l_send_to_server(lua_State* L) {
    return send_dir(L, Dir::C2S);
}

int l_inject_to_client(lua_State* L) {
    return send_dir(L, Dir::S2C);
}

std::string shortest(double x) {
    char buf[64];
    const std::to_chars_result r = std::to_chars(buf, buf + sizeof buf, x);
    return std::string(buf, r.ptr);
}

std::string text_escape(const char* s, size_t n) {
    std::string out;
    out.reserve(n);
    char buf[8];
    for (size_t i = 0; i < n; ++i) {
        const uint8_t c = (uint8_t)s[i];
        if (c == '\\') {
            out += "\\\\";
        } else if (c < 0x20 || c >= 0x7F) {
            std::snprintf(buf, sizeof buf, "\\x%02X", (unsigned)c);
            out += buf;
        } else {
            out += (char)c;
        }
    }
    return out;
}

struct MakeCtx {
    const char* sname;
    const std::vector<EditField>* leaves;
    std::vector<uint8_t>* bytes;
};

void set_leaf(lua_State* L, const std::string& name, const MakeCtx& m) {
    const EditField* f = find_leaf(*m.leaves, name);
    if (!f) {
        const std::string list = field_list(*m.leaves);
        luaL_error(L, "make(%s): no field '%s' -- its fields: %s", m.sname, name.c_str(), list.c_str());
    }
    const bool bytes_leaf = f->text || f->prim == Prim::None;
    const int vt = lua_type(L, -1);
    std::string text;
    if (bytes_leaf) {
        if (vt != LUA_TSTRING) {
            luaL_error(L, "make(%s): %s takes a string (%s) -- not a %s", m.sname, name.c_str(),
                       f->text ? "its text" : "its raw bytes", luaL_typename(L, -1));
        }
        size_t n = 0;
        const char* s = lua_tolstring(L, -1, &n);
        text = f->text ? text_escape(s, n) : hex_line(reinterpret_cast<const uint8_t*>(s), n);
    } else if (vt == LUA_TBOOLEAN) {
        const bool on = lua_toboolean(L, -1) != 0;
        text = f->prim == Prim::Bool ? (on ? "true" : "false") : (on ? "1" : "0");
    } else if (vt == LUA_TNUMBER) {
        text = lua_isinteger(L, -1) ? std::to_string((long long)lua_tointeger(L, -1))
                                    : shortest((double)lua_tonumber(L, -1));
    } else if (vt == LUA_TSTRING) {
        text = lua_tostring(L, -1);
    } else {
        luaL_error(L, "make(%s): %s takes a number, a boolean or a string -- not a %s", m.sname, name.c_str(),
                   luaL_typename(L, -1));
    }
    std::string err;
    if (set_field(*f, text, *m.bytes, &err)) {
        return;
    }
    if (bytes_leaf) {
        luaL_error(L, "make(%s): %s: %s", m.sname, name.c_str(), err.c_str());
    }
    luaL_error(L, "make(%s): %s = %s: %s", m.sname, name.c_str(), text.c_str(), err.c_str());
}

void apply_fields(lua_State* L, int t, const std::string& prefix, int depth, const MakeCtx& m) {
    if (depth > kMaxMakeDepth) {
        luaL_error(L, "make(%s): fields nested deeper than %d", m.sname, kMaxMakeDepth);
    }
    t = lua_absindex(L, t);
    luaL_checkstack(L, 3, "make: fields");
    lua_pushnil(L);
    while (lua_next(L, t) != 0) {
        std::string name;
        if (lua_type(L, -2) == LUA_TSTRING) {
            const char* k = lua_tostring(L, -2);
            name = prefix.empty() ? std::string(k) : prefix + "." + k;
        } else if (!prefix.empty() && lua_isinteger(L, -2) && lua_tointeger(L, -2) >= 1) {
            name = prefix + "[" + std::to_string((long long)lua_tointeger(L, -2) - 1) + "]";
        } else {
            luaL_error(L, "make(%s): a field key must be a name -- or, inside a field's table, an index >= 1", m.sname);
        }
        if (lua_type(L, -1) == LUA_TTABLE) {
            apply_fields(L, -1, name, depth + 1, m);
        } else {
            set_leaf(L, name, m);
        }
        lua_pop(L, 1);
    }
}

int l_make(lua_State* L) {
    const char* sname = luaL_checkstring(L, 1);
    if (!lua_isnoneornil(L, 2)) {
        luaL_checktype(L, 2, LUA_TTABLE);
    }
    const PacketDb* db = impl(L)->io.db;
    const Layout lay = layout_of(db, sname);
    if (!lay.s) {
        return luaL_error(L, "make: %s", lay.why.c_str());
    }
    if (lay.s->size <= 0) {
        return luaL_error(L, "make: %s has no measured size", sname);
    }
    std::vector<uint8_t> bytes((size_t)lay.s->size, 0);
    const std::vector<EditField> leaves = edit_fields(*lay.s, db, bytes.data(), bytes.size());
    if (lua_istable(L, 2)) {
        apply_fields(L, 2, std::string(), 0, MakeCtx{sname, &leaves, &bytes});
    }
    lua_pushlstring(L, reinterpret_cast<const char*>(bytes.data()), bytes.size());
    return 1;
}

nlohmann::json lua_json(lua_State* L, int idx, const std::string& where, int depth) {
    idx = lua_absindex(L, idx);
    const char* at = where.empty() ? "the rule" : where.c_str();
    switch (lua_type(L, idx)) {
    case LUA_TSTRING: {
        size_t n = 0;
        const char* s = lua_tolstring(L, idx, &n);
        return nlohmann::json(std::string(s, n));
    }
    case LUA_TBOOLEAN:
        return nlohmann::json(lua_toboolean(L, idx) != 0);
    case LUA_TNUMBER: {
        int isint = 0;
        const lua_Integer i = lua_tointegerx(L, idx, &isint);
        if (isint) {
            return nlohmann::json((long long)i);
        }
        return nlohmann::json((double)lua_tonumber(L, idx));
    }
    case LUA_TTABLE: {
        if (depth >= kMaxRuleDepth) {
            luaL_error(L, "rules.add: %s: nested deeper than %d", at, kMaxRuleDepth);
        }
        nlohmann::json o = nlohmann::json::object();
        luaL_checkstack(L, 3, "rules.add");
        lua_pushnil(L);
        while (lua_next(L, idx) != 0) {
            if (lua_type(L, -2) != LUA_TSTRING) {
                luaL_error(L, "rules.add: %s%severy key must be a name (the rules file's keys)", where.c_str(),
                           where.empty() ? "" : ": ");
            }
            size_t kn = 0;
            const char* ks = lua_tolstring(L, -2, &kn);
            const std::string k(ks, kn);
            o[k] = lua_json(L, -1, where.empty() ? k : where + "." + k, depth + 1);
            lua_pop(L, 1);
        }
        return o;
    }
    default:
        luaL_error(L, "rules.add: %s takes a string, a number, a boolean or a table -- not a %s", at,
                   luaL_typename(L, idx));
        return nlohmann::json();
    }
}

ScriptRulesView rules_view(ScriptHost::Impl* h) {
    return h->io.rules ? h->io.rules() : ScriptRulesView{};
}

bool rules_rate_ok(ScriptHost::Impl* h) {
    const Clock::time_point now = Clock::now();
    if (now - h->rule_rate_start >= std::chrono::seconds(1)) {
        h->rule_rate_start = now;
        h->rule_rate_n = 0;
    }
    if (h->rule_rate_n >= h->lim.max_rule_changes_per_s) {
        return false;
    }
    ++h->rule_rate_n;
    return true;
}

const char* const kNoRules = "not applied: no patch rules here (the hooks are not installed)";

int rules_refuse(lua_State* L, ScriptHost::Impl* h, const char* fn, const std::string& why) {
    ++h->st.rules_refused;
    if (!h->said_rules) {
        h->said_rules = true;
        h->add(ScriptLine::Kind::Info,
               std::string(fn) + ": " + why + " -- the call returned false (said once per run)");
    }
    lua_pushboolean(L, 0);
    lua_pushlstring(L, why.data(), why.size());
    return 2;
}

int rules_apply(lua_State* L, ScriptHost::Impl* h, const char* fn, std::vector<PatchRule> list,
                const std::string& change, lua_Integer index) {
    if (!rules_rate_ok(h)) {
        return rules_refuse(L, h, fn,
                            "not applied: over " + std::to_string(h->lim.max_rule_changes_per_s) +
                                " rule changes per second from this script");
    }
    const ScriptRules a =
        h->io.set_rules ? h->io.set_rules(h->name, std::move(list), change) : ScriptRules::Unavailable;
    if (a == ScriptRules::Unavailable) {
        return rules_refuse(L, h, fn, kNoRules);
    }
    ++h->st.rule_changes;
    if (index > 0) {
        lua_pushinteger(L, index);
    } else {
        lua_pushboolean(L, 1);
    }
    if (a != ScriptRules::Disarmed) {
        return 1;
    }
    const std::string why =
        "applied -- Rules was ARMED and this session has not let scripts change the armed rules: "
        "it is disarmed now (tick Rules: arming the new list asks first, and lets scripts change it)";
    h->add(ScriptLine::Kind::Info, std::string(fn) + ": " + why);
    lua_pushlstring(L, why.data(), why.size());
    return 2;
}

int l_rules_add(lua_State* L) {
    luaL_checktype(L, 1, LUA_TTABLE);
    ScriptHost::Impl* h = impl(L);
    nlohmann::json e = lua_json(L, 1, std::string(), 0);
    if (!e.contains("name")) {
        e["name"] = "script " + h->name;
    }
    const RulesLoad ld =
        parse_rules_json("{\"rules\": [" + e.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace) + "]}");
    if (ld.rules.size() != 1) {
        return luaL_error(L, "rules.add: %s", ld.error.empty() ? "not one rule" : ld.error.c_str());
    }
    const PatchRule& r = ld.rules[0];
    const std::string bad = check_rule(r);
    if (!bad.empty()) {
        return luaL_error(L, "rules.add: %s", bad.c_str());
    }
    const ScriptRulesView v = rules_view(h);
    if (!v.list) {
        return rules_refuse(L, h, "rules.add", kNoRules);
    }
    if (v.list->size() >= kMaxRules) {
        return rules_refuse(L, h, "rules.add",
                            "not added: the Rules list holds " + std::to_string(kMaxRules) + " rules (only the first " +
                                std::to_string(kMaxRules) + " are used) -- rules.remove some");
    }
    std::vector<PatchRule> list = *v.list;
    list.push_back(r);
    const size_t index = list.size();
    const std::string change = "added " + rule_title(index - 1, r);
    return rules_apply(L, h, "rules.add", std::move(list), change, (lua_Integer)index);
}

std::vector<size_t> pick_rules(lua_State* L, const std::vector<PatchRule>& list, std::string* why) {
    std::vector<size_t> out;
    if (lua_type(L, 1) == LUA_TNUMBER) {
        const lua_Integer i = luaL_checkinteger(L, 1);
        if (i >= 1 && (uint64_t)i <= (uint64_t)list.size()) {
            out.push_back((size_t)i - 1);
        } else {
            *why = "no rule #" + std::to_string((long long)i) + " in the Rules list (it holds " +
                   std::to_string(list.size()) + ")";
        }
        return out;
    }
    size_t n = 0;
    const char* s = lua_tolstring(L, 1, &n);
    const std::string name(s, n);
    for (size_t i = 0; i < list.size(); ++i) {
        if (list[i].name == name) {
            out.push_back(i);
        }
    }
    if (out.empty()) {
        *why = "no rule named '" + name + "' in the Rules list";
    }
    return out;
}

int l_rules_enable(lua_State* L) {
    const int t = lua_type(L, 1);
    luaL_argcheck(L, t == LUA_TNUMBER || t == LUA_TSTRING, 1, "a rule name (string) or # (integer)");
    if (!lua_isnoneornil(L, 2)) {
        luaL_checktype(L, 2, LUA_TBOOLEAN);
    }
    const bool on = lua_isnoneornil(L, 2) || lua_toboolean(L, 2) != 0;
    ScriptHost::Impl* h = impl(L);
    const ScriptRulesView v = rules_view(h);
    if (!v.list) {
        return rules_refuse(L, h, "rules.enable", kNoRules);
    }
    std::string why;
    const std::vector<size_t> at = pick_rules(L, *v.list, &why);
    if (at.empty()) {
        return rules_refuse(L, h, "rules.enable", why);
    }
    std::vector<PatchRule> list = *v.list;
    std::string change;
    for (const size_t i : at) {
        if (list[i].enabled == on) {
            continue;
        }
        list[i].enabled = on;
        change +=
            (change.empty() ? std::string(on ? "enabled " : "disabled ") : std::string(", ")) + rule_label(i, list[i]);
    }
    if (change.empty()) {
        lua_pushboolean(L, 1);
        return 1;
    }
    return rules_apply(L, h, "rules.enable", std::move(list), change, 0);
}

int l_rules_remove(lua_State* L) {
    const int t = lua_type(L, 1);
    luaL_argcheck(L, t == LUA_TNUMBER || t == LUA_TSTRING, 1, "a rule name (string) or # (integer)");
    ScriptHost::Impl* h = impl(L);
    const ScriptRulesView v = rules_view(h);
    if (!v.list) {
        return rules_refuse(L, h, "rules.remove", kNoRules);
    }
    std::string why;
    const std::vector<size_t> at = pick_rules(L, *v.list, &why);
    if (at.empty()) {
        return rules_refuse(L, h, "rules.remove", why);
    }
    std::vector<PatchRule> list;
    std::string change;
    for (size_t i = 0, k = 0; i < v.list->size(); ++i) {
        if (k < at.size() && at[k] == i) {
            change += (change.empty() ? "removed " : ", ") + rule_label(i, (*v.list)[i]);
            ++k;
            continue;
        }
        list.push_back((*v.list)[i]);
    }
    return rules_apply(L, h, "rules.remove", std::move(list), change, 0);
}

int l_rules_list(lua_State* L) {
    const ScriptRulesView v = rules_view(impl(L));
    const size_t n = v.list ? v.list->size() : 0;
    lua_createtable(L, (int)n, 0);
    for (size_t i = 0; i < n; ++i) {
        const PatchRule& r = (*v.list)[i];
        const bool valid = check_rule(r).empty();
        const std::string text = r.error.empty() ? describe_rule(r) : "INVALID: " + r.error;
        lua_createtable(L, 0, 5);
        lua_pushlstring(L, r.name.data(), r.name.size());
        lua_setfield(L, -2, "name");
        lua_pushboolean(L, r.enabled);
        lua_setfield(L, -2, "enabled");
        lua_pushboolean(L, valid);
        lua_setfield(L, -2, "valid");
        lua_pushboolean(L, r.enabled && valid && i < kMaxRules);
        lua_setfield(L, -2, "active");
        lua_pushlstring(L, text.data(), text.size());
        lua_setfield(L, -2, "text");
        lua_rawseti(L, -2, (lua_Integer)i + 1);
    }
    return 1;
}

int l_rules_armed(lua_State* L) {
    lua_pushboolean(L, rules_view(impl(L)).armed);
    return 1;
}

const luaL_Reg kRulesFns[] = {
    {"add", l_rules_add},   {"enable", l_rules_enable}, {"remove", l_rules_remove},
    {"list", l_rules_list}, {"armed", l_rules_armed},   {nullptr, nullptr},
};

int add_timer(lua_State* L, bool once) {
    const lua_Integer ms = luaL_checkinteger(L, 1);
    luaL_argcheck(L, ms >= 1 && ms <= kMaxTickMs, 1, "ms: 1..86400000");
    luaL_checktype(L, 2, LUA_TFUNCTION);
    ScriptHost::Impl* h = impl(L);
    if (h->timers.size() >= h->lim.max_timers) {
        return luaL_error(L, "%s: more than %d timers at once -- cancel_tick the ones you no longer need",
                          once ? "after" : "on_tick", (int)h->lim.max_timers);
    }
    const uint32_t id = ++h->next_timer;
    lua_getfield(L, LUA_REGISTRYINDEX, kTimers);
    lua_pushvalue(L, 2);
    lua_rawseti(L, -2, (lua_Integer)id);
    h->timers.push_back(ScriptHost::Impl::Timer{id, (double)ms, h->now_ms() + (double)ms, once});
    h->st.timers = (uint32_t)h->timers.size();
    lua_pushinteger(L, (lua_Integer)id);
    return 1;
}

int l_on_tick(lua_State* L) {
    return add_timer(L, false);
}

int l_after(lua_State* L) {
    return add_timer(L, true);
}

int l_cancel_tick(lua_State* L) {
    const lua_Integer id = luaL_checkinteger(L, 1);
    ScriptHost::Impl* h = impl(L);
    const auto it = std::find_if(h->timers.begin(), h->timers.end(), [id](const ScriptHost::Impl::Timer& t) {
        return (lua_Integer)t.id == id;
    });
    if (it == h->timers.end()) {
        lua_pushboolean(L, 0);
        return 1;
    }
    h->timers.erase(it);
    h->st.timers = (uint32_t)h->timers.size();
    lua_getfield(L, LUA_REGISTRYINDEX, kTimers);
    lua_pushnil(L);
    lua_rawseti(L, -2, id);
    lua_pushboolean(L, 1);
    return 1;
}

struct Fire {
    uint32_t id;
    bool once;
};

int fire(lua_State* L) {
    ScriptHost::Impl* h = impl(L);
    const Fire* f = static_cast<const Fire*>(lua_touserdata(L, 1));
    lua_getfield(L, LUA_REGISTRYINDEX, kTimers);
    lua_rawgeti(L, 2, (lua_Integer)f->id);
    if (lua_type(L, 3) != LUA_TFUNCTION) {
        return 0;
    }
    if (f->once) {
        lua_pushnil(L);
        lua_rawseti(L, 2, (lua_Integer)f->id);
    }
    h->arm(L);
    const Clock::time_point t0 = Clock::now();
    lua_call(L, 0, 0);
    h->st.slowest_ms = std::max(h->st.slowest_ms, ms_since(t0));
    ++h->st.ticks;
    if (h->tripped) {
        return luaL_error(L, "watchdog: %s", h->trip_why.c_str());
    }
    return 0;
}

int setup(lua_State* L) {
    static const luaL_Reg libs[] = {
        {LUA_GNAME, luaopen_base},       {LUA_TABLIBNAME, luaopen_table}, {LUA_STRLIBNAME, luaopen_string},
        {LUA_MATHLIBNAME, luaopen_math}, {LUA_UTF8LIBNAME, luaopen_utf8}, {LUA_COLIBNAME, luaopen_coroutine},
    };
    for (const luaL_Reg& l : libs) {
        luaL_requiref(L, l.name, l.func, 1);
        lua_pop(L, 1);
    }
    for (const char* g : {"dofile", "loadfile", "load"}) {
        lua_pushnil(L);
        lua_setglobal(L, g);
    }
    lua_getglobal(L, "setmetatable");
    lua_pushcclosure(L, l_setmetatable, 1);
    lua_setglobal(L, "setmetatable");
    lua_pushcfunction(L, l_log);
    lua_setglobal(L, "log");
    lua_pushcfunction(L, l_log);
    lua_setglobal(L, "print");
    lua_pushcfunction(L, l_on_packet);
    lua_setglobal(L, "on_packet");
    lua_pushcfunction(L, l_send_to_server);
    lua_setglobal(L, "send_to_server");
    lua_pushcfunction(L, l_inject_to_client);
    lua_setglobal(L, "inject_to_client");
    lua_pushcfunction(L, l_make);
    lua_setglobal(L, "make");
    lua_pushcfunction(L, l_on_tick);
    lua_setglobal(L, "on_tick");
    lua_pushcfunction(L, l_after);
    lua_setglobal(L, "after");
    lua_pushcfunction(L, l_cancel_tick);
    lua_setglobal(L, "cancel_tick");
    luaL_newlib(L, kRulesFns);
    lua_setglobal(L, "rules");
    lua_newtable(L);
    lua_setfield(L, LUA_REGISTRYINDEX, kHandlers);
    lua_newtable(L);
    lua_setfield(L, LUA_REGISTRYINDEX, kTimers);
    luaL_newmetatable(L, kPacketMt);
    luaL_newlib(L, kPacketMethods);
    lua_setfield(L, -2, "__index");
    lua_pop(L, 1);
    return 0;
}

struct Chunk {
    std::string_view code;
    const char* name;
};

int run_chunk(lua_State* L) {
    const Chunk* c = static_cast<const Chunk*>(lua_touserdata(L, 1));
    if (luaL_loadbufferx(L, c->code.data(), c->code.size(), c->name, "t") != LUA_OK) {
        return lua_error(L);
    }
    lua_call(L, 0, 0);
    return 0;
}

int dispatch(lua_State* L) {
    ScriptHost::Impl* h = impl(L);
    const ScriptPacket* p = static_cast<const ScriptPacket*>(lua_touserdata(L, 1));
    push_packet(L, *p);
    lua_getfield(L, LUA_REGISTRYINDEX, kHandlers);
    const lua_Integer n = (lua_Integer)lua_rawlen(L, 3);
    for (lua_Integer i = 1; i <= n; ++i) {
        lua_rawgeti(L, 3, i);
        lua_pushvalue(L, 2);
        h->arm(L);
        const Clock::time_point t0 = Clock::now();
        lua_call(L, 1, 0);
        h->st.slowest_ms = std::max(h->st.slowest_ms, ms_since(t0));
        ++h->st.callbacks;
        if (h->tripped) {
            return luaL_error(L, "watchdog: %s", h->trip_why.c_str());
        }
    }
    return 0;
}

int traceback(lua_State* L) {
    const char* m = lua_type(L, 1) == LUA_TSTRING ? lua_tostring(L, 1) : nullptr;
    if (!m) {
        m = lua_pushfstring(L, "(error object is a %s value)", luaL_typename(L, 1));
    }
    luaL_traceback(L, L, m, 1);
    return 1;
}

}

void ScriptHost::Impl::add(ScriptLine::Kind k, std::string text) {
    if (sink) {
        sink(text.c_str());
    }
    lines.push_back(ScriptLine{k, std::move(text)});
    while (lines.size() > std::max<size_t>(lim.max_lines, 1)) {
        lines.pop_front();
    }
    ++line_seq;
}

void ScriptHost::Impl::arm(lua_State* T) {
    start = Clock::now();
    count = 0;
    lua_sethook(T, hook, LUA_MASKCOUNT, std::max(lim.hook_every, 1));
}

void ScriptHost::Impl::hook(lua_State* T, lua_Debug*) {
    Impl* h = impl(T);
    if (!h->tripped) {
        h->count += (uint64_t)std::max(h->lim.hook_every, 1);
        char why[128] = "";
        if (h->count > h->lim.max_instructions) {
            std::snprintf(why, sizeof why, "more than %llu Lua instructions without returning",
                          (unsigned long long)h->lim.max_instructions);
        } else {
            const double ms = ms_since(h->start);
            if (ms > (double)h->lim.max_ms) {
                std::snprintf(why, sizeof why, "ran %.0f ms without returning (limit %u ms)", ms,
                              (unsigned)h->lim.max_ms);
            }
        }
        if (!why[0]) {
            return;
        }
        h->tripped = true;
        h->trip_why = why;
    }
    lua_sethook(T, hook, LUA_MASKCOUNT, 1);
    if (h->L && T != h->L) {
        lua_sethook(h->L, hook, LUA_MASKCOUNT, 1);
    }
    luaL_error(T, "watchdog: %s", h->trip_why.c_str());
}

bool ScriptHost::Impl::protect(lua_CFunction fn, void* arg, const std::string& what) {
    lua_pushcfunction(L, traceback);
    lua_pushcfunction(L, fn);
    lua_pushlightuserdata(L, arg);
    arm(L);
    const int status = lua_pcall(L, 1, 0, -3);
    if (status == LUA_OK && !tripped) {
        lua_pop(L, 1);
        return true;
    }
    std::string msg;
    if (status != LUA_OK) {
        msg = lua_type(L, -1) == LUA_TSTRING ? std::string(lua_tostring(L, -1)) : std::string("(no message)");
    }
    lua_pop(L, status == LUA_OK ? 1 : 2);
    stopped_by(status, msg, what);
    return false;
}

void ScriptHost::Impl::stopped_by(int status, const std::string& msg, const std::string& what) {
    if (tripped) {
        state = ScriptState::Tripped;
        ++st.trips;
        last_error = "watchdog: " + trip_why + " (in " + what + ")";
        add(ScriptLine::Kind::Error, "STOPPED by the watchdog -- " + trip_why + " (in " + what +
                                         "). The script is disabled: fix it, then Reload / Run.");
    } else {
        state = ScriptState::Failed;
        ++st.errors;
        const std::string m = status == LUA_ERRMEM ? "not enough memory -- the script's VM is capped at " +
                                                         std::to_string(lim.max_bytes >> 20) + " MB"
                                                   : msg;
        last_error = first_line(m);
        add(ScriptLine::Kind::Error, "FAILED (in " + what + "): " + m);
    }
    close_vm();
    gone();
}

void ScriptHost::Impl::close_vm() {
    timers.clear();
    st.timers = 0;
    if (!L) {
        return;
    }
    arm(L);
    try {
        lua_close(L);
    } catch (const Panic&) {
    }
    L = nullptr;
}

void ScriptHost::Impl::abandon(const char* why) {
    L = nullptr;
    state = ScriptState::Failed;
    ++st.errors;
    last_error = std::string("Lua panic: ") + why;
    add(ScriptLine::Kind::Error, "FAILED: " + last_error + " -- the VM is abandoned");
    timers.clear();
    st.timers = 0;
    gone();
}

void ScriptHost::Impl::gone() {
    if (io.stopped) {
        io.stopped();
    }
}

ScriptHost::ScriptHost(ScriptLimits lim, Sink sink) : d_(std::make_unique<Impl>()) {
    d_->lim = lim;
    d_->sink = sink;
}

ScriptHost::~ScriptHost() {
    d_->close_vm();
}

std::string ScriptHost::check(std::string_view code, const std::string& chunk) {
    Mem mem{0, size_t(64) << 20};
    lua_State* L = new_state(&mem);
    if (!L) {
        return "cannot create a Lua state";
    }
    lua_atpanic(L, on_panic);
    std::string err;
    try {
        if (luaL_loadbufferx(L, code.data(), code.size(), chunk.c_str(), "t") != LUA_OK) {
            err = lua_type(L, -1) == LUA_TSTRING ? lua_tostring(L, -1) : "the script does not load";
        }
        lua_close(L);
    } catch (const Panic& e) {
        err = std::string("Lua panic: ") + e.what();
    }
    return err;
}

bool ScriptHost::run(std::string_view code, const std::string& chunk) {
    Impl& h = *d_;
    stop("a new Run");
    h.close_vm();
    const uint64_t runs = h.st.runs, trips = h.st.trips, errors = h.st.errors;
    h.st = ScriptStats{};
    h.st.runs = runs;
    h.st.trips = trips;
    h.st.errors = errors;
    h.tripped = false;
    h.trip_why.clear();
    h.last_error.clear();
    h.said_skip = false;
    h.said_refused = false;
    h.rate_start = Clock::now();
    h.rate_n = 0;
    h.said_rules = false;
    h.rule_rate_start = Clock::now();
    h.rule_rate_n = 0;
    h.next_timer = 0;
    h.name = display_name(chunk);
    h.frame_start = Clock::now();
    const std::string syntax = check(code, chunk);
    if (!syntax.empty()) {
        h.state = ScriptState::Failed;
        ++h.st.errors;
        h.last_error = syntax;
        h.add(ScriptLine::Kind::Error, "FAILED (syntax): " + syntax);
        return false;
    }
    h.mem = Mem{0, h.lim.max_bytes};
    h.L = new_state(&h.mem);
    if (!h.L) {
        h.state = ScriptState::Failed;
        ++h.st.errors;
        h.last_error = "cannot create a Lua state (memory cap " + std::to_string(h.lim.max_bytes >> 20) + " MB)";
        h.add(ScriptLine::Kind::Error, "FAILED: " + h.last_error);
        return false;
    }
    *static_cast<Impl**>(lua_getextraspace(h.L)) = &h;
    lua_atpanic(h.L, on_panic);
    Chunk c{code, chunk.c_str()};
    try {
        if (!h.protect(setup, nullptr, "setting up the VM")) {
            return false;
        }
        if (!h.protect(run_chunk, &c, "the top level of " + h.name)) {
            return false;
        }
    } catch (const Panic& e) {
        h.abandon(e.what());
        return false;
    }
    h.state = ScriptState::Running;
    ++h.st.runs;
    h.add(ScriptLine::Kind::Info, "started " + h.name + " -- " + std::to_string(h.st.handlers) +
                                      " on_packet handler(s), " + std::to_string(h.timers.size()) +
                                      " timer(s); watchdog: " + std::to_string(h.lim.max_instructions) +
                                      " instructions or " + std::to_string(h.lim.max_ms) + " ms per callback");
    return true;
}

void ScriptHost::stop(const char* why) {
    Impl& h = *d_;
    if (h.state != ScriptState::Running) {
        return;
    }
    h.close_vm();
    h.state = ScriptState::Stopped;
    h.add(ScriptLine::Kind::Info, std::string("stopped (") + why + ") -- " + std::to_string(h.st.packets) +
                                      " packet(s), " + std::to_string(h.st.callbacks) + " callback(s) this run");
    h.gone();
}

void ScriptHost::begin_frame() {
    d_->frame_start = Clock::now();
}

void ScriptHost::tick() {
    Impl& h = *d_;
    if (h.state != ScriptState::Running || h.timers.empty()) {
        return;
    }
    const double now = h.now_ms();
    std::vector<Impl::Timer> due;
    for (const Impl::Timer& t : h.timers) {
        if (t.due <= now) {
            due.push_back(t);
        }
    }
    std::stable_sort(due.begin(), due.end(), [](const Impl::Timer& a, const Impl::Timer& b) {
        return a.due < b.due;
    });
    for (const Impl::Timer& d : due) {
        if (h.state != ScriptState::Running) {
            return;
        }
        if (ms_since(h.frame_start) >= (double)h.lim.frame_ms) {
            return;
        }
        const auto it = std::find_if(h.timers.begin(), h.timers.end(), [&d](const Impl::Timer& t) {
            return t.id == d.id;
        });
        if (it == h.timers.end()) {
            continue;
        }
        if (it->once) {
            h.timers.erase(it);
        } else {
            it->due = now + it->period;
        }
        h.st.timers = (uint32_t)h.timers.size();
        char what[64];
        std::snprintf(what, sizeof what, "%s #%u (%s%.0f ms)", d.once ? "after" : "on_tick", (unsigned)d.id,
                      d.once ? "" : "every ", d.period);
        Fire f{d.id, d.once};
        try {
            h.protect(fire, &f, what);
        } catch (const Panic& e) {
            h.abandon(e.what());
            return;
        }
    }
}

void ScriptHost::set_clock(double (*now_ms)()) {
    d_->clock_fn = now_ms;
}

void ScriptHost::on_packet(const ScriptPacket& p) {
    Impl& h = *d_;
    if (h.state != ScriptState::Running || h.st.handlers == 0) {
        return;
    }
    if (ms_since(h.frame_start) >= (double)h.lim.frame_ms) {
        ++h.st.skipped;
        if (!h.said_skip) {
            h.said_skip = true;
            h.add(ScriptLine::Kind::Info,
                  "frame budget: over " + std::to_string(h.lim.frame_ms) +
                      " ms of script in one drain -- the rest of that drain's packets skip the script (counted as "
                      "skipped; said once per run)");
        }
        return;
    }
    ++h.st.packets;
    char what[64];
    std::snprintf(what, sizeof what, "on_packet, packet #%llu %s (%u,%u)", (unsigned long long)p.seq,
                  p.dir == Dir::C2S ? "C2S" : "S2C", (unsigned)p.main, (unsigned)p.sub);
    try {
        h.protect(dispatch, const_cast<ScriptPacket*>(&p), what);
    } catch (const Panic& e) {
        h.abandon(e.what());
    }
}

void ScriptHost::note(std::string text) {
    d_->add(ScriptLine::Kind::Info, std::move(text));
}

void ScriptHost::clear_lines() {
    d_->lines.clear();
}

void ScriptHost::set_io(ScriptIo io) {
    d_->io = std::move(io);
}

ScriptState ScriptHost::state() const {
    return d_->state;
}

const std::deque<ScriptLine>& ScriptHost::lines() const {
    return d_->lines;
}

uint64_t ScriptHost::line_seq() const {
    return d_->line_seq;
}

const std::string& ScriptHost::last_error() const {
    return d_->last_error;
}

const ScriptLimits& ScriptHost::limits() const {
    return d_->lim;
}

ScriptStats ScriptHost::stats() const {
    ScriptStats s = d_->st;
    s.state = d_->state;
    s.mem_bytes = d_->L ? d_->mem.used : 0;
    return s;
}

}
