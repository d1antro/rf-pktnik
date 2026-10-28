#include "proto/packet_db.h"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <array>
#include <cstdio>
#include <exception>
#include <fstream>
#include <stdexcept>
#include <string>
#include <unordered_map>

namespace rfte {

struct PacketDb::Impl {
    std::unordered_map<std::string, Struct> structs;
    std::unordered_map<uint32_t, std::vector<std::string>> ops;
    size_t n_ops = 0;

    struct Cat {
        uint8_t kind = 0;
        std::string name;
        int slot = -1;
        uint32_t addr = 0;
    };

    struct Arm {
        std::string handler;
        uint32_t addr = 0;
        int bytes = 0;
    };

    bool has_client = false;
    std::string client_build;
    std::array<Cat, 256> cats;
    size_t n_cats = 0;
    std::unordered_map<uint16_t, Arm> arms;

    struct SCat {
        uint8_t kind = 0;
        bool accepts = false;
        std::string handler;
    };

    struct SArm {
        std::string handler, request;
        ServerRoute::Payload payload = ServerRoute::Payload::Unknown;
    };

    bool has_server = false;
    std::string server_build;
    std::array<SCat, 256> scats;
    size_t n_scats = 0;
    std::unordered_map<uint16_t, SArm> sarms;
    int internal_above = -1;
    std::string internal_handler;
    size_t n_triggers = 0;
};

namespace {
uint32_t op_key(Dir dir, uint8_t main, uint8_t sub) {
    return ((uint32_t)dir << 16) | ((uint32_t)main << 8) | (uint32_t)sub;
}

int int_or_null(const nlohmann::json& j, const char* key) {
    const nlohmann::json& v = j.at(key);
    return v.is_null() ? -1 : v.get<int>();
}

uint32_t hex_addr(const nlohmann::json& j) {
    const auto it = j.find("addr");
    return it == j.end() ? 0u : (uint32_t)std::stoul(it->get<std::string>(), nullptr, 16);
}
}

bool PacketDb::load(const std::filesystem::path& json_path, std::string* error) {
    p_.reset();
    std::ifstream f(json_path, std::ios::binary);
    if (!f) {
        if (error) {
            *error = "cannot open the file";
        }
        return false;
    }
    const nlohmann::json j = nlohmann::json::parse(f, nullptr, false);
    if (j.is_discarded()) {
        if (error) {
            *error = "JSON parse error";
        }
        return false;
    }
    auto impl = std::make_shared<Impl>();
    try {
        for (const auto& [name, js] : j.at("structs").items()) {
            Struct s;
            s.name = name;
            s.size = int_or_null(js, "size");
            s.resolved = js.value("resolved", false);
            s.var = js.value("var", false);
            s.source = js.value("source", std::string());
            for (const nlohmann::json& jf : js.at("fields")) {
                Field fd;
                fd.name = jf.at("name").get<std::string>();
                fd.type = jf.at("type").get<std::string>();
                fd.count = jf.value("count", 1);
                fd.offset = jf.at("offset").get<int>();
                fd.size = int_or_null(jf, "size");
                fd.resolved = jf.value("resolved", false);
                fd.ref = jf.value("struct", std::string());
                s.fields.push_back(std::move(fd));
            }
            std::stable_sort(s.fields.begin(), s.fields.end(), [](const Field& a, const Field& b) {
                return a.offset < b.offset;
            });
            impl->structs.emplace(name, std::move(s));
        }
        for (const nlohmann::json& jo : j.at("opcodes")) {
            const std::string d = jo.at("dir").get<std::string>();
            Dir dir;
            if (d == "clzo") {
                dir = Dir::C2S;
            } else if (d == "zocl") {
                dir = Dir::S2C;
            } else {
                continue;
            }
            const int main = jo.at("main").get<int>(), sub = jo.at("sub").get<int>();
            if (main < 0 || main > 255 || sub < 0 || sub > 255) {
                continue;
            }
            impl->ops[op_key(dir, (uint8_t)main, (uint8_t)sub)].push_back(jo.at("struct").get<std::string>());
            ++impl->n_ops;
        }
        if (const auto jc = j.find("client"); jc != j.end()) {
            impl->client_build = jc->at("build").get<std::string>();
            for (const nlohmann::json& c : jc->at("categories")) {
                const int main = c.at("main").get<int>();
                if (main < 0 || main > 255) {
                    continue;
                }
                const std::string kind = c.at("kind").get<std::string>();
                Impl::Cat& cat = impl->cats[(size_t)main];
                if (kind == "direct") {
                    cat.kind = 1;
                } else if (kind == "processor") {
                    cat.kind = 2;
                } else if (kind == "ignored") {
                    cat.kind = 3;
                } else {
                    throw std::runtime_error("client category kind '" + kind + "'");
                }
                cat.name = c.at("name").get<std::string>();
                cat.slot = c.value("slot", -1);
                cat.addr = hex_addr(c);
                ++impl->n_cats;
            }
            for (const nlohmann::json& a : jc->at("arms")) {
                const int main = a.at("main").get<int>(), sub = a.at("sub").get<int>();
                if (main < 0 || main > 255 || sub < 0 || sub > 255) {
                    continue;
                }
                impl->arms[(uint16_t)(main << 8 | sub)] =
                    Impl::Arm{a.at("handler").get<std::string>(), hex_addr(a), a.value("bytes", 0)};
            }
            impl->has_client = true;
        }
        if (const auto js = j.find("server"); js != j.end()) {
            impl->server_build = js->value("build", std::string("2.2.3.2"));
            for (const nlohmann::json& c : js->at("categories")) {
                const int main = c.at("main").get<int>();
                if (main < 0 || main > 255) {
                    continue;
                }
                const std::string kind = c.at("kind").get<std::string>();
                Impl::SCat& cat = impl->scats[(size_t)main];
                if (kind == "switch") {
                    cat.kind = 1;
                } else if (kind == "any") {
                    cat.kind = 2;
                } else {
                    throw std::runtime_error("server category kind '" + kind + "'");
                }
                cat.accepts = c.value("default", std::string("refused")) == "accepted";
                cat.handler = c.value("handler", std::string());
                ++impl->n_scats;
            }
            for (const nlohmann::json& a : js->at("arms")) {
                const int main = a.at("main").get<int>(), sub = a.at("sub").get<int>();
                if (main < 0 || main > 255 || sub < 0 || sub > 255) {
                    continue;
                }
                Impl::SArm arm;
                arm.handler = a.at("handler").get<std::string>();
                arm.request = a.value("struct", std::string());
                const std::string pl = a.value("payload", std::string());
                arm.payload = !arm.request.empty() ? ServerRoute::Payload::Struct
                              : pl == "unread"     ? ServerRoute::Payload::Unread
                              : pl == "forwarded"  ? ServerRoute::Payload::Forwarded
                                                   : ServerRoute::Payload::Unknown;
                if (arm.payload == ServerRoute::Payload::Unread &&
                    impl->ops.find(op_key(Dir::C2S, (uint8_t)main, (uint8_t)sub)) == impl->ops.end()) {
                    ++impl->n_triggers;
                }
                impl->sarms[(uint16_t)(main << 8 | sub)] = std::move(arm);
            }
            if (const auto ji = js->find("internal"); ji != js->end()) {
                impl->internal_above = ji->at("above").get<int>();
                impl->internal_handler = ji->at("handler").get<std::string>();
            }
            impl->has_server = true;
        }
    } catch (const std::exception& e) {
        if (error) {
            *error = std::string("schema: ") + e.what();
        }
        return false;
    }
    p_ = impl;
    return true;
}

Decoded PacketDb::classify(Dir dir, uint8_t main, uint8_t sub, uint16_t len) const {
    Decoded d;
    if (!p_) {
        return d;
    }
    const auto it = p_->ops.find(op_key(dir, main, sub));
    if (it == p_->ops.end()) {
        if (dir == Dir::C2S && p_->has_server) {
            const ServerRoute r = server_route(main, sub);
            if (r.kind == ServerRoute::Kind::Arm || r.kind == ServerRoute::Kind::Any) {
                d.name = r.handler;
            }
            if (r.trigger()) {
                d.status = Status::Trigger;
            }
        }
        return d;
    }
    const std::vector<std::string>& cands = it->second;
    std::vector<const Struct*> layouts;
    for (const std::string& c : cands) {
        const Struct* s = get(c);
        d.candidates.push_back(c);
        d.candidate_sizes.push_back(s ? s->size : -1);
        if (s) {
            layouts.push_back(s);
        }
    }
    if (layouts.empty()) {
        d.name = cands.size() == 1 ? cands[0] : std::string();
        return d;
    }
    const int n = (int)len;
    auto choose = [&](const Struct* s, Status st) {
        d.layout = s;
        d.name = s->name;
        d.status = st;
        return d;
    };
    for (const Struct* s : layouts) {
        if (s->size == n) {
            return choose(s, Status::Ok);
        }
    }
    for (const Struct* s : layouts) {
        if (s->var && (s->size < 0 || n < s->size)) {
            return choose(s, Status::Var);
        }
    }
    if (layouts.size() == 1) {
        return choose(layouts[0], Status::Mismatch);
    }
    d.status = Status::Mismatch;
    return d;
}

const Struct* PacketDb::get(const std::string& name) const {
    if (!p_) {
        return nullptr;
    }
    const auto it = p_->structs.find(name);
    return it == p_->structs.end() ? nullptr : &it->second;
}

std::vector<const Struct*> PacketDb::all() const {
    std::vector<const Struct*> out;
    if (!p_) {
        return out;
    }
    out.reserve(p_->structs.size());
    for (const auto& kv : p_->structs) {
        out.push_back(&kv.second);
    }
    std::sort(out.begin(), out.end(), [](const Struct* a, const Struct* b) {
        return a->name < b->name;
    });
    return out;
}

size_t PacketDb::struct_count() const {
    return p_ ? p_->structs.size() : 0;
}

size_t PacketDb::opcode_count() const {
    return p_ ? p_->n_ops : 0;
}

bool PacketDb::has_client() const {
    return p_ && p_->has_client;
}

std::string PacketDb::client_build() const {
    return has_client() ? p_->client_build : std::string();
}

size_t PacketDb::client_category_count() const {
    return has_client() ? p_->n_cats : 0;
}

size_t PacketDb::client_arm_count() const {
    return has_client() ? p_->arms.size() : 0;
}

ClientRoute PacketDb::client_route(uint8_t main, uint8_t sub) const {
    ClientRoute r;
    if (!has_client()) {
        return r;
    }
    r.build = p_->client_build;
    const Impl::Cat& c = p_->cats[main];
    r.group = c.name;
    switch (c.kind) {
    case 1: {
        const auto it = p_->arms.find((uint16_t)(main << 8 | sub));
        if (it == p_->arms.end()) {
            r.kind = ClientRoute::Kind::NoArm;
            break;
        }
        r.kind = ClientRoute::Kind::Arm;
        r.handler = it->second.handler;
        r.addr = it->second.addr;
        r.bytes = it->second.bytes;
        break;
    }
    case 2:
        r.kind = ClientRoute::Kind::Processor;
        r.addr = c.addr;
        r.slot = c.slot;
        break;
    case 3:
        r.kind = ClientRoute::Kind::Ignored;
        break;
    default:
        r.kind = ClientRoute::Kind::NoCase;
        break;
    }
    return r;
}

std::string route_text(const ClientRoute& r, uint8_t main, uint8_t sub) {
    char buf[256];
    const unsigned m = main, s = sub;
    const char* b = r.build.c_str();
    const char* g = r.group.c_str();
    switch (r.kind) {
    case ClientRoute::Kind::Arm:
        std::snprintf(buf, sizeof buf, "client %s: %s (%u,%u) -> %s @0x%06x (%d B)", b, g, m, s, r.handler.c_str(),
                      (unsigned)r.addr, r.bytes);
        break;
    case ClientRoute::Kind::Processor:
        if (r.addr) {
            std::snprintf(buf, sizeof buf,
                          "client %s: (%u,%u) -> %s::AnalysisServerPacket @0x%06x (m_pMsgProcessor[%d]) "
                          "-- its sub switch is not mapped yet",
                          b, m, s, g, (unsigned)r.addr, r.slot);
        } else {
            std::snprintf(buf, sizeof buf,
                          "client %s: (%u,%u) -> %s::AnalysisServerPacket (m_pMsgProcessor[%d]) "
                          "-- its sub switch is not mapped yet",
                          b, m, s, g, r.slot);
        }
        break;
    case ClientRoute::Kind::Ignored:
        std::snprintf(buf, sizeof buf, "client %s: %s (%u,%u) -- accepted and ignored (returns 1)", b, g, m, s);
        break;
    case ClientRoute::Kind::NoArm:
        std::snprintf(buf, sizeof buf,
                      "client %s: NO HANDLER for (%u,%u) -- %s has no arm for sub %u: "
                      "\"Unknown Message\", returns 0",
                      b, m, s, g, s);
        break;
    case ClientRoute::Kind::NoCase:
        std::snprintf(buf, sizeof buf,
                      "client %s: NO HANDLER for (%u,%u) -- no case for main %u: "
                      "\"Unknown Message\", returns 0",
                      b, m, s, m);
        break;
    default:
        return {};
    }
    return buf;
}

bool route_on_host(const ClientRoute& r, const std::string& host) {
    return host.empty() || r.kind == ClientRoute::Kind::NoData || r.build == host;
}

std::string route_text(const ClientRoute& r, uint8_t main, uint8_t sub, const std::string& host) {
    std::string t = route_text(r, main, sub);
    if (!t.empty() && !route_on_host(r, host)) {
        t += "  [" + r.build + " reference -- this client is " + host + "]";
    }
    return t;
}

bool PacketDb::has_server() const {
    return p_ && p_->has_server;
}

std::string PacketDb::server_build() const {
    return has_server() ? p_->server_build : std::string();
}

size_t PacketDb::server_category_count() const {
    return has_server() ? p_->n_scats : 0;
}

size_t PacketDb::server_arm_count() const {
    return has_server() ? p_->sarms.size() : 0;
}

size_t PacketDb::server_trigger_count() const {
    return has_server() ? p_->n_triggers : 0;
}

ServerRoute PacketDb::server_route(uint8_t main, uint8_t sub) const {
    ServerRoute r;
    if (!has_server()) {
        return r;
    }
    r.build = p_->server_build;
    if (p_->internal_above >= 0 && (int)main > p_->internal_above) {
        r.kind = ServerRoute::Kind::Internal;
        r.handler = p_->internal_handler;
        r.above = p_->internal_above;
        return r;
    }
    const Impl::SCat& c = p_->scats[main];
    switch (c.kind) {
    case 1: {
        const auto it = p_->sarms.find((uint16_t)(main << 8 | sub));
        if (it == p_->sarms.end()) {
            r.kind = c.accepts ? ServerRoute::Kind::Accepted : ServerRoute::Kind::NoArm;
            break;
        }
        r.kind = ServerRoute::Kind::Arm;
        r.handler = it->second.handler;
        r.request = it->second.request;
        r.payload = it->second.payload;
        break;
    }
    case 2:
        r.kind = ServerRoute::Kind::Any;
        r.handler = c.handler;
        break;
    default:
        r.kind = ServerRoute::Kind::NoCase;
        break;
    }
    return r;
}

std::string server_text(const ServerRoute& r, uint8_t main, uint8_t sub) {
    if (r.kind == ServerRoute::Kind::NoData) {
        return {};
    }
    char key[96];
    const unsigned m = main, s = sub;
    std::string t = "server " + r.build + ": ";
    switch (r.kind) {
    case ServerRoute::Kind::Arm:
        std::snprintf(key, sizeof key, "(%u,%u) -> ", m, s);
        t += key + r.handler;
        switch (r.payload) {
        case ServerRoute::Payload::Struct:
            t += " reads " + r.request;
            break;
        case ServerRoute::Payload::Unread:
            t += " -- a trigger: it reads no payload";
            break;
        case ServerRoute::Payload::Forwarded:
            t += " -- passes the payload on (no request struct mapped)";
            break;
        default:
            t += " -- no request struct";
            break;
        }
        break;
    case ServerRoute::Kind::Any:
        std::snprintf(key, sizeof key, "(%u,%u) -> ", m, s);
        t += key + r.handler;
        std::snprintf(key, sizeof key, " (category %u takes any sub)", m);
        t += key;
        break;
    case ServerRoute::Kind::Accepted:
        std::snprintf(key, sizeof key, "NO HANDLER for (%u,%u) -- category %u has no arm for sub %u; ", m, s, m, s);
        t += key;
        t += "its default returns true: accepted, nothing done";
        break;
    case ServerRoute::Kind::NoArm:
        std::snprintf(key, sizeof key, "NO HANDLER for (%u,%u) -- category %u has no arm for sub %u: ", m, s, m, s);
        t += key;
        t += "returns false -> OddMsg, the server closes the connection";
        break;
    case ServerRoute::Kind::NoCase:
        std::snprintf(key, sizeof key, "NO HANDLER for (%u,%u) -- no case for main %u: ", m, s, m);
        t += key;
        t += "returns false -> OddMsg, the server closes the connection";
        break;
    case ServerRoute::Kind::Internal:
        std::snprintf(key, sizeof key, "(%u,%u) -> ", m, s);
        t += key + r.handler;
        std::snprintf(key, sizeof key, " (main > %d: not ClientLineAnalysis) -- not mapped", r.above);
        t += key;
        break;
    default:
        return {};
    }
    return t;
}

bool route_on_host(const ServerRoute& r, const std::string& host) {
    return host.empty() || r.kind == ServerRoute::Kind::NoData || r.build == host;
}

std::string server_text(const ServerRoute& r, uint8_t main, uint8_t sub, const std::string& host) {
    std::string t = server_text(r, main, sub);
    if (!t.empty() && !route_on_host(r, host)) {
        t += "  [" + r.build + " reference -- this client is " + host + "]";
    }
    return t;
}

}
