#pragma once
#include "hooks/hooks.h"
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace rfte {

struct Field {
    std::string name, type;
    int count = 1;
    int offset = 0;
    int size = -1;
    bool resolved = false;
    std::string ref;
};

struct Struct {
    std::string name;
    int size = -1;
    bool resolved = false;
    bool var = false;
    std::string source;
    std::vector<Field> fields;
};

enum class Status : uint8_t {
    Ok,
    Unknown,
    Mismatch,
    Var,
    Trigger
};
constexpr size_t kStatusCount = 5;

inline const char* status_name(Status s) {
    switch (s) {
    case Status::Ok:
        return "ok";
    case Status::Mismatch:
        return "mismatch";
    case Status::Var:
        return "var";
    case Status::Trigger:
        return "trigger";
    default:
        return "unknown";
    }
}

struct Decoded {
    Status status = Status::Unknown;
    std::string name;
    const Struct* layout = nullptr;
    std::vector<std::string> candidates;
    std::vector<int> candidate_sizes;
};

struct ClientRoute {
    enum class Kind : uint8_t {
        NoData,
        Arm,
        Processor,
        Ignored,
        NoArm,
        NoCase,
    };
    Kind kind = Kind::NoData;
    std::string build;
    std::string group;
    std::string handler;
    uint32_t addr = 0;
    int bytes = 0;
    int slot = -1;

    bool refused() const {
        return kind == Kind::NoArm || kind == Kind::NoCase;
    }
};

std::string route_text(const ClientRoute& r, uint8_t main, uint8_t sub);
bool route_on_host(const ClientRoute& r, const std::string& host);
std::string route_text(const ClientRoute& r, uint8_t main, uint8_t sub, const std::string& host);

struct ServerRoute {
    enum class Kind : uint8_t {
        NoData,
        Arm,
        Any,
        Accepted,
        NoArm,
        NoCase,
        Internal,
    };
    enum class Payload : uint8_t {
        Unknown,
        Struct,
        Unread,
        Forwarded,
    };
    Kind kind = Kind::NoData;
    std::string build;
    std::string handler;
    std::string request;
    Payload payload = Payload::Unknown;
    int above = -1;

    bool refused() const {
        return kind == Kind::NoArm || kind == Kind::NoCase;
    }

    bool trigger() const {
        return kind == Kind::Arm && payload == Payload::Unread;
    }
};

std::string server_text(const ServerRoute& r, uint8_t main, uint8_t sub);
bool route_on_host(const ServerRoute& r, const std::string& host);
std::string server_text(const ServerRoute& r, uint8_t main, uint8_t sub, const std::string& host);

class PacketDb {
public:
    bool load(const std::filesystem::path& json_path, std::string* error = nullptr);
    Decoded classify(Dir dir, uint8_t main, uint8_t sub, uint16_t len) const;
    const Struct* get(const std::string& name) const;
    std::vector<const Struct*> all() const;
    size_t struct_count() const;
    size_t opcode_count() const;
    bool has_client() const;
    ClientRoute client_route(uint8_t main, uint8_t sub) const;
    std::string client_build() const;
    size_t client_category_count() const;
    size_t client_arm_count() const;
    bool has_server() const;
    ServerRoute server_route(uint8_t main, uint8_t sub) const;
    std::string server_build() const;
    size_t server_category_count() const;
    size_t server_arm_count() const;
    size_t server_trigger_count() const;

private:
    struct Impl;
    std::shared_ptr<const Impl> p_;
};

}
