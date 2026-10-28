#pragma once
#include "proto/decode.h"
#include "proto/packet_db.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace rfte {

struct EditField {
    std::string name;
    std::string type;
    int offset = 0;
    int size = 0;
    Prim prim = Prim::None;
    bool text = false;
};

constexpr int kEditMaxElems = 16;
constexpr int kEditMaxNest = 4;

std::vector<EditField> edit_fields(const Struct& s, const PacketDb* db, const uint8_t* p, size_t n);

inline bool present(const EditField& f, size_t n) {
    return f.offset >= 0 && f.size >= 0 && (size_t)f.offset + (size_t)f.size <= n;
}

std::string field_text(const EditField& f, const uint8_t* p, size_t n);

bool set_field(const EditField& f, std::string_view text, std::vector<uint8_t>& bytes, std::string* err = nullptr);

int layout_choices(const PacketDb& db, Dir dir, uint8_t main, uint8_t sub, uint16_t len,
                   std::vector<const Struct*>& out);

}
