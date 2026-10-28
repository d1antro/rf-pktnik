#pragma once
#include "proto/packet_db.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace rfte {

struct FieldSpan {
    enum class Kind : uint8_t {
        Field,
        Gap,
        Extra
    };
    Kind kind = Kind::Field;
    const Field* field = nullptr;
    int offset = 0;
    int size = 0;
    int avail = 0;
    std::string value;
};

enum class Prim : uint8_t {
    None,
    U,
    S,
    Bool,
    F32,
    F64
};

struct PrimInfo {
    Prim kind;
    int unit;
};

PrimInfo prim_of(std::string_view type);

std::vector<FieldSpan> map_fields(const Struct& s, const uint8_t* p, size_t n);
std::vector<FieldSpan> map_element(const Struct& elem, const FieldSpan& sp, int i, const uint8_t* p, size_t n);
void append_field_lines(std::string& out, const std::vector<FieldSpan>& spans);
std::string describe(const Decoded& d, uint16_t len);

}
