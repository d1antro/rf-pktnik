#pragma once
#include "proto/decode.h"
#include "ui/packet_model.h"
#include <cstdint>
#include <string>
#include <vector>

namespace rfte {

struct PacketView {
    uint64_t seq = ~0ull;
    std::vector<const Struct*> layouts;
    int pick = -1;
    bool trial = false;
    std::vector<FieldSpan> spans;
    std::vector<int> owner;
};

void build_view(PacketView& v, const Row& r, const PacketDb* db, int pick = -1);

enum class CopyKind : uint8_t {
    Hex,
    Decoded,
    Snippet
};
std::string copy_text(const PacketView& v, const Row& r, CopyKind k);

}
