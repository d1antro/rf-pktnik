#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

namespace rfte {

struct Pattern {
    std::vector<uint8_t> bytes, mask;
};

bool parse_pattern(const char* text, Pattern& out);
bool match_at(const uint8_t* p, const Pattern& pat);

struct CodeRange {
    const uint8_t* data;
    size_t len;
    uintptr_t va;
};

std::vector<uintptr_t> scan(const CodeRange* ranges, size_t n, const Pattern& pat, size_t max_hits = 8);

}
