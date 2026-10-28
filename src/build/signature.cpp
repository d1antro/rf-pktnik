#include "build/signature.h"

namespace rfte {
namespace {
int hex_nibble(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

bool is_space(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}
}

bool parse_pattern(const char* text, Pattern& out) {
    out.bytes.clear();
    out.mask.clear();
    if (!text) {
        return false;
    }
    const char* p = text;
    for (;;) {
        while (is_space(*p)) {
            ++p;
        }
        if (!*p) {
            break;
        }
        const char* tok = p;
        while (*p && !is_space(*p)) {
            ++p;
        }
        const size_t n = (size_t)(p - tok);
        if ((n == 1 && tok[0] == '?') || (n == 2 && tok[0] == '?' && tok[1] == '?')) {
            out.bytes.push_back(0);
            out.mask.push_back(0);
            continue;
        }
        if (n != 2) {
            return false;
        }
        const int hi = hex_nibble(tok[0]), lo = hex_nibble(tok[1]);
        if (hi < 0 || lo < 0) {
            return false;
        }
        out.bytes.push_back((uint8_t)(hi << 4 | lo));
        out.mask.push_back(1);
    }
    return !out.bytes.empty();
}

bool match_at(const uint8_t* p, const Pattern& pat) {
    for (size_t i = 0; i < pat.bytes.size(); ++i) {
        if (pat.mask[i] && p[i] != pat.bytes[i]) {
            return false;
        }
    }
    return true;
}

std::vector<uintptr_t> scan(const CodeRange* ranges, size_t n, const Pattern& pat, size_t max_hits) {
    std::vector<uintptr_t> hits;
    const size_t m = pat.bytes.size();
    if (m == 0) {
        return hits;
    }
    for (size_t r = 0; r < n; ++r) {
        const CodeRange& cr = ranges[r];
        if (!cr.data || cr.len < m) {
            continue;
        }
        for (size_t off = 0; off + m <= cr.len; ++off) {
            if (match_at(cr.data + off, pat)) {
                hits.push_back(cr.va + off);
                if (hits.size() >= max_hits) {
                    return hits;
                }
            }
        }
    }
    return hits;
}

}
