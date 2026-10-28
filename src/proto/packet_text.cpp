#include "proto/packet_text.h"
#include "proto/decode.h"
#include <algorithm>
#include <cstdio>
#include <string>

namespace rfte {

const char* dir_name(Dir d) {
    return d == Dir::C2S ? "C2S" : "S2C";
}

void append_hex_rows(std::string& out, const uint8_t* p, size_t n) {
    static const char kHex[] = "0123456789ABCDEF";
    for (size_t row = 0; row < n; row += 16) {
        char buf[4 + 4 + 2 + 16 * 3 + 1];
        int k = std::snprintf(buf, sizeof buf, "    %04X ", (unsigned)row);
        const size_t end = row + 16 < n ? row + 16 : n;
        for (size_t i = row; i < end; ++i) {
            buf[k++] = ' ';
            buf[k++] = kHex[p[i] >> 4];
            buf[k++] = kHex[p[i] & 0xF];
        }
        buf[k++] = '\n';
        out.append(buf, (size_t)k);
    }
}

namespace {
constexpr size_t kMaxEditLines = 32;

void append_edit_lines(std::string& out, const PacketRec& r) {
    if (!r.edited || r.bytes.empty()) {
        return;
    }
    if (r.before.empty()) {
        out += "    edited: no before-image (lost to capture-ring overflow)\n";
        return;
    }
    const std::vector<EditRun> runs = edit_runs(r.before, r.bytes);
    if (runs.empty()) {
        out += "    edited: no captured byte differs (past the 4 KB capture, or a later rule undid it)\n";
        return;
    }
    const size_t shown = std::min(runs.size(), kMaxEditLines);
    for (size_t i = 0; i < shown; ++i) {
        out += "    edited " + edit_run_text(r, runs[i]) + "\n";
    }
    if (runs.size() > shown) {
        out += "    edited: ... " + std::to_string(runs.size() - shown) + " more run(s)\n";
    }
}
}

std::vector<EditRun> edit_runs(const std::vector<uint8_t>& before, const std::vector<uint8_t>& after) {
    std::vector<EditRun> out;
    const size_t n = std::min(before.size(), after.size());
    for (size_t i = 0; i < n;) {
        if (before[i] == after[i]) {
            ++i;
            continue;
        }
        size_t e = i;
        while (e < n && before[e] != after[e]) {
            ++e;
        }
        out.push_back({i, e - i});
        i = e;
    }
    return out;
}

std::string edit_run_text(const PacketRec& r, const EditRun& e) {
    char head[32];
    std::snprintf(head, sizeof head, "+%04X %zu: ", (unsigned)e.off, e.len);
    return head + hex_line(r.before.data() + e.off, e.len) + " -> " + hex_line(r.bytes.data() + e.off, e.len);
}

std::string format_packet(const PacketRec& r, double t_ms, std::string_view label, const Struct* layout) {
    char head[128];
    int k = std::snprintf(head, sizeof head, "#%llu t+%.3fms %s (%u,%u) size=%u", (unsigned long long)r.seq, t_ms,
                          dir_name(r.dir), (unsigned)r.main, (unsigned)r.sub, (unsigned)r.size);
    std::string out(head, (size_t)k);
    if (!label.empty()) {
        out += ' ';
        out += label;
    }
    if (r.edited) {
        out += " edited";
    }
    if (r.tool) {
        out += " tool";
    }
    if (r.bytes.size() < r.size) {
        k = std::snprintf(head, sizeof head, " captured=%u", (unsigned)r.bytes.size());
        out.append(head, (size_t)k);
    }
    out += '\n';
    append_edit_lines(out, r);
    if (layout) {
        append_field_lines(out, map_fields(*layout, r.bytes.data(), r.bytes.size()));
    }
    append_hex_rows(out, r.bytes.data(), r.bytes.size());
    return out;
}

std::string hex_line(const uint8_t* p, size_t n) {
    static const char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(n * 3);
    for (size_t i = 0; i < n; ++i) {
        if (i) {
            out += ' ';
        }
        out += kHex[p[i] >> 4];
        out += kHex[p[i] & 0xF];
    }
    return out;
}

bool parse_hex(std::string_view s, std::vector<uint8_t>& out, size_t max_len, size_t* bad_at) {
    out.clear();
    auto sep = [](char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',';
    };
    auto nib = [](char c) {
        return c >= '0' && c <= '9'   ? c - '0'
               : c >= 'a' && c <= 'f' ? c - 'a' + 10
               : c >= 'A' && c <= 'F' ? c - 'A' + 10
                                      : -1;
    };
    size_t i = 0;
    while (i < s.size()) {
        if (sep(s[i])) {
            ++i;
            continue;
        }
        const size_t tok = i;
        size_t e = i;
        while (e < s.size() && !sep(s[e])) {
            ++e;
        }
        const bool pre = e - tok >= 2 && s[tok] == '0' && (s[tok + 1] == 'x' || s[tok + 1] == 'X');
        const size_t d = pre ? tok + 2 : tok, digits = e - d;
        bool ok = digits >= 2 && digits % 2 == 0 && (!pre || digits == 2) && out.size() + digits / 2 <= max_len;
        for (size_t k = d; ok && k < e; ++k) {
            ok = nib(s[k]) >= 0;
        }
        if (!ok) {
            out.clear();
            if (bad_at) {
                *bad_at = tok;
            }
            return false;
        }
        for (size_t k = d; k < e; k += 2) {
            out.push_back((uint8_t)(nib(s[k]) << 4 | nib(s[k + 1])));
        }
        i = e;
    }
    return true;
}

std::string format_snippet(const PacketRec& r, std::string_view label, const Struct* layout) {
    static const char kHex[] = "0123456789ABCDEF";
    const size_t n = r.bytes.size();
    char buf[192];
    int k = std::snprintf(buf, sizeof buf, "// #%llu %s (%u,%u) size=%u", (unsigned long long)r.seq, dir_name(r.dir),
                          (unsigned)r.main, (unsigned)r.sub, (unsigned)r.size);
    std::string out(buf, (size_t)k);
    if (!label.empty()) {
        out += ' ';
        out += label;
    }
    if (r.edited) {
        out += " edited";
    }
    if (r.tool) {
        out += " tool";
    }
    if (n < r.size) {
        k = std::snprintf(buf, sizeof buf,
                          " captured=%u\n// msg is the captured prefix only (%u of %u bytes) -- not the whole packet",
                          (unsigned)n, (unsigned)n, (unsigned)r.size);
        out.append(buf, (size_t)k);
    }
    out += '\n';
    if (layout) {
        std::string fl;
        append_field_lines(fl, map_fields(*layout, r.bytes.data(), n));
        for (size_t at = 0; at < fl.size();) {
            const size_t nl = fl.find('\n', at);
            out += "//   ";
            out.append(fl, at + 6, nl - at - 6 + 1);
            at = nl + 1;
        }
    }
    if (r.dir == Dir::C2S) {
        k = std::snprintf(buf, sizeof buf, "const uint8_t byType[2] = { %u, %u };\n", (unsigned)r.main,
                          (unsigned)r.sub);
        out.append(buf, (size_t)k);
    }
    if (n) {
        k = std::snprintf(buf, sizeof buf, "const uint8_t msg[%u] = {\n", (unsigned)n);
        out.append(buf, (size_t)k);
        for (size_t i = 0; i < n; ++i) {
            if (i % 16 == 0) {
                out += "    ";
            }
            out += "0x";
            out += kHex[r.bytes[i] >> 4];
            out += kHex[r.bytes[i] & 0xF];
            out += ',';
            out += (i % 16 == 15 || i + 1 == n) ? '\n' : ' ';
        }
        out += "};\n";
    }
    const char* msg = n ? "(void*)msg" : "nullptr";
    if (r.dir == Dir::C2S) {
        k = std::snprintf(buf, sizeof buf,
                          "CNetworkMgr__SendNetMessage(pThis, dwClientIndex, byType, %s, %u, nNetProcessIdx);\n", msg,
                          (unsigned)n);
    } else {
        k = std::snprintf(buf, sizeof buf,
                          "_MSG_HEADER hdr = { 4 + %u, { %u, %u } };\n"
                          "CNetworkMgr__AnalysisZoneServerPacket(pThis, &hdr, %s);\n",
                          (unsigned)n, (unsigned)r.main, (unsigned)r.sub, msg);
    }
    out.append(buf, (size_t)k);
    return out;
}

}
