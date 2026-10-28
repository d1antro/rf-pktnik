#include "ui/field_edit.h"
#include "proto/packet_text.h"
#include <algorithm>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <limits>
#include <system_error>

namespace rfte {
namespace {

void add_leaves(std::vector<EditField>& out, const std::vector<FieldSpan>& spans, const PacketDb* db, const uint8_t* p,
                size_t n, const std::string& prefix, int depth) {
    for (const FieldSpan& sp : spans) {
        EditField e;
        e.offset = sp.offset;
        e.size = sp.size;
        if (sp.kind != FieldSpan::Kind::Field) {
            e.name = prefix + (sp.kind == FieldSpan::Kind::Gap ? "(unmapped)" : "(beyond sizeof)");
            out.push_back(std::move(e));
            continue;
        }
        const Field& f = *sp.field;
        const Struct* elem = db && !f.ref.empty() ? db->get(f.ref) : nullptr;
        if (elem && elem->size > 0 && depth < kEditMaxNest) {
            for (int i = 0; i < f.count; ++i) {
                add_leaves(out, map_element(*elem, sp, i, p, n), db, p, n,
                           prefix + f.name + (f.count > 1 ? "[" + std::to_string(i) + "]." : "."), depth + 1);
            }
            continue;
        }
        const PrimInfo pi = f.ref.empty() ? prim_of(f.type) : PrimInfo{Prim::None, 0};
        const bool prim = pi.kind != Prim::None && sp.size == pi.unit * f.count;
        const std::string arr = f.count > 1 ? "[" + std::to_string(f.count) + "]" : "";
        if (prim && f.count > 1 && f.type == "char") {
            e.name = prefix + f.name;
            e.type = f.type + arr;
            e.text = true;
        } else if (prim && f.count == 1) {
            e.name = prefix + f.name;
            e.type = f.type;
            e.prim = pi.kind;
        } else if (prim && f.count <= kEditMaxElems) {
            for (int i = 0; i < f.count; ++i) {
                EditField x;
                x.name = prefix + f.name + "[" + std::to_string(i) + "]";
                x.type = f.type;
                x.offset = sp.offset + i * pi.unit;
                x.size = pi.unit;
                x.prim = pi.kind;
                out.push_back(std::move(x));
            }
            continue;
        } else {
            e.name = prefix + f.name + arr;
            e.type = f.type + arr;
        }
        out.push_back(std::move(e));
    }
}

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) {
        s.remove_prefix(1);
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) {
        s.remove_suffix(1);
    }
    return s;
}

bool ieq(std::string_view a, const char* b) {
    const size_t n = std::strlen(b);
    if (a.size() != n) {
        return false;
    }
    for (size_t i = 0; i < n; ++i) {
        const char c = a[i] >= 'A' && a[i] <= 'Z' ? (char)(a[i] - 'A' + 'a') : a[i];
        if (c != b[i]) {
            return false;
        }
    }
    return true;
}

bool hex_prefix(std::string_view s) {
    return s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X');
}

int nib(char c) {
    return c >= '0' && c <= '9'   ? c - '0'
           : c >= 'a' && c <= 'f' ? c - 'a' + 10
           : c >= 'A' && c <= 'F' ? c - 'A' + 10
                                  : -1;
}

template <class T> bool whole_int(std::string_view s, T& v, int base) {
    const auto r = std::from_chars(s.data(), s.data() + s.size(), v, base);
    return !s.empty() && r.ec == std::errc() && r.ptr == s.data() + s.size();
}

template <class T> bool whole_float(std::string_view s, T& v) {
    const auto r = std::from_chars(s.data(), s.data() + s.size(), v);
    return !s.empty() && r.ec == std::errc() && r.ptr == s.data() + s.size();
}

uint64_t umax(int unit) {
    return unit >= 8 ? std::numeric_limits<uint64_t>::max() : (uint64_t(1) << (8 * unit)) - 1;
}

bool fail(std::string* err, std::string msg) {
    if (err) {
        *err = std::move(msg);
    }
    return false;
}

}

std::vector<EditField> edit_fields(const Struct& s, const PacketDb* db, const uint8_t* p, size_t n) {
    std::vector<EditField> out;
    add_leaves(out, map_fields(s, p, n), db, p, n, std::string(), 0);
    return out;
}

std::string field_text(const EditField& f, const uint8_t* p, size_t n) {
    if (!present(f, n)) {
        return {};
    }
    const uint8_t* at = p + f.offset;
    char buf[64];
    if (f.prim == Prim::F32 || f.prim == Prim::F64) {
        std::to_chars_result r;
        if (f.prim == Prim::F32) {
            float x;
            std::memcpy(&x, at, 4);
            r = std::to_chars(buf, buf + sizeof buf, x);
        } else {
            double x;
            std::memcpy(&x, at, 8);
            r = std::to_chars(buf, buf + sizeof buf, x);
        }
        return std::string(buf, r.ptr);
    }
    if (f.prim != Prim::None) {
        uint64_t u = 0;
        std::memcpy(&u, at, (size_t)f.size);
        if (f.prim == Prim::Bool && u <= 1) {
            return u ? "true" : "false";
        }
        if (f.prim == Prim::S) {
            const int sh = 64 - 8 * f.size;
            return std::to_string(sh > 0 ? (int64_t)(u << sh) >> sh : (int64_t)u);
        }
        return std::to_string(u);
    }
    if (f.text) {
        std::string out;
        for (int i = 0; i < f.size && at[i]; ++i) {
            const uint8_t c = at[i];
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
    return hex_line(at, (size_t)f.size);
}

bool set_field(const EditField& f, std::string_view text, std::vector<uint8_t>& bytes, std::string* err) {
    if (!present(f, bytes.size())) {
        return fail(err, "the payload (" + std::to_string(bytes.size()) +
                             " B) ends before this field -- Fill to sizeof first");
    }
    uint8_t* at = bytes.data() + f.offset;
    if (f.prim == Prim::F32 || f.prim == Prim::F64) {
        const std::string_view s = trim(text);
        if (f.prim == Prim::F32) {
            float x = 0;
            if (!whole_float(s, x)) {
                return fail(err, "a number for a float (e.g. 1.5, -2, 1e3)");
            }
            std::memcpy(at, &x, 4);
        } else {
            double x = 0;
            if (!whole_float(s, x)) {
                return fail(err, "a number for a double (e.g. 1.5, -2, 1e3)");
            }
            std::memcpy(at, &x, 8);
        }
        return true;
    }
    if (f.prim != Prim::None) {
        const std::string_view s = trim(text);
        const int unit = f.size;
        uint64_t u = 0;
        if (f.prim == Prim::Bool) {
            if (ieq(s, "true")) {
                u = 1;
            } else if (ieq(s, "false")) {
                u = 0;
            } else if (!whole_int(s, u, 10) || u > 255) {
                return fail(err, "true, false or 0..255");
            }
        } else if (hex_prefix(s)) {
            if (!whole_int(s.substr(2), u, 16) || u > umax(unit)) {
                return fail(err, "0x.. with at most " + std::to_string(2 * unit) + " hex digits");
            }
        } else if (f.prim == Prim::S) {
            const int64_t hi = unit >= 8 ? std::numeric_limits<int64_t>::max() : (int64_t(1) << (8 * unit - 1)) - 1;
            const int64_t lo = -hi - 1;
            int64_t v = 0;
            if (!whole_int(s, v, 10) || v < lo || v > hi) {
                return fail(err, "a whole number in " + std::to_string(lo) + ".." + std::to_string(hi));
            }
            u = (uint64_t)v;
        } else {
            if (!whole_int(s, u, 10) || u > umax(unit)) {
                return fail(err, "a whole number in 0.." + std::to_string(umax(unit)) + " (or 0x..)");
            }
        }
        std::memcpy(at, &u, (size_t)unit);
        return true;
    }
    if (f.text) {
        std::string out;
        for (size_t i = 0; i < text.size(); ++i) {
            const char c = text[i];
            if (c != '\\') {
                out += c;
                continue;
            }
            if (i + 1 < text.size() && text[i + 1] == '\\') {
                out += '\\';
                ++i;
                continue;
            }
            if (i + 3 < text.size() && text[i + 1] == 'x' && nib(text[i + 2]) >= 0 && nib(text[i + 3]) >= 0) {
                out += (char)(nib(text[i + 2]) << 4 | nib(text[i + 3]));
                i += 3;
                continue;
            }
            return fail(err, "bad escape at character " + std::to_string(i + 1) + " -- use \\\\ or \\xNN");
        }
        if (out.size() > (size_t)f.size) {
            return fail(err, std::to_string(out.size()) + " bytes: the field holds " + std::to_string(f.size));
        }
        std::memset(at, 0, (size_t)f.size);
        if (!out.empty()) {
            std::memcpy(at, out.data(), out.size());
        }
        return true;
    }
    std::vector<uint8_t> out;
    size_t bad = 0;
    if (!parse_hex(text, out, (size_t)kMaxAction, &bad)) {
        return fail(err, "not hex bytes at character " + std::to_string(bad + 1));
    }
    if (out.size() != (size_t)f.size) {
        return fail(err, std::to_string(out.size()) + " bytes: this field is exactly " + std::to_string(f.size) +
                             " (edits never change the packet's length)");
    }
    if (!out.empty()) {
        std::memcpy(at, out.data(), out.size());
    }
    return true;
}

int layout_choices(const PacketDb& db, Dir dir, uint8_t main, uint8_t sub, uint16_t len,
                   std::vector<const Struct*>& out) {
    out.clear();
    const Decoded d = db.classify(dir, main, sub, len);
    for (const std::string& c : d.candidates) {
        if (const Struct* s = db.get(c)) {
            if (std::find(out.begin(), out.end(), s) == out.end()) {
                out.push_back(s);
            }
        }
    }
    for (size_t i = 0; i < out.size(); ++i) {
        if (out[i] == d.layout) {
            return (int)i;
        }
    }
    return out.empty() ? -1 : 0;
}

}
