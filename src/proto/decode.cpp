#include "proto/decode.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string_view>

namespace rfte {

PrimInfo prim_of(std::string_view t) {
    static const struct {
        const char* name;
        Prim kind;
        int unit;
    } kTable[] = {
        {"uint8_t", Prim::U, 1},
        {"unsigned char", Prim::U, 1},
        {"BYTE", Prim::U, 1},
        {"unsigned __int8", Prim::U, 1},
        {"int8_t", Prim::S, 1},
        {"signed char", Prim::S, 1},
        {"__int8", Prim::S, 1},
        {"char", Prim::S, 1},
        {"bool", Prim::Bool, 1},
        {"uint16_t", Prim::U, 2},
        {"unsigned short", Prim::U, 2},
        {"WORD", Prim::U, 2},
        {"unsigned __int16", Prim::U, 2},
        {"wchar_t", Prim::U, 2},
        {"int16_t", Prim::S, 2},
        {"short", Prim::S, 2},
        {"__int16", Prim::S, 2},
        {"uint32_t", Prim::U, 4},
        {"unsigned int", Prim::U, 4},
        {"unsigned long", Prim::U, 4},
        {"DWORD", Prim::U, 4},
        {"u_long", Prim::U, 4},
        {"unsigned __int32", Prim::U, 4},
        {"int32_t", Prim::S, 4},
        {"int", Prim::S, 4},
        {"long", Prim::S, 4},
        {"__int32", Prim::S, 4},
        {"float", Prim::F32, 4},
        {"uint64_t", Prim::U, 8},
        {"unsigned __int64", Prim::U, 8},
        {"int64_t", Prim::S, 8},
        {"__int64", Prim::S, 8},
        {"__time64_t", Prim::S, 8},
        {"double", Prim::F64, 8},
        {"long double", Prim::F64, 8},
    };

    for (const auto& e : kTable) {
        if (t == e.name) {
            return {e.kind, e.unit};
        }
    }
    return {Prim::None, 0};
}

namespace {

void append_hex(std::string& out, const uint8_t* p, int n) {
    static const char kHex[] = "0123456789ABCDEF";
    const int shown = std::min(n, 16);
    for (int i = 0; i < shown; ++i) {
        if (i) {
            out += ' ';
        }
        out += kHex[p[i] >> 4];
        out += kHex[p[i] & 0xF];
    }
    if (n > shown) {
        out += " ...";
    }
}

std::string raw_value(const uint8_t* p, int size, int avail) {
    char buf[64];
    if (size == 0) {
        return "<0 B>";
    }
    if (avail == 0) {
        return "<absent>";
    }
    std::string out;
    if (avail < size) {
        std::snprintf(buf, sizeof buf, "<truncated %d/%d: ", avail, size);
    } else {
        std::snprintf(buf, sizeof buf, "<%d B: ", size);
    }
    out = buf;
    append_hex(out, p, avail);
    out += '>';
    return out;
}

std::string element(Prim k, int unit, const uint8_t* p, bool hex) {
    char buf[64];
    switch (k) {
    case Prim::U: {
        uint64_t v = 0;
        std::memcpy(&v, p, (size_t)unit);
        if (hex && v > 9) {
            std::snprintf(buf, sizeof buf, "%llu (0x%llX)", (unsigned long long)v, (unsigned long long)v);
        } else {
            std::snprintf(buf, sizeof buf, "%llu", (unsigned long long)v);
        }
        break;
    }
    case Prim::S: {
        long long v = 0;
        if (unit == 1) {
            int8_t x;
            std::memcpy(&x, p, 1);
            v = x;
        } else if (unit == 2) {
            int16_t x;
            std::memcpy(&x, p, 2);
            v = x;
        } else if (unit == 4) {
            int32_t x;
            std::memcpy(&x, p, 4);
            v = x;
        } else {
            int64_t x;
            std::memcpy(&x, p, 8);
            v = x;
        }
        std::snprintf(buf, sizeof buf, "%lld", v);
        break;
    }
    case Prim::Bool:
        if (hex && p[0] > 1) {
            std::snprintf(buf, sizeof buf, "true (0x%02X)", (unsigned)p[0]);
        } else {
            std::snprintf(buf, sizeof buf, "%s", p[0] ? "true" : "false");
        }
        break;
    case Prim::F32: {
        float f;
        std::memcpy(&f, p, 4);
        std::snprintf(buf, sizeof buf, "%g", (double)f);
        break;
    }
    case Prim::F64: {
        double f;
        std::memcpy(&f, p, 8);
        std::snprintf(buf, sizeof buf, "%.10g", f);
        break;
    }
    default:
        buf[0] = '\0';
        break;
    }
    return buf;
}

std::string char_array(const uint8_t* p, int size, int avail) {
    if (avail == 0) {
        return "<absent>";
    }
    std::string out = "\"";
    char buf[32];
    for (int i = 0; i < avail && p[i]; ++i) {
        const uint8_t c = p[i];
        if (c == '"') {
            out += "\\\"";
        } else if (c == '\\') {
            out += "\\\\";
        } else if (c < 0x20 || c >= 0x7F) {
            std::snprintf(buf, sizeof buf, "\\x%02X", (unsigned)c);
            out += buf;
        } else {
            out += (char)c;
        }
    }
    out += '"';
    if (avail < size) {
        std::snprintf(buf, sizeof buf, " (truncated %d/%d)", avail, size);
        out += buf;
    }
    return out;
}

std::string field_value(const Field& f, const uint8_t* p, int size, int avail) {
    const PrimInfo pi = f.ref.empty() ? prim_of(f.type) : PrimInfo{Prim::None, 0};
    if (pi.kind == Prim::None || size != pi.unit * f.count) {
        return raw_value(p, size, avail);
    }
    if (f.type == "char" && f.count > 1) {
        return char_array(p, size, avail);
    }
    if (avail < size) {
        return raw_value(p, size, avail);
    }
    if (f.count == 1) {
        return element(pi.kind, pi.unit, p, true);
    }
    std::string out = "[";
    const int shown = std::min(f.count, 16);
    for (int i = 0; i < shown; ++i) {
        if (i) {
            out += ", ";
        }
        out += element(pi.kind, pi.unit, p + (size_t)i * (size_t)pi.unit, false);
    }
    if (f.count > shown) {
        char buf[32];
        std::snprintf(buf, sizeof buf, ", ... (+%d)", f.count - shown);
        out += buf;
    }
    out += ']';
    return out;
}

}

std::vector<FieldSpan> map_fields(const Struct& s, const uint8_t* p, size_t n) {
    const int have = (int)n;
    std::vector<FieldSpan> spans;
    auto add = [&](FieldSpan::Kind kind, const Field* f, int offset, int size) {
        FieldSpan sp;
        sp.kind = kind;
        sp.field = f;
        sp.offset = offset;
        sp.size = size;
        sp.avail = std::clamp(have - offset, 0, size);
        const uint8_t* at = p + (sp.avail ? offset : 0);
        sp.value = f ? field_value(*f, at, size, sp.avail) : raw_value(at, size, sp.avail);
        spans.push_back(std::move(sp));
    };
    int cursor = 0;
    for (size_t i = 0; i < s.fields.size(); ++i) {
        const Field& f = s.fields[i];
        int span = f.size;
        if (span < 0) {
            const int next = i + 1 < s.fields.size() ? s.fields[i + 1].offset : (s.size >= 0 ? s.size : have);
            span = std::max(next - f.offset, 0);
        }
        if (f.offset > cursor) {
            add(FieldSpan::Kind::Gap, nullptr, cursor, f.offset - cursor);
        }
        add(FieldSpan::Kind::Field, &f, f.offset, span);
        cursor = std::max(cursor, f.offset + span);
    }
    const int end = s.size >= 0 ? s.size : cursor;
    if (end > cursor) {
        add(FieldSpan::Kind::Gap, nullptr, cursor, end - cursor);
    }
    if (have > end) {
        add(FieldSpan::Kind::Extra, nullptr, end, have - end);
    }
    return spans;
}

std::vector<FieldSpan> map_element(const Struct& elem, const FieldSpan& sp, int i, const uint8_t* p, size_t n) {
    if (sp.kind != FieldSpan::Kind::Field || !sp.field || elem.size < 1 || i < 0 || i >= sp.field->count) {
        return {};
    }
    const int base = sp.offset + i * elem.size;
    const int have = std::clamp((int)n - base, 0, elem.size);
    std::vector<FieldSpan> out = map_fields(elem, have ? p + base : p, (size_t)have);
    for (FieldSpan& s : out) {
        s.offset += base;
    }
    return out;
}

void append_field_lines(std::string& out, const std::vector<FieldSpan>& spans) {
    char buf[32];
    for (const FieldSpan& sp : spans) {
        std::snprintf(buf, sizeof buf, "      +%04X ", (unsigned)sp.offset);
        out += buf;
        if (sp.kind == FieldSpan::Kind::Field) {
            out += sp.field->type;
            out += ' ';
            out += sp.field->name;
            if (sp.field->count > 1) {
                std::snprintf(buf, sizeof buf, "[%d]", sp.field->count);
                out += buf;
            }
        } else {
            out += sp.kind == FieldSpan::Kind::Gap ? "(unmapped)" : "(beyond sizeof)";
        }
        out += " = ";
        out += sp.value;
        out += '\n';
    }
}

std::string describe(const Decoded& d, uint16_t len) {
    auto num = [](int v) {
        return v < 0 ? std::string("?") : std::to_string(v);
    };
    const std::string l = std::to_string(len);
    switch (d.status) {
    case Status::Ok:
        return d.name + " ok";
    case Status::Var:
        return d.name + " var(" + l + "/" + num(d.layout ? d.layout->size : -1) + ")";
    case Status::Mismatch: {
        if (d.layout) {
            return d.name + " MISMATCH(" + l + "!=" + num(d.layout->size) + ")";
        }
        std::string out = "MISMATCH(" + l + " fits none of: ";
        for (size_t i = 0; i < d.candidates.size(); ++i) {
            if (i) {
                out += ", ";
            }
            out += d.candidates[i] + " " + num(i < d.candidate_sizes.size() ? d.candidate_sizes[i] : -1);
        }
        return out + ")";
    }
    case Status::Trigger:
        return d.name + " trigger";
    default: {
        if (d.candidates.empty()) {
            return d.name.empty() ? std::string("unknown") : d.name + " unknown(no layout)";
        }
        std::string out;
        for (size_t i = 0; i < d.candidates.size(); ++i) {
            if (i) {
                out += ", ";
            }
            out += d.candidates[i];
        }
        return out + " unknown(no layout)";
    }
    }
}

}
