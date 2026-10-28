#include "ui/filter.h"
#include "proto/packet_text.h"
#include <algorithm>

namespace rfte {
namespace {
std::string_view trim(std::string_view v) {
    while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) {
        v.remove_prefix(1);
    }
    while (!v.empty() && (v.back() == ' ' || v.back() == '\t')) {
        v.remove_suffix(1);
    }
    return v;
}

char lower(char c) {
    return c >= 'A' && c <= 'Z' ? (char)(c - 'A' + 'a') : c;
}
}

bool parse_opcode(std::string_view s, int& main, int& sub) {
    s = trim(s);
    if (!s.empty() && (s.front() == '(' || s.back() == ')')) {
        if (s.size() < 2 || s.front() != '(' || s.back() != ')') {
            return false;
        }
        s = trim(s.substr(1, s.size() - 2));
    }
    int v[2] = {-1, -1}, n = 0;
    while (!s.empty()) {
        if (n == 2) {
            return false;
        }
        int base = 10;
        if (s.size() > 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
            base = 16;
            s.remove_prefix(2);
        }
        int x = 0;
        size_t k = 0;
        for (; k < s.size(); ++k) {
            const char c = lower(s[k]);
            const int d = c >= '0' && c <= '9' ? c - '0' : base == 16 && c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
            if (d < 0) {
                break;
            }
            x = x * base + d;
            if (x > 255) {
                return false;
            }
        }
        if (k == 0) {
            return false;
        }
        v[n++] = x;
        s = trim(s.substr(k));
        if (!s.empty() && s.front() == ',') {
            s = trim(s.substr(1));
            if (s.empty()) {
                return false;
            }
        }
    }
    main = v[0];
    sub = v[1];
    return true;
}

bool icontains(std::string_view hay, std::string_view needle) {
    if (needle.empty()) {
        return true;
    }
    return std::search(hay.begin(), hay.end(), needle.begin(), needle.end(), [](char a, char b) {
               return lower(a) == lower(b);
           }) != hay.end();
}

std::string search_text(const Row& r) {
    return format_packet(r.rec, r.t_ms, r.label, r.layout);
}

void set_muted(Filter& f, uint32_t key, bool on) {
    const auto it = std::lower_bound(f.muted.begin(), f.muted.end(), key);
    const bool has = it != f.muted.end() && *it == key;
    if (on && !has) {
        f.muted.insert(it, key);
    } else if (!on && has) {
        f.muted.erase(it);
    }
}

bool is_muted(const Filter& f, uint32_t key) {
    return std::binary_search(f.muted.begin(), f.muted.end(), key);
}

bool matches(const Filter& f, const Row& r) {
    const PacketRec& p = r.rec;
    if (!f.dir[p.dir == Dir::C2S ? 0 : 1]) {
        return false;
    }
    const size_t st = (size_t)r.status;
    if (st >= f.status.size() || !f.status[st]) {
        return false;
    }
    if (f.edited_only && !p.edited) {
        return false;
    }
    if (f.main >= 0 && (p.main != f.main || (f.sub >= 0 && p.sub != f.sub))) {
        return false;
    }
    if ((int)p.size < f.size_min || (int)p.size > f.size_max) {
        return false;
    }
    if (!f.muted.empty() && is_muted(f, mute_key(p.dir, p.main, p.sub))) {
        return false;
    }
    if (!icontains(r.name, f.name)) {
        return false;
    }
    return f.text.empty() || icontains(search_text(r), f.text);
}

void FilterView::reset(const Filter& f) {
    f_ = f;
    seqs_.clear();
    next_ = 0;
}

size_t FilterView::update(const PacketModel& m, size_t budget) {
    if (m.size() == 0) {
        seqs_.clear();
        return 0;
    }
    const uint64_t first = m.at(0).rec.seq;
    while (!seqs_.empty() && seqs_.front() < first) {
        seqs_.pop_front();
    }
    size_t i = m.lower_bound(next_);
    for (size_t tested = 0; i < m.size() && (budget == 0 || tested < budget); ++i, ++tested) {
        const Row& r = m.at(i);
        if (matches(f_, r)) {
            seqs_.push_back(r.rec.seq);
        }
        next_ = r.rec.seq + 1;
    }
    return m.size() - i;
}

}
