#include "ui/packet_view.h"
#include "proto/packet_text.h"
#include <algorithm>

namespace rfte {

void build_view(PacketView& v, const Row& r, const PacketDb* db, int pick) {
    v = PacketView{};
    v.seq = r.rec.seq;
    if (db) {
        const Decoded d = db->classify(r.rec.dir, r.rec.main, r.rec.sub, r.rec.size);
        for (const std::string& c : d.candidates) {
            if (const Struct* s = db->get(c)) {
                if (std::find(v.layouts.begin(), v.layouts.end(), s) == v.layouts.end()) {
                    v.layouts.push_back(s);
                }
            }
        }
    }
    int def = -1;
    for (size_t i = 0; i < v.layouts.size(); ++i) {
        if (v.layouts[i] == r.layout) {
            def = (int)i;
            break;
        }
    }
    if (def < 0 && !v.layouts.empty()) {
        def = 0;
    }
    v.pick = pick >= 0 && pick < (int)v.layouts.size() ? pick : def;
    v.owner.assign(r.rec.bytes.size(), -1);
    if (v.pick < 0) {
        return;
    }
    const Struct* s = v.layouts[(size_t)v.pick];
    v.trial = s != r.layout;
    v.spans = map_fields(*s, r.rec.bytes.data(), r.rec.bytes.size());
    for (size_t k = 0; k < v.spans.size(); ++k) {
        const FieldSpan& sp = v.spans[k];
        const int end = std::min(sp.offset + sp.avail, (int)v.owner.size());
        for (int b = sp.offset; b < end; ++b) {
            if (v.owner[(size_t)b] < 0) {
                v.owner[(size_t)b] = (int)k;
            }
        }
    }
}

std::string copy_text(const PacketView& v, const Row& r, CopyKind k) {
    if (k == CopyKind::Hex) {
        return hex_line(r.rec.bytes.data(), r.rec.bytes.size());
    }
    const Struct* layout = v.pick >= 0 ? v.layouts[(size_t)v.pick] : nullptr;
    std::string label = r.label;
    if (v.trial && layout) {
        label += " [decoded as " + layout->name + "]";
    }
    return k == CopyKind::Decoded ? format_packet(r.rec, r.t_ms, label, layout) : format_snippet(r.rec, label, layout);
}

}
