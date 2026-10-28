#include "ui/packet_model.h"
#include "proto/decode.h"
#include "proto/packet_text.h"
#include <algorithm>
#include <utility>

namespace rfte {

void RateMeter::prune(double now_ms) {
    while (!s_.empty() && s_.front().t <= now_ms - window_ms_) {
        s_.pop_front();
    }
}

void RateMeter::add(double t_ms, Dir d, uint32_t size) {
    s_.push_back(Sample{t_ms, d, size});
    prune(t_ms);
}

Rates RateMeter::rates(double now_ms) {
    prune(now_ms);
    Rates r;
    for (const Sample& s : s_) {
        const size_t i = s.dir == Dir::C2S ? 0 : 1;
        r.pkts[i] += 1.0;
        r.bytes[i] += (double)s.size;
    }
    const double secs = window_ms_ / 1000.0;
    for (size_t i = 0; i < 2; ++i) {
        r.pkts[i] /= secs;
        r.bytes[i] /= secs;
    }
    return r;
}

PacketModel::PacketModel(const PacketDb* db, int64_t qpc_base, double qpc_per_ms, size_t max_rows, size_t max_bytes)
    : db_(db), qpc_base_(qpc_base), qpc_per_ms_(qpc_per_ms), max_rows_(max_rows), max_bytes_(max_bytes) {
}

void PacketModel::push(PacketRec&& r, std::string* log) {
    Row row;
    row.t_ms = (double)((int64_t)r.ts_qpc - qpc_base_) / qpc_per_ms_;
    rate_.add(row.t_ms, r.dir, r.size);
    if (db_) {
        const Decoded d = db_->classify(r.dir, r.main, r.sub, r.size);
        row.status = d.status;
        row.layout = d.layout;
        row.label = describe(d, r.size);
        if (!d.name.empty()) {
            row.name = d.name;
        } else {
            for (size_t i = 0; i < d.candidates.size(); ++i) {
                if (i) {
                    row.name += " | ";
                }
                row.name += d.candidates[i];
            }
        }
    }
    if (log) {
        *log += format_packet(r, row.t_ms, row.label, row.layout);
    }
    row.rec = std::move(r);
    account(row, +1);
    rows_.push_back(std::move(row));
    ++ingested_;
    while (rows_.size() > max_rows_ || (bytes_ > max_bytes_ && rows_.size() > 1)) {
        account(rows_.front(), -1);
        rows_.pop_front();
        ++evicted_;
    }
}

void PacketModel::account(const Row& r, int sign) {
    const size_t n = r.rec.bytes.size();
    const size_t d = (size_t)r.rec.dir, s = (size_t)r.status;
    if (sign > 0) {
        bytes_ += n;
        if (d < 2) {
            ++by_dir_[d];
        }
        if (s < kStatusCount) {
            ++by_status_[s];
        }
    } else {
        bytes_ -= n;
        if (d < 2) {
            --by_dir_[d];
        }
        if (s < kStatusCount) {
            --by_status_[s];
        }
    }
}

void PacketModel::clear() {
    rows_.clear();
    bytes_ = 0;
    by_dir_[0] = by_dir_[1] = 0;
    for (size_t& c : by_status_) {
        c = 0;
    }
}

size_t PacketModel::lower_bound(uint64_t seq) const {
    return (size_t)(std::lower_bound(rows_.begin(), rows_.end(), seq,
                                     [](const Row& r, uint64_t s) {
                                         return r.rec.seq < s;
                                     }) -
                    rows_.begin());
}

const Row* PacketModel::find(uint64_t seq) const {
    const size_t i = lower_bound(seq);
    return i < rows_.size() && rows_[i].rec.seq == seq ? &rows_[i] : nullptr;
}

size_t PacketModel::count(Dir d) const {
    const size_t i = (size_t)d;
    return i < 2 ? by_dir_[i] : 0;
}

size_t PacketModel::count(Status s) const {
    const size_t i = (size_t)s;
    return i < kStatusCount ? by_status_[i] : 0;
}

}
