#pragma once
#include "hooks/hooks.h"
#include "proto/packet_db.h"
#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>

namespace rfte {

struct Row {
    PacketRec rec;
    double t_ms = 0;
    Status status = Status::Unknown;
    const Struct* layout = nullptr;
    std::string name;
    std::string label;
};

struct Rates {
    double pkts[2] = {0, 0};
    double bytes[2] = {0, 0};
};

class RateMeter {
public:
    static constexpr double kWindowMs = 2000.0;

    explicit RateMeter(double window_ms = kWindowMs) : window_ms_(window_ms) {
    }

    void add(double t_ms, Dir d, uint32_t size);
    Rates rates(double now_ms);

private:
    struct Sample {
        double t;
        Dir dir;
        uint32_t size;
    };

    void prune(double now_ms);
    double window_ms_;
    std::deque<Sample> s_;
};

class PacketModel {
public:
    static constexpr size_t kMaxRows = 50000;
    static constexpr size_t kMaxBytes = size_t(32) << 20;
    PacketModel(const PacketDb* db, int64_t qpc_base, double qpc_per_ms, size_t max_rows = kMaxRows,
                size_t max_bytes = kMaxBytes);
    void push(PacketRec&& r, std::string* log = nullptr);

    void add_dropped(uint64_t n) {
        ring_dropped_ += n;
    }

    void clear();

    size_t size() const {
        return rows_.size();
    }

    const Row& at(size_t i) const {
        return rows_[i];
    }

    const Row* find(uint64_t seq) const;
    size_t lower_bound(uint64_t seq) const;

    Rates rates(double now_ms) {
        return rate_.rates(now_ms);
    }

    size_t count(Dir d) const;
    size_t count(Status s) const;

    size_t payload_bytes() const {
        return bytes_;
    }

    uint64_t ingested() const {
        return ingested_;
    }

    uint64_t evicted() const {
        return evicted_;
    }

    uint64_t ring_dropped() const {
        return ring_dropped_;
    }

private:
    void account(const Row& r, int sign);
    const PacketDb* db_;
    int64_t qpc_base_;
    double qpc_per_ms_;
    size_t max_rows_, max_bytes_;
    std::deque<Row> rows_;
    size_t bytes_ = 0;
    size_t by_dir_[2] = {0, 0};
    size_t by_status_[kStatusCount] = {};
    uint64_t ingested_ = 0, evicted_ = 0, ring_dropped_ = 0;
    RateMeter rate_;
};

}
