#pragma once
#include "hooks/hooks.h"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>

namespace rfte {

struct CaptureSlot {
    uint64_t seq;
    uint64_t ts_qpc;
    Dir dir;
    uint8_t main, sub;
    bool edited;
    bool tool;
    bool before_image;
    uint16_t size;
    uint16_t copied;
    uint8_t bytes[kMaxCapture];
};

class CaptureRing {
public:
    explicit CaptureRing(size_t slots);
    void push(Dir dir, uint8_t main, uint8_t sub, const uint8_t* p, uint16_t len, bool edited, uint64_t ts_qpc,
              bool tool = false);
    void push_edited(Dir dir, uint8_t main, uint8_t sub, const uint8_t* before, const uint8_t* after, uint16_t len,
                     uint64_t ts_qpc);
    bool pop(PacketRec& out);
    uint64_t take_dropped();

    size_t capacity() const {
        return cap_;
    }

private:
    CaptureSlot& claim();
    std::unique_ptr<CaptureSlot[]> slots_;
    size_t cap_ = 0;
    size_t head_ = 0, count_ = 0;
    uint64_t next_seq_ = 0;
    std::atomic<uint64_t> dropped_{0};
    std::mutex mtx_;
};

}
