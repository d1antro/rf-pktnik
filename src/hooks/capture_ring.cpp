#include "hooks/capture_ring.h"
#include <cstddef>
#include <cstring>
#include <new>

namespace rfte {

CaptureRing::CaptureRing(size_t slots) : slots_(new(std::nothrow) CaptureSlot[slots]) {
    cap_ = slots_ ? slots : 0;
}

CaptureSlot& CaptureRing::claim() {
    if (count_ == cap_) {
        if (!slots_[head_].before_image) {
            dropped_.fetch_add(1, std::memory_order_relaxed);
        }
        head_ = (head_ + 1) % cap_;
        --count_;
    }
    CaptureSlot& sl = slots_[(head_ + count_) % cap_];
    ++count_;
    return sl;
}

void CaptureRing::push(Dir dir, uint8_t m, uint8_t s, const uint8_t* p, uint16_t len, bool edited, uint64_t ts,
                       bool tool) {
    const uint16_t copy = !p ? uint16_t(0) : (len > uint16_t(kMaxCapture) ? uint16_t(kMaxCapture) : len);
    std::lock_guard<std::mutex> lk(mtx_);
    if (cap_ == 0) {
        dropped_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    CaptureSlot& sl = claim();
    sl.seq = next_seq_++;
    sl.ts_qpc = ts;
    sl.dir = dir;
    sl.main = m;
    sl.sub = s;
    sl.edited = edited;
    sl.tool = tool;
    sl.before_image = false;
    sl.size = len;
    sl.copied = copy;
    if (copy) {
        std::memcpy(sl.bytes, p, copy);
    }
}

void CaptureRing::push_edited(Dir dir, uint8_t m, uint8_t s, const uint8_t* before, const uint8_t* after, uint16_t len,
                              uint64_t ts) {
    const uint16_t copy = !after ? uint16_t(0) : (len > uint16_t(kMaxCapture) ? uint16_t(kMaxCapture) : len);
    std::lock_guard<std::mutex> lk(mtx_);
    if (cap_ == 0) {
        dropped_.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    const uint64_t seq = next_seq_++;
    for (int k = (cap_ >= 2 && before) ? 0 : 1; k < 2; ++k) {
        CaptureSlot& sl = claim();
        sl.seq = seq;
        sl.ts_qpc = ts;
        sl.dir = dir;
        sl.main = m;
        sl.sub = s;
        sl.edited = true;
        sl.tool = false;
        sl.before_image = k == 0;
        sl.size = len;
        sl.copied = copy;
        if (copy) {
            std::memcpy(sl.bytes, k == 0 ? before : after, copy);
        }
    }
}

bool CaptureRing::pop(PacketRec& out) {
    CaptureSlot tmp;
    CaptureSlot pre;
    bool have_pre = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (count_ == 0) {
            return false;
        }
        if (slots_[head_].before_image) {
            const CaptureSlot& b = slots_[head_];
            std::memcpy(&pre, &b, offsetof(CaptureSlot, bytes) + b.copied);
            have_pre = true;
            head_ = (head_ + 1) % cap_;
            --count_;
            if (count_ == 0) {
                return false;
            }
        }
        const CaptureSlot& sl = slots_[head_];
        std::memcpy(&tmp, &sl, offsetof(CaptureSlot, bytes) + sl.copied);
        head_ = (head_ + 1) % cap_;
        --count_;
    }
    out.seq = tmp.seq;
    out.ts_qpc = tmp.ts_qpc;
    out.dir = tmp.dir;
    out.main = tmp.main;
    out.sub = tmp.sub;
    out.size = tmp.size;
    out.edited = tmp.edited;
    out.tool = tmp.tool;
    out.bytes.assign(tmp.bytes, tmp.bytes + tmp.copied);
    if (have_pre && pre.seq == tmp.seq) {
        out.before.assign(pre.bytes, pre.bytes + pre.copied);
    } else {
        out.before.clear();
    }
    return true;
}

uint64_t CaptureRing::take_dropped() {
    return dropped_.exchange(0);
}

}
