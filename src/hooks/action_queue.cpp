#include "hooks/action_queue.h"
#include <cstddef>
#include <cstring>
#include <new>

namespace rfte {

ActionQueue::ActionQueue(size_t slots_per_dir) : slots_(new(std::nothrow) ActionSlot[2 * slots_per_dir + 2]) {
    cap_ = slots_ && slots_per_dir ? slots_per_dir : 0;
}

Queued ActionQueue::push(Dir dir, uint8_t m, uint8_t s, const uint8_t* p, size_t len) {
    if (len > (size_t)kMaxAction) {
        return Queued::TooLong;
    }
    if (cap_ == 0) {
        return Queued::Unavailable;
    }
    if (!p) {
        len = 0;
    }
    const size_t d = (size_t)dir;
    std::lock_guard<std::mutex> lk(mtx_);
    const size_t c = count_[d].load(std::memory_order_relaxed);
    if (c == cap_) {
        return Queued::Full;
    }
    ActionSlot& sl = slots_[d * cap_ + (head_[d] + c) % cap_];
    sl.id = next_id_++;
    sl.dir = dir;
    sl.main = m;
    sl.sub = s;
    sl.len = (uint16_t)len;
    if (len) {
        std::memcpy(sl.bytes, p, len);
    }
    count_[d].store(c + 1, std::memory_order_release);
    return Queued::Ok;
}

bool ActionQueue::take(Dir dir, ActionSlot& out) {
    const size_t d = (size_t)dir;
    std::lock_guard<std::mutex> lk(mtx_);
    const size_t c = count_[d].load(std::memory_order_relaxed);
    if (c == 0) {
        return false;
    }
    const ActionSlot& sl = slots_[d * cap_ + head_[d]];
    std::memcpy(&out, &sl, offsetof(ActionSlot, bytes) + sl.len);
    head_[d] = (head_[d] + 1) % cap_;
    count_[d].store(c - 1, std::memory_order_relaxed);
    return true;
}

size_t ActionQueue::cancel() {
    std::lock_guard<std::mutex> lk(mtx_);
    size_t n = 0;
    for (size_t d = 0; d < 2; ++d) {
        n += count_[d].load(std::memory_order_relaxed);
        count_[d].store(0, std::memory_order_relaxed);
        head_[d] = 0;
    }
    return n;
}

}
