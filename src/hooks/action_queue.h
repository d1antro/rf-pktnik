#pragma once
#include "hooks/hooks.h"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>

namespace rfte {

struct ActionSlot {
    uint64_t id;
    Dir dir;
    uint8_t main, sub;
    uint16_t len;
    uint8_t bytes[kMaxAction];
};

class ActionQueue {
public:
    explicit ActionQueue(size_t slots_per_dir);
    Queued push(Dir dir, uint8_t main, uint8_t sub, const uint8_t* p, size_t len);
    template <class F> size_t drain(Dir dir, F&& exec);

    size_t pending(Dir dir) const {
        return count_[(size_t)dir].load(std::memory_order_relaxed);
    }

    size_t cancel();

    size_t capacity() const {
        return cap_;
    }

private:
    bool take(Dir dir, ActionSlot& out);
    std::unique_ptr<ActionSlot[]> slots_;
    size_t cap_ = 0;
    size_t head_[2] = {0, 0};
    std::atomic<size_t> count_[2]{};
    uint64_t next_id_ = 0;
    std::atomic<bool> busy_[2]{};
    std::mutex mtx_;
};

template <class F> size_t ActionQueue::drain(Dir dir, F&& exec) {
    const size_t d = (size_t)dir;
    if (cap_ == 0 || count_[d].load(std::memory_order_acquire) == 0) {
        return 0;
    }
    if (busy_[d].exchange(true, std::memory_order_acquire)) {
        return 0;
    }
    ActionSlot& scratch = slots_[2 * cap_ + d];
    size_t n = 0;
    while (take(dir, scratch)) {
        exec(scratch);
        ++n;
    }
    busy_[d].store(false, std::memory_order_release);
    return n;
}

}
