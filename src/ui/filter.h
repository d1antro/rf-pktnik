#pragma once
#include "ui/packet_model.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>
#include <string_view>
#include <vector>

namespace rfte {

constexpr uint32_t mute_key(Dir d, uint8_t main, uint8_t sub) {
    return (uint32_t)d << 16 | (uint32_t)main << 8 | (uint32_t)sub;
}

struct Filter {
    std::array<bool, 2> dir{true, true};
    std::array<bool, kStatusCount> status{true, true, true, true, true};
    bool edited_only = false;
    int main = -1, sub = -1;
    int size_min = 0, size_max = 0xFFFF;
    std::string name;
    std::string text;
    std::vector<uint32_t> muted;
    bool operator==(const Filter&) const = default;
};

bool parse_opcode(std::string_view s, int& main, int& sub);

bool icontains(std::string_view hay, std::string_view needle);
std::string search_text(const Row& r);
void set_muted(Filter& f, uint32_t key, bool on);
bool is_muted(const Filter& f, uint32_t key);

bool matches(const Filter& f, const Row& r);

class FilterView {
public:
    void reset(const Filter& f);

    const Filter& filter() const {
        return f_;
    }

    size_t update(const PacketModel& m, size_t budget = 0);

    size_t size() const {
        return seqs_.size();
    }

    uint64_t seq(size_t i) const {
        return seqs_[i];
    }

private:
    Filter f_;
    std::deque<uint64_t> seqs_;
    uint64_t next_ = 0;
};

}
