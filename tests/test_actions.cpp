#include "hooks/action_queue.h"
#include "proto/packet_text.h"
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

using namespace rfte;

static int g_fail = 0;
#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_fail;                                                   \
        }                                                               \
    } while (0)

struct Ran {
    uint64_t id;
    Dir dir;
    uint8_t main, sub;
    std::vector<uint8_t> bytes;
};

static void test_queue() {
    ActionQueue q(4);
    CHECK(q.capacity() == 4);
    CHECK(q.pending(Dir::C2S) == 0 && q.pending(Dir::S2C) == 0);
    const uint8_t a[3] = {1, 2, 3}, b[1] = {9};
    CHECK(q.push(Dir::C2S, 4, 1, a, 3) == Queued::Ok);
    CHECK(q.push(Dir::S2C, 3, 4, b, 1) == Queued::Ok);
    CHECK(q.push(Dir::C2S, 4, 2, nullptr, 0) == Queued::Ok);
    CHECK(q.pending(Dir::C2S) == 2 && q.pending(Dir::S2C) == 1);
    std::vector<Ran> ran;
    auto rec = [&](ActionSlot& s) {
        ran.push_back({s.id, s.dir, s.main, s.sub, std::vector<uint8_t>(s.bytes, s.bytes + s.len)});
    };
    CHECK(q.drain(Dir::C2S, rec) == 2);
    CHECK(ran.size() == 2);
    if (ran.size() == 2) {
        CHECK(ran[0].id == 0 && ran[0].dir == Dir::C2S && ran[0].main == 4 && ran[0].sub == 1);
        CHECK((ran[0].bytes == std::vector<uint8_t>{1, 2, 3}));
        CHECK(ran[1].id == 2 && ran[1].sub == 2 && ran[1].bytes.empty());
    }
    CHECK(q.pending(Dir::C2S) == 0 && q.pending(Dir::S2C) == 1);
    CHECK(q.drain(Dir::C2S, rec) == 0);
    ran.clear();
    CHECK(q.drain(Dir::S2C, rec) == 1);
    CHECK(ran.size() == 1 && ran[0].id == 1 && ran[0].dir == Dir::S2C && ran[0].main == 3 && ran[0].sub == 4);
    CHECK(ran.size() == 1 && (ran[0].bytes == std::vector<uint8_t>{9}));
    for (int i = 0; i < 4; ++i) {
        CHECK(q.push(Dir::C2S, 1, (uint8_t)i, a, 1) == Queued::Ok);
    }
    CHECK(q.push(Dir::C2S, 1, 9, a, 1) == Queued::Full);
    CHECK(q.push(Dir::S2C, 1, 9, a, 1) == Queued::Ok);
    ran.clear();
    CHECK(q.drain(Dir::C2S, rec) == 4);
    for (size_t i = 0; i < ran.size(); ++i) {
        CHECK(ran[i].sub == (uint8_t)i);
    }
    std::vector<uint8_t> big((size_t)kMaxAction + 1, 0x5A);
    CHECK(q.push(Dir::C2S, 1, 1, big.data(), big.size()) == Queued::TooLong);
    CHECK(q.push(Dir::C2S, 1, 1, big.data(), (size_t)kMaxAction) == Queued::Ok);
    ran.clear();
    CHECK(q.drain(Dir::C2S, rec) == 1);
    CHECK(ran.size() == 1 && ran[0].bytes.size() == (size_t)kMaxAction && ran[0].bytes.back() == 0x5A);
    CHECK(q.push(Dir::C2S, 1, 1, a, 1) == Queued::Ok);
    CHECK(q.cancel() == 2);
    CHECK(q.pending(Dir::C2S) == 0 && q.pending(Dir::S2C) == 0);
    CHECK(q.drain(Dir::S2C, rec) == 0);
    CHECK(q.push(Dir::S2C, 7, 7, b, 1) == Queued::Ok);
    CHECK(q.pending(Dir::S2C) == 1);
    std::printf("queue: done\n");
}

static void test_drain() {
    {
        ActionQueue q(8);
        const uint8_t x = 7;
        q.push(Dir::S2C, 1, 1, &x, 1);
        q.push(Dir::S2C, 1, 2, &x, 1);
        q.push(Dir::C2S, 2, 2, &x, 1);
        size_t outer = 0, nested_same = 99, nested_other = 99;
        const size_t n = q.drain(Dir::S2C, [&](ActionSlot&) {
            if (outer++ == 0) {
                nested_same = q.drain(Dir::S2C, [](ActionSlot&) {
                });
                nested_other = q.drain(Dir::C2S, [](ActionSlot&) {
                });
            }
        });
        CHECK(n == 2 && outer == 2);
        CHECK(nested_same == 0);
        CHECK(nested_other == 1);
        CHECK(q.pending(Dir::S2C) == 0 && q.pending(Dir::C2S) == 0);
        q.push(Dir::C2S, 3, 1, &x, 1);
        bool once = true;
        const size_t m = q.drain(Dir::C2S, [&](ActionSlot&) {
            if (once) {
                once = false;
                CHECK(q.push(Dir::C2S, 3, 2, &x, 1) == Queued::Ok);
            }
        });
        CHECK(m == 2 && q.pending(Dir::C2S) == 0);
    }
    {
        ActionQueue q(16);
        constexpr uint32_t kN = 5000;
        std::thread prod([&] {
            for (uint32_t i = 0; i < kN;) {
                uint8_t v[4];
                std::memcpy(v, &i, 4);
                if (q.push(Dir::C2S, 1, 1, v, 4) == Queued::Ok) {
                    ++i;
                } else {
                    std::this_thread::yield();
                }
            }
        });
        uint32_t next = 0;
        bool order_ok = true;
        while (next < kN) {
            q.drain(Dir::C2S, [&](ActionSlot& s) {
                uint32_t v = 0;
                std::memcpy(&v, s.bytes, 4);
                if (s.len != 4 || v != next) {
                    order_ok = false;
                }
                ++next;
            });
            if (next < kN) {
                std::this_thread::yield();
            }
        }
        prod.join();
        CHECK(order_ok && next == kN && q.pending(Dir::C2S) == 0);
    }
    std::printf("drain: done\n");
}

static void test_hex() {
    std::vector<uint8_t> out;
    size_t bad = 0;
    const std::vector<uint8_t> mv = {0x01, 0x00, 0x00, 0xC0, 0x3F, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x80,
                                     0xC8, 0x42, 0xD2, 0x04, 0x00, 0x00, 0xFB, 0xFF, 0x07, 0x00, 0x03};
    CHECK(parse_hex(hex_line(mv.data(), mv.size()), out) && out == mv);
    CHECK(parse_hex("", out) && out.empty());
    CHECK(parse_hex(" \t\r\n, ", out) && out.empty());
    CHECK(parse_hex("0x01, 0x00,0XfF", out) && (out == std::vector<uint8_t>{0x01, 0x00, 0xFF}));
    CHECK(parse_hex("0100c0\n3F", out) && (out == std::vector<uint8_t>{0x01, 0x00, 0xC0, 0x3F}));
    CHECK(!parse_hex("01 0G", out, (size_t)kMaxAction, &bad) && bad == 3 && out.empty());
    CHECK(!parse_hex("01 123", out, (size_t)kMaxAction, &bad) && bad == 3);
    CHECK(!parse_hex("1", out, (size_t)kMaxAction, &bad) && bad == 0);
    CHECK(!parse_hex("0x", out, (size_t)kMaxAction, &bad) && bad == 0);
    CHECK(!parse_hex("0x1", out, (size_t)kMaxAction, &bad) && bad == 0);
    CHECK(!parse_hex("aa 0x0102", out, (size_t)kMaxAction, &bad) && bad == 3);
    CHECK(!parse_hex("01 02 03", out, 2, &bad) && bad == 6);
    CHECK(!parse_hex("0102 03", out, 2, &bad) && bad == 5);
    CHECK(!parse_hex("010203", out, 2, &bad) && bad == 0);
    CHECK(parse_hex("01 02", out, 2) && out.size() == 2);
    std::vector<uint8_t> full((size_t)kMaxAction, 0xAB);
    CHECK(parse_hex(hex_line(full.data(), full.size()), out) && out.size() == (size_t)kMaxAction);
    std::printf("hex: done\n");
}

int main() {
    test_queue();
    test_drain();
    test_hex();
    if (g_fail) {
        std::printf("FAILED (%d failure(s))\n", g_fail);
    } else {
        std::printf("PASSED (0 failure(s))\n");
    }
    return g_fail ? 1 : 0;
}
