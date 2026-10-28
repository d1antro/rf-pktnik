#include "hooks/capture_ring.h"
#include "proto/packet_text.h"
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
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

static void test_ring() {
    {
        CaptureRing ring(4);
        CHECK(ring.capacity() == 4);
        for (int i = 0; i < 3; ++i) {
            uint8_t buf[16];
            for (int j = 0; j < 16; ++j) {
                buf[j] = (uint8_t)(i * 16 + j);
            }
            ring.push(i % 2 ? Dir::S2C : Dir::C2S, (uint8_t)(i + 1), (uint8_t)(i + 10), buf, (uint16_t)(5 + i), i == 1,
                      1000u + i, i == 2);
        }
        for (int i = 0; i < 3; ++i) {
            PacketRec r;
            CHECK(ring.pop(r));
            CHECK(r.seq == (uint64_t)i);
            CHECK(r.ts_qpc == 1000u + (uint64_t)i);
            CHECK(r.dir == (i % 2 ? Dir::S2C : Dir::C2S));
            CHECK(r.main == i + 1 && r.sub == i + 10);
            CHECK(r.size == 5 + i);
            CHECK(r.edited == (i == 1));
            CHECK(r.tool == (i == 2));
            CHECK(r.bytes.size() == (size_t)(5 + i));
            for (size_t j = 0; j < r.bytes.size(); ++j) {
                CHECK(r.bytes[j] == (uint8_t)(i * 16 + j));
            }
        }
        PacketRec r;
        CHECK(!ring.pop(r));
        CHECK(ring.take_dropped() == 0);
    }
    {
        CaptureRing ring(4);
        const uint8_t b = 0x42;
        for (int i = 0; i < 6; ++i) {
            ring.push(Dir::C2S, 1, 1, &b, 1, false, (uint64_t)i);
        }
        CHECK(ring.take_dropped() == 2);
        CHECK(ring.take_dropped() == 0);
        for (uint64_t want = 2; want <= 5; ++want) {
            PacketRec r;
            CHECK(ring.pop(r));
            CHECK(r.seq == want);
        }
        PacketRec r;
        CHECK(!ring.pop(r));
    }
    {
        CaptureRing ring(4);
        std::vector<uint8_t> big(5000);
        for (size_t i = 0; i < big.size(); ++i) {
            big[i] = (uint8_t)(i * 7);
        }
        ring.push(Dir::S2C, 1, 8, big.data(), 5000, false, 0);
        ring.push(Dir::S2C, 1, 9, nullptr, 9, false, 0);
        ring.push(Dir::C2S, 2, 0, big.data(), 0, false, 0);
        PacketRec r;
        CHECK(ring.pop(r));
        CHECK(r.size == 5000);
        CHECK(r.bytes.size() == (size_t)kMaxCapture);
        CHECK(std::equal(r.bytes.begin(), r.bytes.end(), big.begin()));
        CHECK(ring.pop(r));
        CHECK(r.size == 9 && r.bytes.empty());
        CHECK(ring.pop(r));
        CHECK(r.size == 0 && r.bytes.empty());
    }
    {
        CaptureRing ring(4);
        const uint8_t x = 0x42, b0[3] = {1, 2, 3}, a0[3] = {1, 9, 3};
        ring.push(Dir::C2S, 1, 1, &x, 1, false, 10);
        ring.push_edited(Dir::S2C, 2, 10, b0, a0, 3, 11);
        ring.push(Dir::C2S, 1, 2, &x, 1, false, 12);
        PacketRec r;
        CHECK(ring.pop(r) && r.seq == 0 && !r.edited && r.before.empty());
        CHECK(ring.pop(r) && r.seq == 1 && r.edited && !r.tool && r.dir == Dir::S2C && r.main == 2 && r.sub == 10);
        CHECK(r.size == 3 && r.ts_qpc == 11);
        CHECK((r.bytes == std::vector<uint8_t>{1, 9, 3}) && (r.before == std::vector<uint8_t>{1, 2, 3}));
        CHECK(ring.pop(r) && r.seq == 2 && !r.edited && r.before.empty());
        CHECK(!ring.pop(r));
        CHECK(ring.take_dropped() == 0);
    }
    {
        CaptureRing ring(4);
        const uint8_t x = 0x42, b0[2] = {1, 2}, a0[2] = {7, 2};
        ring.push_edited(Dir::C2S, 4, 1, b0, a0, 2, 0);
        ring.push(Dir::C2S, 1, 1, &x, 1, false, 1);
        ring.push(Dir::C2S, 1, 2, &x, 1, false, 2);
        ring.push(Dir::C2S, 1, 3, &x, 1, false, 3);
        CHECK(ring.take_dropped() == 0);
        PacketRec r;
        CHECK(ring.pop(r) && r.seq == 0 && r.edited && (r.bytes == std::vector<uint8_t>{7, 2}) && r.before.empty());
        for (uint64_t want = 1; want <= 3; ++want) {
            CHECK(ring.pop(r) && r.seq == want);
        }
        CHECK(!ring.pop(r));
    }
    {
        CaptureRing ring(4);
        const uint8_t x = 0x42;
        for (int i = 0; i < 4; ++i) {
            ring.push(Dir::C2S, 1, (uint8_t)i, &x, 1, false, (uint64_t)i);
        }
        std::vector<uint8_t> b(5000, 0x11), a(5000, 0x22);
        ring.push_edited(Dir::S2C, 3, 4, b.data(), a.data(), 5000, 4);
        CHECK(ring.take_dropped() == 2);
        PacketRec r;
        CHECK(ring.pop(r) && r.seq == 2);
        CHECK(ring.pop(r) && r.seq == 3);
        CHECK(ring.pop(r) && r.seq == 4 && r.size == 5000 && r.bytes.size() == (size_t)kMaxCapture &&
              r.before.size() == (size_t)kMaxCapture && r.bytes[0] == 0x22 && r.before[0] == 0x11);
        CHECK(!ring.pop(r));
    }
    std::printf("ring: done\n");
}

static void test_format() {
    {
        PacketRec r{};
        r.seq = 7;
        r.dir = Dir::C2S;
        r.main = 4;
        r.sub = 1;
        r.size = 22;
        r.edited = false;
        for (int i = 0; i < 22; ++i) {
            r.bytes.push_back((uint8_t)i);
        }
        const std::string got = format_packet(r, 1.5);
        const std::string want = "#7 t+1.500ms C2S (4,1) size=22\n"
                                 "    0000  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F\n"
                                 "    0010  10 11 12 13 14 15\n";
        CHECK(got == want);
        if (got != want) {
            std::printf("got:\n%s", got.c_str());
        }
    }
    {
        PacketRec r{};
        r.seq = 0;
        r.dir = Dir::S2C;
        r.main = 4;
        r.sub = 4;
        r.size = 0;
        r.edited = true;
        CHECK(format_packet(r, 0.0) == "#0 t+0.000ms S2C (4,4) size=0 edited\n");
    }
    {
        PacketRec r{};
        r.seq = 3;
        r.dir = Dir::S2C;
        r.main = 1;
        r.sub = 8;
        r.size = 5000;
        r.edited = false;
        r.bytes.assign(kMaxCapture, 0xAB);
        const std::string got = format_packet(r, 2.0);
        const std::string head = "#3 t+2.000ms S2C (1,8) size=5000 captured=4096\n";
        CHECK(got.compare(0, head.size(), head) == 0);
        CHECK(got.find("\n    0FF0  AB AB") != std::string::npos);
        CHECK(std::count(got.begin(), got.end(), '\n') == 257);
    }
    {
        PacketRec r{};
        r.seq = 1;
        r.dir = Dir::C2S;
        r.main = 4;
        r.sub = 1;
        r.size = 2;
        r.tool = true;
        r.bytes = {0xAA, 0xBB};
        CHECK(format_packet(r, 0.0) == "#1 t+0.000ms C2S (4,1) size=2 tool\n    0000  AA BB\n");
        CHECK(format_packet(r, 0.0, "_x ok") == "#1 t+0.000ms C2S (4,1) size=2 _x ok tool\n    0000  AA BB\n");
        r.edited = true;
        CHECK(format_packet(r, 0.0).rfind("#1 t+0.000ms C2S (4,1) size=2 edited tool\n", 0) == 0);
        CHECK(format_snippet(r).rfind("// #1 C2S (4,1) size=2 edited tool\n", 0) == 0);
    }
    {
        PacketRec r{};
        r.seq = 5;
        r.dir = Dir::C2S;
        r.main = 2;
        r.sub = 2;
        r.size = 8;
        r.edited = true;
        r.before = {0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x00, 0x11};
        r.bytes = {0x05, 0x48, 0x45, 0x4C, 0x4C, 0x4F, 0x00, 0x22};
        const std::string want = "#5 t+0.000ms C2S (2,2) size=8 edited\n"
                                 "    edited +0001 5: 68 65 6C 6C 6F -> 48 45 4C 4C 4F\n"
                                 "    edited +0007 1: 11 -> 22\n"
                                 "    0000  05 48 45 4C 4C 4F 00 22\n";
        const std::string got = format_packet(r, 0.0);
        CHECK(got == want);
        if (got != want) {
            std::printf("got:\n%s", got.c_str());
        }
        const std::vector<EditRun> runs = edit_runs(r.before, r.bytes);
        CHECK(runs.size() == 2 && runs[0].off == 1 && runs[0].len == 5 && runs[1].off == 7 && runs[1].len == 1);
        CHECK(edit_run_text(r, runs[1]) == "+0007 1: 11 -> 22");
        r.before = r.bytes;
        CHECK(format_packet(r, 0.0).find("\n    edited: no captured byte differs") != std::string::npos);
        r.before.clear();
        CHECK(format_packet(r, 0.0) == "#5 t+0.000ms C2S (2,2) size=8 edited\n"
                                       "    edited: no before-image (lost to capture-ring overflow)\n"
                                       "    0000  05 48 45 4C 4C 4F 00 22\n");
        r.size = 80;
        r.before.assign(80, 0);
        r.bytes.assign(80, 0);
        for (size_t i = 0; i < 80; i += 2) {
            r.bytes[i] = 1;
        }
        const std::string many = format_packet(r, 0.0);
        CHECK(many.find("    edited +003E 1: 00 -> 01\n") != std::string::npos);
        CHECK(many.find("    edited +0040") == std::string::npos);
        CHECK(many.find("    edited: ... 8 more run(s)\n") != std::string::npos);
    }
    CHECK(std::strcmp(dir_name(Dir::C2S), "C2S") == 0);
    CHECK(std::strcmp(dir_name(Dir::S2C), "S2C") == 0);
    std::printf("format: done\n");
}

int main() {
    test_ring();
    test_format();
    if (g_fail) {
        std::printf("FAILED (%d failure(s))\n", g_fail);
    } else {
        std::printf("PASSED (0 failure(s))\n");
    }
    return g_fail ? 1 : 0;
}
