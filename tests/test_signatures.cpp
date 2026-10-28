#include "build/build_profile.h"
#include "build/signature.h"
#include <windows.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <cwchar>
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

static bool load_file(const char* path, std::vector<uint8_t>& out) {
    FILE* f = std::fopen(path, "rb");
    if (!f) {
        return false;
    }
    std::fseek(f, 0, SEEK_END);
    const long n = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    out.resize(n > 0 ? (size_t)n : 0);
    const size_t got = out.empty() ? 0 : std::fread(out.data(), 1, out.size(), f);
    std::fclose(f);
    return got == out.size();
}

struct Image {
    std::vector<uint8_t> file;
    uint32_t image_base = 0;
    std::vector<CodeRange> code;
};

static bool parse_image(const char* path, Image& img) {
    if (!load_file(path, img.file)) {
        return false;
    }
    const uint8_t* b = img.file.data();
    CHECK(img.file.size() > sizeof(IMAGE_DOS_HEADER));
    auto* dos = (const IMAGE_DOS_HEADER*)b;
    CHECK(dos->e_magic == IMAGE_DOS_SIGNATURE);
    auto* nt = (const IMAGE_NT_HEADERS32*)(b + dos->e_lfanew);
    CHECK(nt->Signature == IMAGE_NT_SIGNATURE);
    CHECK(nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386);
    img.image_base = nt->OptionalHeader.ImageBase;
    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            continue;
        }
        size_t len = std::min<size_t>(sec->SizeOfRawData, sec->Misc.VirtualSize);
        if (sec->PointerToRawData >= img.file.size()) {
            continue;
        }
        len = std::min<size_t>(len, img.file.size() - sec->PointerToRawData);
        img.code.push_back(CodeRange{b + sec->PointerToRawData, len, img.image_base + sec->VirtualAddress});
    }
    return true;
}

static const uint8_t* at_va(const Image& img, uintptr_t va, size_t n) {
    for (const CodeRange& r : img.code) {
        if (va >= r.va && va + n <= r.va + r.len) {
            return r.data + (va - r.va);
        }
    }
    return nullptr;
}

static const BuildProfile* find_row(Build b) {
    size_t n = 0;
    const BuildProfile* t = profile_table(n);
    for (size_t i = 0; i < n; ++i) {
        if (t[i].build == b) {
            return &t[i];
        }
    }
    return nullptr;
}

static void test_units() {
    Pattern p;
    CHECK(parse_pattern("55 8B ?? ec", p));
    CHECK((p.bytes == std::vector<uint8_t>{0x55, 0x8B, 0x00, 0xEC}));
    CHECK((p.mask == std::vector<uint8_t>{1, 1, 0, 1}));
    CHECK(parse_pattern("?", p) && p.bytes.size() == 1 && p.mask[0] == 0);
    CHECK(!parse_pattern("", p));
    CHECK(!parse_pattern("5", p));
    CHECK(!parse_pattern("GG", p));
    CHECK(!parse_pattern("123", p));

    CHECK(parse_pattern("55 ?? EC", p));
    const uint8_t a[] = {0x55, 0x12, 0xEC}, c[] = {0x55, 0x12, 0xED};
    CHECK(match_at(a, p));
    CHECK(!match_at(c, p));

    std::vector<uint8_t> buf(64, 0x90);
    buf[5] = 0x55;
    buf[6] = 0x34;
    buf[7] = 0xEC;
    buf[40] = 0x55;
    buf[41] = 0x99;
    buf[42] = 0xEC;
    const CodeRange r{buf.data(), buf.size(), 0x401000};
    const std::vector<uintptr_t> hits = scan(&r, 1, p);
    CHECK((hits == std::vector<uintptr_t>{0x401005, 0x401028}));
    CHECK(scan(&r, 1, p, 1).size() == 1);
    std::printf("units: done\n");
}

struct Target {
    const char* what;
    uint32_t va;
    const char* sig;
};

constexpr const char* kPresentShape = "A1 ?? ?? ?? ?? 8B 15 ?? ?? ?? ?? A3 ?? ?? ?? ?? A1 ?? ?? ?? ?? A8 08 89 15 ?? "
                                      "?? ?? ?? C7 05 ?? ?? ?? ?? 00 00 00 00 74 08";

static void test_positive(const char* label, const Image& img, const BuildProfile& row) {
    CHECK(img.image_base == row.image_base);
    const Target ts[] = {{"SendNetMessage", row.send_net_message, row.send_sig},
                         {"AnalysisZoneServerPacket", row.analysis_zone_packet, row.analysis_sig}};
    for (const Target& t : ts) {
        Pattern p;
        CHECK(t.sig && parse_pattern(t.sig, p));
        const uint8_t* at = at_va(img, t.va, p.bytes.size());
        const bool m = at && match_at(at, p);
        CHECK(m);
        const std::vector<uintptr_t> hits = scan(img.code.data(), img.code.size(), p);
        CHECK((hits == std::vector<uintptr_t>{t.va}));
        std::printf("%s %s: %s @0x%06x, scan hits %u\n", label, t.what, m ? "match" : "NO MATCH", (unsigned)t.va,
                    (unsigned)hits.size());
    }
    Pattern p;
    CHECK(parse_pattern(kPresentShape, p));
    if (row.main_cycle_tick == 0) {
        const std::vector<uintptr_t> hits = scan(img.code.data(), img.code.size(), p);
        CHECK(hits.empty());
        std::printf("%s per-frame present (reference): not pinned, shape scan hits %u\n", label, (unsigned)hits.size());
        return;
    }
    const uint8_t* at = at_va(img, row.main_cycle_tick, p.bytes.size());
    const bool m = at && match_at(at, p);
    CHECK(m);
    const std::vector<uintptr_t> hits = scan(img.code.data(), img.code.size(), p);
    CHECK((hits == std::vector<uintptr_t>{row.main_cycle_tick}));
    std::printf("%s per-frame present (reference): %s @0x%06x, scan hits %u\n", label, m ? "match" : "NO MATCH",
                (unsigned)row.main_cycle_tick, (unsigned)hits.size());
}

static void test_send_arity(const char* label, const Image& img, const BuildProfile& row, uint32_t ret_va) {
    Pattern p;
    CHECK(parse_pattern("8B E5 5D C2 ?? 00", p));
    const uint8_t* at = at_va(img, ret_va - 3, p.bytes.size());
    const bool m = at && match_at(at, p);
    CHECK(m);
    const unsigned pops = m ? at[4] : 0;
    CHECK(pops == 4u * row.send_stack_args);
    std::printf("%s SendNetMessage retn %02Xh @0x%06x: %u stack args (profile: %u)\n", label, pops, (unsigned)ret_va,
                pops / 4, (unsigned)row.send_stack_args);
}

static void test_spliced_entry(const char* label, const Image& img, uint32_t va, uint32_t expect_to) {
    const uint8_t* at = at_va(img, va, 5);
    CHECK(at && at[0] == 0xE9);
    int32_t rel = 0;
    if (at) {
        std::memcpy(&rel, at + 1, sizeof rel);
    }
    const uint32_t to = va + 5 + (uint32_t)rel;
    CHECK(to == expect_to);
    std::printf("%s AnalysisZoneServerPacket entry: E9 -> 0x%06x (the client's own detour; the signature "
                "masks these 5 bytes)\n",
                label, (unsigned)to);
}

static uint32_t resolve_offline(const Image& img, uint32_t va, const char* sig) {
    Pattern p;
    if (!va || !sig || !parse_pattern(sig, p)) {
        return 0;
    }
    const uint8_t* at = at_va(img, va, p.bytes.size());
    if (at && match_at(at, p)) {
        return va;
    }
    const std::vector<uintptr_t> hits = scan(img.code.data(), img.code.size(), p, 2);
    return hits.size() == 1 ? (uint32_t)hits[0] : 0;
}

static void test_negative(const char* label, const Image& img, const BuildProfile& row, unsigned analysis_hits = 0) {
    const Target ts[] = {{"SendNetMessage", row.send_net_message, row.send_sig},
                         {"AnalysisZoneServerPacket", row.analysis_zone_packet, row.analysis_sig}};
    uintptr_t shared = 0;
    for (size_t i = 0; i < 2; ++i) {
        const Target& t = ts[i];
        Pattern p;
        CHECK(t.sig && parse_pattern(t.sig, p));
        const uint8_t* at = at_va(img, t.va, p.bytes.size());
        const bool m = at && match_at(at, p);
        CHECK(!m);
        const std::vector<uintptr_t> hits = scan(img.code.data(), img.code.size(), p);
        CHECK(hits.size() == (i == 0 ? 0u : analysis_hits));
        if (i == 1 && !hits.empty()) {
            shared = hits[0];
        }
        std::printf("%s (negative) %s %s: %s @0x%06x, scan hits %u\n", label, row.name, t.what,
                    m ? "MATCH (bad)" : "no match", (unsigned)t.va, (unsigned)hits.size());
    }
    if (analysis_hits) {
        CHECK(resolve_offline(img, row.send_net_message, row.send_sig) == 0);
        std::printf("%s (negative) %s: shares the AnalysisZoneServerPacket prologue (scan hit @0x%06x) -- "
                    "its SendNetMessage does not resolve, so the row never verifies here\n",
                    label, row.name, (unsigned)shared);
    }
}

static Build pick(const Image& img, const wchar_t* module, uint32_t& send, uint32_t& analysis) {
    send = analysis = 0;
    size_t n = 0;
    const BuildProfile* t = profile_table(n);
    for (size_t i = 0; i < n; ++i) {
        const BuildProfile& row = t[i];
        if (std::wcscmp(row.module, module) != 0) {
            continue;
        }
        if (!row.send_sig || !row.analysis_sig) {
            return row.build;
        }
        const uint32_t s = resolve_offline(img, row.send_net_message, row.send_sig);
        const uint32_t a = resolve_offline(img, row.analysis_zone_packet, row.analysis_sig);
        if (s && a) {
            send = s;
            analysis = a;
            return row.build;
        }
    }
    return Build::Unknown;
}

int main(int argc, char** argv) {
    test_units();
    const BuildProfile* r2232 = find_row(Build::V2232);
    const BuildProfile* r415 = find_row(Build::V415);
    const BuildProfile* r455 = find_row(Build::V455);
    CHECK(r2232 != nullptr);
    CHECK(r415 != nullptr);
    const BuildProfile* rep = find_row(Build::EP1P2);
    CHECK(r455 != nullptr);
    CHECK(rep != nullptr);
    if (r2232 && r415 && r455 && rep) {
        CHECK(r2232->main_cycle_tick == 0x7ed4d0);
        CHECK(r415->send_net_message == 0x553c40);
        CHECK(r415->analysis_zone_packet == 0x554000);
        CHECK(r415->main_cycle_tick == 0x8d6460);
        CHECK(std::wcscmp(r455->module, L"RF_Online.exe") == 0);
        CHECK(r455->send_net_message == 0x562d00);
        CHECK(r455->analysis_zone_packet == 0x563070);
        CHECK(r455->main_cycle_tick == 0x8f2840);
        CHECK(r2232->send_stack_args == 5 && r415->send_stack_args == 5 && r455->send_stack_args == 5);
        CHECK(std::wcscmp(rep->module, L"RF_classic.bin") == 0);
        CHECK(rep->send_net_message == 0x507913);
        CHECK(rep->analysis_zone_packet == 0x507b36);
        CHECK(rep->main_cycle_tick == 0);
        CHECK(rep->send_stack_args == 4);
        uint32_t s = 0, a = 0;
        if (argc > 1) {
            Image img;
            if (parse_image(argv[1], img)) {
                test_positive("2232", img, *r2232);
                test_send_arity("2232", img, *r2232, 0x52ec6c);
                test_negative("2232", img, *r415);
                test_negative("2232", img, *r455);
                test_negative("2232", img, *rep);
                const Build b = pick(img, L"RF_Online.bin", s, a);
                CHECK(b == Build::V2232);
                CHECK(s == 0x52eb90 && a == 0x52edf0);
                std::printf("2232 detect: %s\n", b == Build::V2232 ? "2.2.3.2" : "WRONG");
                const Build bx = pick(img, L"RF_classic.bin", s, a);
                CHECK(bx == Build::Unknown);
                std::printf("2232 detect as RF_classic.bin: %s\n",
                            bx == Build::Unknown ? "none (the EP1P2 row does not verify)" : "WRONG");
            } else {
                std::printf("SKIP: %s not found\n", argv[1]);
            }
        } else {
            std::printf("SKIP: no 2232 image argument\n");
        }
        if (argc > 2) {
            Image img;
            if (parse_image(argv[2], img)) {
                test_positive("4.15", img, *r415);
                test_send_arity("4.15", img, *r415, 0x553df3);
                test_negative("4.15", img, *r2232);
                test_negative("4.15", img, *r455, 1);
                test_negative("4.15", img, *rep);
                Build b = pick(img, L"RF_Online.bin", s, a);
                CHECK(b == Build::V415);
                CHECK(s == 0x553c40 && a == 0x554000);
                std::printf("4.15 detect: %s\n", b == Build::V415 ? "4.15" : "WRONG");
                b = pick(img, L"RF_Online.exe", s, a);
                CHECK(b == Build::Unknown);
                std::printf("4.15 detect as RF_Online.exe: %s\n",
                            b == Build::Unknown ? "none (the 4.55 row does not verify)" : "WRONG");
                b = pick(img, L"RF_classic.bin", s, a);
                CHECK(b == Build::Unknown);
                std::printf("4.15 detect as RF_classic.bin: %s\n",
                            b == Build::Unknown ? "none (the EP1P2 row does not verify)" : "WRONG");
            } else {
                std::printf("SKIP: %s not found\n", argv[2]);
            }
        } else {
            std::printf("SKIP: no 4.15 image argument\n");
        }
        if (argc > 3) {
            Image img;
            if (parse_image(argv[3], img)) {
                test_positive("4.55", img, *r455);
                test_send_arity("4.55", img, *r455, 0x562e2b);
                test_negative("4.55", img, *r2232);
                test_negative("4.55", img, *r415, 1);
                test_negative("4.55", img, *rep);
                Build b = pick(img, L"RF_Online.exe", s, a);
                CHECK(b == Build::V455);
                CHECK(s == 0x562d00 && a == 0x563070);
                std::printf("4.55 detect: %s\n", b == Build::V455 ? "4.55" : "WRONG");
                b = pick(img, L"RF_Online.bin", s, a);
                CHECK(b == Build::Unknown);
                std::printf("4.55 detect as RF_Online.bin: %s\n",
                            b == Build::Unknown ? "none (neither RF_Online.bin row verifies)" : "WRONG");
                b = pick(img, L"RF_classic.bin", s, a);
                CHECK(b == Build::Unknown);
                std::printf("4.55 detect as RF_classic.bin: %s\n",
                            b == Build::Unknown ? "none (the EP1P2 row does not verify)" : "WRONG");
            } else {
                std::printf("SKIP: %s not found\n", argv[3]);
            }
        } else {
            std::printf("SKIP: no 4.55 image argument\n");
        }
        if (argc > 4) {
            Image img;
            if (parse_image(argv[4], img)) {
                test_positive("EP1P2", img, *rep);
                test_send_arity("EP1P2", img, *rep, 0x5079af);
                test_spliced_entry("EP1P2", img, 0x507b36, 0x30e83a0);
                test_negative("EP1P2", img, *r2232);
                test_negative("EP1P2", img, *r415);
                test_negative("EP1P2", img, *r455);
                Build b = pick(img, L"RF_classic.bin", s, a);
                CHECK(b == Build::EP1P2);
                CHECK(s == 0x507913 && a == 0x507b36);
                std::printf("EP1P2 detect: %s\n", b == Build::EP1P2 ? "EP1P2" : "WRONG");
                b = pick(img, L"RF_Online.bin", s, a);
                const Build b2 = pick(img, L"RF_Online.exe", s, a);
                CHECK(b == Build::Unknown && b2 == Build::Unknown);
                std::printf("EP1P2 detect as RF_Online.bin / RF_Online.exe: %s\n",
                            b == Build::Unknown && b2 == Build::Unknown ? "none (no other row verifies)" : "WRONG");
            } else {
                std::printf("SKIP: %s not found\n", argv[4]);
            }
        } else {
            std::printf("SKIP: no EP1P2 image argument\n");
        }
    }
    std::printf("%s (%d failure(s))\n", g_fail ? "FAILED" : "PASSED", g_fail);
    return g_fail ? 1 : 0;
}
