#include <windows.h>
#include <MinHook.h>
#include <cstdint>
#include <cstdio>
#include <cstring>

static int g_fail = 0;
#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            std::printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_fail;                                                   \
        }                                                               \
    } while (0)

#pragma pack(push, 1)

struct Hdr {
    uint16_t wSize;
    uint8_t byType[2];
};

#pragma pack(pop)
using AnalysisFn = char(__fastcall*)(void*, void*, Hdr*, void*);
using Send4Fn = int(__fastcall*)(void*, void*, unsigned int, const uint8_t*, void*, int);

static char g_order[8];
static int g_n = 0;

static void mark(char c) {
    if (g_n < 7) {
        g_order[g_n++] = c;
        g_order[g_n] = 0;
    }
}

static __declspec(noinline) char __fastcall real_analysis(void*, void*, Hdr* h, void*) {
    mark('o');
    return (char)(h->byType[0] + 1);
}

static __declspec(noinline) char __fastcall theirs(void* self, void* edx, Hdr* h, void* p) {
    mark('t');
    return real_analysis(self, edx, h, p);
}

static AnalysisFn g_ourAnalysis = nullptr;

static __declspec(noinline) char __fastcall ours(void* self, void* edx, Hdr* h, void* p) {
    mark('u');
    return g_ourAnalysis(self, edx, h, p);
}

static void* volatile g_self4 = nullptr;
static unsigned g_a4 = 0;
static const uint8_t* g_t4 = nullptr;
static void* g_p4 = nullptr;
static int g_n4 = 0;

static __declspec(noinline) int __fastcall real_send4(void* self, void*, unsigned int a, const uint8_t* t, void* p,
                                                      int n) {
    g_self4 = self;
    g_a4 = a;
    g_t4 = t;
    g_p4 = p;
    g_n4 = n;
    return (int)a * 1000 + n;
}

static Send4Fn g_ourSend4 = nullptr;
static int g_seen4 = 0;

static
    __declspec(noinline) int __fastcall ours4(void* self, void* edx, unsigned int a, const uint8_t* t, void* p, int n) {
    ++g_seen4;
    return g_ourSend4(self, edx, a, t, p, n);
}

static __declspec(noinline) int call4(Send4Fn f, void* self, unsigned a, const uint8_t* t, void* p, int n,
                                      bool& esp_ok) {
    uint32_t e0 = 0, e1 = 0;
    int r;
    // A single-line __asm ends at the newline, so these lines must not be joined.
    // clang-format off
    __asm mov e0, esp
    r = f(self, nullptr, a, t, p, n);
    __asm mov e1, esp
    esp_ok = e0 == e1;
    // clang-format on
    return r;
}

static void test_chain() {
    uint8_t* entry = (uint8_t*)VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    CHECK(entry != nullptr);
    if (!entry) {
        return;
    }
    std::memset(entry, 0xCC, 4096);
    const int32_t rel = (int32_t)((uintptr_t)&theirs - ((uintptr_t)entry + 5));
    entry[0] = 0xE9;
    std::memcpy(entry + 1, &rel, 4);
    entry[5] = 0x1C;
    uint8_t spliced[5];
    std::memcpy(spliced, entry, 5);
    FlushInstructionCache(GetCurrentProcess(), entry, 16);

    Hdr h{4 + 2, {4, 9}};
    uint8_t payload[2] = {1, 2};
    char r = ((AnalysisFn)entry)(nullptr, nullptr, &h, payload);
    CHECK(r == 5 && std::strcmp(g_order, "to") == 0);

    MH_STATUS st = MH_CreateHook(entry, (LPVOID)&ours, (LPVOID*)&g_ourAnalysis);
    CHECK(st == MH_OK);
    const MH_STATUS en = MH_EnableHook(entry);
    CHECK(en == MH_OK);
    int32_t rel2 = 0;
    std::memcpy(&rel2, entry + 1, 4);
    CHECK(entry[0] == 0xE9 && (uintptr_t)entry + 5 + (uintptr_t)(intptr_t)rel2 == (uintptr_t)&ours);
    g_n = 0;
    g_order[0] = 0;
    r = ((AnalysisFn)entry)(nullptr, nullptr, &h, payload);
    CHECK(r == 5 && std::strcmp(g_order, "uto") == 0);
    std::printf(
        "chain: entry E9 -> theirs; hooked over it: %s; call order %s (ours -> theirs -> original), returned %d\n",
        MH_StatusToString(st), g_order, (int)r);
    st = MH_DisableHook(entry);
    const bool back = std::memcmp(entry, spliced, 5) == 0;
    CHECK(st == MH_OK && back);
    std::printf("chain: disabled -- their E9 is back byte for byte: %s\n", back ? "yes" : "NO");
    MH_RemoveHook(entry);
    VirtualFree(entry, 0, MEM_RELEASE);
}

static void test_arity() {
    MH_STATUS st = MH_CreateHook((LPVOID)&real_send4, (LPVOID)&ours4, (LPVOID*)&g_ourSend4);
    CHECK(st == MH_OK);
    CHECK(MH_EnableHook((LPVOID)&real_send4) == MH_OK);
    const uint8_t type[2] = {4, 1};
    uint8_t msg[22] = {};
    int self_obj = 0;
    bool esp_ok = false;
    const int r = call4((Send4Fn)&real_send4, &self_obj, 7, type, msg, 22, esp_ok);
    const bool args = g_self4 == &self_obj && g_a4 == 7 && g_t4 == type && g_p4 == msg && g_n4 == 22;
    CHECK(g_seen4 == 1);
    CHECK(r == 7022 && args);
    CHECK(esp_ok);
    std::printf("arity: 4-arg detour over a 4-arg target: args %s, ESP %s, returned %d\n", args ? "intact" : "WRONG",
                esp_ok ? "balanced" : "UNBALANCED", r);
    MH_DisableHook((LPVOID)&real_send4);
    MH_RemoveHook((LPVOID)&real_send4);
}

int main() {
    CHECK(MH_Initialize() == MH_OK);
    test_chain();
    test_arity();
    MH_Uninitialize();
    std::printf("%s (%d failure(s))\n", g_fail ? "FAILED" : "PASSED", g_fail);
    return g_fail ? 1 : 0;
}
