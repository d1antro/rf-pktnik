#include "hooks/hooks.h"
#include "build/build_profile.h"
#include "build/signature.h"
#include "hooks/action_queue.h"
#include "hooks/capture_ring.h"
#include "hooks/patch_rules.h"
#include "util/log.h"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <MinHook.h>
#include <atomic>
#include <cstring>
#include <cwchar>
#include <memory>
#include <new>

namespace rfte {
namespace {

#pragma pack(push, 1)

struct MsgHeader {
    uint16_t wSize;
    uint8_t byType[2];
};

#pragma pack(pop)

using CNet = void;

using SendFn = int(__fastcall*)(CNet*, void*, unsigned int, const uint8_t*, void*, int, int);
using AnalysisFn = char(__fastcall*)(CNet*, void*, MsgHeader*, void*);
using Send4Fn = int(__fastcall*)(CNet*, void*, unsigned int, const uint8_t*, void*, int);

SendFn g_origSend = nullptr;
Send4Fn g_origSend4 = nullptr;
AnalysisFn g_origAnalysis = nullptr;

std::atomic<bool> g_installed{false};
std::atomic<bool> g_captureOn{true};

std::atomic<unsigned int> g_sendClientIdx{0};
std::atomic<int> g_sendNetProcIdx{0};
std::atomic<bool> g_haveSendArgs{false};

std::atomic<CNet*> g_sendSelf{nullptr};
std::atomic<CNet*> g_recvSelf{nullptr};
std::atomic<uint32_t> g_sendTid{0};
std::atomic<uint32_t> g_recvTid{0};
std::atomic<uint32_t> g_nSend{0};
std::atomic<uint32_t> g_nRecv{0};

void note_first(std::atomic<CNet*>& self_slot, std::atomic<uint32_t>& tid_slot, CNet* self) {
    CNet* noself = nullptr;
    self_slot.compare_exchange_strong(noself, self);
    uint32_t notid = 0;
    tid_slot.compare_exchange_strong(notid, (uint32_t)GetCurrentThreadId());
}

std::atomic<int> g_inFlight{0};

struct InFlight {
    InFlight() {
        g_inFlight.fetch_add(1, std::memory_order_acq_rel);
    }

    ~InFlight() {
        g_inFlight.fetch_sub(1, std::memory_order_acq_rel);
    }
};

constexpr size_t kRingSlots = 2048;
std::unique_ptr<CaptureRing> g_ring;

void push_capture(Dir dir, uint8_t m, uint8_t s, const uint8_t* p, uint16_t len, bool edited, bool tool = false) {
    if (!g_captureOn.load(std::memory_order_relaxed) || !g_ring) {
        return;
    }
    LARGE_INTEGER q;
    QueryPerformanceCounter(&q);
    g_ring->push(dir, m, s, p, len, edited, (uint64_t)q.QuadPart, tool);
}

void push_capture_edited(Dir dir, uint8_t m, uint8_t s, const uint8_t* before, const uint8_t* after, uint16_t len) {
    if (!g_captureOn.load(std::memory_order_relaxed) || !g_ring) {
        return;
    }
    LARGE_INTEGER q;
    QueryPerformanceCounter(&q);
    g_ring->push_edited(dir, m, s, before, after, len, (uint64_t)q.QuadPart);
}

bool restored(uintptr_t a, const char* sig) {
    Pattern p;
    return a && sig && parse_pattern(sig, p) && match_at((const uint8_t*)a, p);
}

bool entry_ok(const char* what, uintptr_t a) {
    const uint8_t b0 = *(const uint8_t*)a;
    if (b0 == 0x55) {
        return true;
    }
    if (b0 != 0xE9) {
        logmsg("%s entry byte %02X is neither push ebp (55) nor a jmp (E9) -- not hooking", what, b0);
        return false;
    }
    int32_t rel = 0;
    std::memcpy(&rel, (const void*)(a + 1), sizeof rel);
    const uintptr_t to = a + 5 + (uintptr_t)(intptr_t)rel;
    HMODULE m = nullptr;
    wchar_t path[MAX_PATH] = L"";
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)to, &m) &&
        m) {
        GetModuleFileNameW(m, path, MAX_PATH);
    }
    const wchar_t* slash = wcsrchr(path, L'\\');
    logmsg("%s entry is already a jmp: E9 -> 0x%08X (%ls) -- another detour sits on it; ours chains in front of it",
           what, (unsigned)to, path[0] ? (slash ? slash + 1 : path) : L"no module");
    return true;
}

bool jmps_to(uintptr_t a, const void* detour) {
    int32_t rel = 0;
    std::memcpy(&rel, (const void*)(a + 1), sizeof rel);
    return *(const uint8_t*)a == 0xE9 && a + 5 + (uintptr_t)(intptr_t)rel == (uintptr_t)detour;
}

std::unique_ptr<ActionQueue> g_actq;
std::atomic<uint64_t> g_actDone[2]{}, g_actFailed[2]{};
std::atomic<unsigned int> g_lastClientIdx{0};
std::atomic<int> g_lastNetProcIdx{0};

int call_orig_send(CNet* self, unsigned int clientIdx, const uint8_t* type, void* p, int n, int netProcIdx) {
    if (g_origSend4) {
        return g_origSend4(self, nullptr, clientIdx, type, p, n);
    }
    return g_origSend(self, nullptr, clientIdx, type, p, n, netProcIdx);
}

void drain_sends(CNet* self, unsigned int clientIdx, int netProcIdx) {
    if (!g_actq || !self) {
        return;
    }
    g_actq->drain(Dir::C2S, [&](ActionSlot& a) {
        push_capture(Dir::C2S, a.main, a.sub, a.bytes, a.len, false, true);
        const uint8_t type[2] = {a.main, a.sub};
        const int ok = call_orig_send(self, clientIdx, type, a.bytes, (int)a.len, netProcIdx);
        g_actDone[0].fetch_add(1, std::memory_order_relaxed);
        if (!ok) {
            g_actFailed[0].fetch_add(1, std::memory_order_relaxed);
        }
    });
}

void drain_injects(CNet* self) {
    if (!g_actq || !self) {
        return;
    }
    g_actq->drain(Dir::S2C, [&](ActionSlot& a) {
        push_capture(Dir::S2C, a.main, a.sub, a.bytes, a.len, false, true);
        MsgHeader h;
        h.wSize = (uint16_t)(sizeof(MsgHeader) + a.len);
        h.byType[0] = a.main;
        h.byType[1] = a.sub;
        const char r = g_origAnalysis(self, nullptr, &h, a.bytes);
        g_actDone[1].fetch_add(1, std::memory_order_relaxed);
        if (!r) {
            g_actFailed[1].fetch_add(1, std::memory_order_relaxed);
        }
    });
}

RuleSet g_rules;

__declspec(noinline) void rules_and_capture(Dir dir, uint8_t m, uint8_t s, uint8_t* p, uint16_t len) {
    uint8_t before[kMaxCapture];
    const Applied a = g_rules.apply(dir, m, s, p, len, before, sizeof before);
    if (a.changed) {
        push_capture_edited(dir, m, s, before, p, len);
    } else {
        push_capture(dir, m, s, p, len, false);
    }
}

void edit_and_capture(Dir dir, uint8_t m, uint8_t s, uint8_t* p, uint16_t len) {
    if (p && len && g_rules.live()) {
        rules_and_capture(dir, m, s, p, len);
    } else {
        push_capture(dir, m, s, p, len, false);
    }
}

void on_send(CNet* self, unsigned int clientIdx, const uint8_t* pbyType, void* pMsg, int nSize, int netProcIdx) {
    g_nSend.fetch_add(1, std::memory_order_relaxed);
    note_first(g_sendSelf, g_sendTid, self);
    if (!g_haveSendArgs.load(std::memory_order_acquire)) {
        g_sendClientIdx.store(clientIdx);
        g_sendNetProcIdx.store(netProcIdx);
        g_haveSendArgs.store(true, std::memory_order_release);
    }
    g_lastClientIdx.store(clientIdx, std::memory_order_relaxed);
    g_lastNetProcIdx.store(netProcIdx, std::memory_order_relaxed);
    drain_sends(self, clientIdx, netProcIdx);
    if (pbyType) {
        edit_and_capture(Dir::C2S, pbyType[0], pbyType[1], (uint8_t*)pMsg, (uint16_t)nSize);
    }
}

int __fastcall hkSend(CNet* self, void* edx, unsigned int clientIdx, const uint8_t* pbyType, void* pMsg, int nSize,
                      int netProcIdx) {
    InFlight guard;
    on_send(self, clientIdx, pbyType, pMsg, nSize, netProcIdx);
    return g_origSend(self, edx, clientIdx, pbyType, pMsg, nSize, netProcIdx);
}

int __fastcall hkSend4(CNet* self, void* edx, unsigned int clientIdx, const uint8_t* pbyType, void* pMsg, int nSize) {
    InFlight guard;
    on_send(self, clientIdx, pbyType, pMsg, nSize, 0);
    return g_origSend4(self, edx, clientIdx, pbyType, pMsg, nSize);
}

char __fastcall hkAnalysis(CNet* self, void* edx, MsgHeader* hdr, void* pMsg) {
    InFlight guard;
    g_nRecv.fetch_add(1, std::memory_order_relaxed);
    note_first(g_recvSelf, g_recvTid, self);
    uint16_t len = hdr ? (uint16_t)(hdr->wSize >= sizeof(MsgHeader) ? hdr->wSize - sizeof(MsgHeader) : 0) : 0;
    if (hdr) {
        edit_and_capture(Dir::S2C, hdr->byType[0], hdr->byType[1], (uint8_t*)pMsg, len);
    }
    const char r = g_origAnalysis(self, edx, hdr, pMsg);
    drain_injects(self);
    if (g_actq && g_actq->pending(Dir::C2S) && g_haveSendArgs.load(std::memory_order_acquire) &&
        GetCurrentThreadId() == g_sendTid.load(std::memory_order_relaxed)) {
        drain_sends(g_sendSelf.load(), g_lastClientIdx.load(std::memory_order_relaxed),
                    g_lastNetProcIdx.load(std::memory_order_relaxed));
    }
    return r;
}

}

bool install_hooks() {
    const ResolvedProfile& r = active_profile();
    if (!r.profile || !r.send_net_message || !r.analysis_zone_packet) {
        logmsg("install_hooks: no verified targets (unknown build or addresses not derived) -- not hooking");
        return false;
    }
    const unsigned nargs = r.profile->send_stack_args;
    if (nargs != 4 && nargs != 5) {
        logmsg("BUG: %s profile: send_stack_args %u (must be 4 or 5) -- not hooking", r.profile->name, nargs);
        return false;
    }
    if (!entry_ok("SendNetMessage", r.send_net_message) ||
        !entry_ok("AnalysisZoneServerPacket", r.analysis_zone_packet)) {
        return false;
    }
    if (!g_ring) {
        g_ring.reset(new (std::nothrow) CaptureRing(kRingSlots));
    }
    if (!g_ring || g_ring->capacity() == 0) {
        logmsg("capture ring: allocation of %u slots failed -- not hooking", (unsigned)kRingSlots);
        return false;
    }
    if (!g_actq) {
        g_actq.reset(new (std::nothrow) ActionQueue(kActionSlots));
    }
    if (g_actq && g_actq->capacity() == 0) {
        g_actq.reset();
    }
    if (!g_actq) {
        logmsg("action queue: allocation failed -- sending / injecting is unavailable (capture is not affected)");
    }
    MH_STATUS st = MH_Initialize();
    if (st != MH_OK && st != MH_ERROR_ALREADY_INITIALIZED) {
        logmsg("MH_Initialize: %s", MH_StatusToString(st));
        return false;
    }
    const bool send4 = nargs == 4;
    const LPVOID send_detour = send4 ? (LPVOID)&hkSend4 : (LPVOID)&hkSend;
    st = MH_CreateHook((LPVOID)r.send_net_message, send_detour, send4 ? (LPVOID*)&g_origSend4 : (LPVOID*)&g_origSend);
    if (st != MH_OK) {
        logmsg("MH_CreateHook(SendNetMessage 0x%08X): %s", (unsigned)r.send_net_message, MH_StatusToString(st));
        uninstall_hooks();
        return false;
    }
    st = MH_CreateHook((LPVOID)r.analysis_zone_packet, (LPVOID)&hkAnalysis, (LPVOID*)&g_origAnalysis);
    if (st != MH_OK) {
        logmsg("MH_CreateHook(AnalysisZoneServerPacket 0x%08X): %s", (unsigned)r.analysis_zone_packet,
               MH_StatusToString(st));
        uninstall_hooks();
        return false;
    }
    st = MH_EnableHook(MH_ALL_HOOKS);
    if (st != MH_OK) {
        logmsg("MH_EnableHook(all): %s", MH_StatusToString(st));
        uninstall_hooks();
        return false;
    }
    g_installed.store(true);
    logmsg("hooks installed: SendNetMessage 0x%08X, AnalysisZoneServerPacket 0x%08X", (unsigned)r.send_net_message,
           (unsigned)r.analysis_zone_packet);
    if (send4) {
        logmsg(
            "SendNetMessage: 4 stack args on this build (no nNetProcessIdx, retn 10h) -- hooked with the 4-arg detour");
    }
    logmsg("patched first bytes: SendNetMessage %02X%s, AnalysisZoneServerPacket %02X%s",
           *(const uint8_t*)r.send_net_message,
           jmps_to(r.send_net_message, send_detour) ? " (jmp, OK)" : " (NOT our jmp!)",
           *(const uint8_t*)r.analysis_zone_packet,
           jmps_to(r.analysis_zone_packet, (const void*)&hkAnalysis) ? " (jmp, OK)" : " (NOT our jmp!)");
    logmsg("capture ring: %u slots x %u B", (unsigned)kRingSlots, (unsigned)sizeof(CaptureSlot));
    if (g_actq) {
        logmsg("action queue: %u slots per direction x %u B -- the UI's sends / injects run inside the two "
               "hooks, on the game's thread",
               (unsigned)kActionSlots, (unsigned)sizeof(ActionSlot));
    }
    return true;
}

bool uninstall_hooks(unsigned wait_ms) {
    const bool was_on = g_installed.exchange(false);
    g_rules.arm(false);
    MH_DisableHook(MH_ALL_HOOKS);
    if (was_on) {
        logmsg("hooks disabled -- waiting for in-flight calls to leave the detours");
    }
    const ULONGLONG t0 = GetTickCount64();
    for (;;) {
        if (g_inFlight.load() == 0) {
            Sleep(100);
            if (g_inFlight.load() == 0) {
                break;
            }
        }
        if (GetTickCount64() - t0 >= wait_ms) {
            logmsg("unload ABORTED: %d call(s) still inside a detour after %u ms -- hooks are "
                   "DISABLED (original bytes back), trampolines kept; the DLL must stay loaded",
                   g_inFlight.load(), wait_ms);
            return false;
        }
        Sleep(10);
    }
    if (g_actq) {
        const size_t n = g_actq->cancel();
        if (n) {
            logmsg("action queue: %u queued action(s) dropped at unload -- never executed", (unsigned)n);
        }
    }
    MH_RemoveHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    g_origSend = nullptr;
    g_origSend4 = nullptr;
    g_origAnalysis = nullptr;
    if (was_on) {
        const ResolvedProfile& r = active_profile();
        logmsg("hooks removed; original bytes: SendNetMessage %s, AnalysisZoneServerPacket %s",
               restored(r.send_net_message, r.profile->send_sig) ? "signature OK" : "SIGNATURE MISMATCH",
               restored(r.analysis_zone_packet, r.profile->analysis_sig) ? "signature OK" : "SIGNATURE MISMATCH");
    }
    return true;
}

HookStats hook_stats() {
    HookStats s;
    s.send_self = g_sendSelf.load();
    s.recv_self = g_recvSelf.load();
    s.send_tid = g_sendTid.load();
    s.recv_tid = g_recvTid.load();
    s.have_send_args = g_haveSendArgs.load(std::memory_order_acquire);
    if (s.have_send_args) {
        s.client_idx = g_sendClientIdx.load();
        s.net_proc_idx = g_sendNetProcIdx.load();
    }
    s.n_send = g_nSend.load(std::memory_order_relaxed);
    s.n_recv = g_nRecv.load(std::memory_order_relaxed);
    return s;
}

size_t drain_captures(std::vector<PacketRec>& out, size_t max, uint64_t& dropped) {
    dropped = g_ring ? g_ring->take_dropped() : 0;
    if (!g_ring) {
        return 0;
    }
    size_t n = 0;
    PacketRec r;
    while (n < max && g_ring->pop(r)) {
        out.push_back(std::move(r));
        ++n;
    }
    return n;
}

void set_capture_enabled(bool on) {
    g_captureOn.store(on);
}

Queued queue_action(Dir dir, uint8_t m, uint8_t s, const uint8_t* payload, size_t len) {
    if (!g_installed.load() || !g_actq) {
        return Queued::Unavailable;
    }
    return g_actq->push(dir, m, s, payload, len);
}

size_t cancel_actions() {
    return g_actq ? g_actq->cancel() : 0;
}

ActionStats action_stats() {
    ActionStats s;
    for (size_t d = 0; d < 2; ++d) {
        s.pending[d] = g_actq ? (uint32_t)g_actq->pending((Dir)d) : 0;
        s.done[d] = g_actDone[d].load(std::memory_order_relaxed);
        s.failed[d] = g_actFailed[d].load(std::memory_order_relaxed);
    }
    s.calls[0] = g_nSend.load(std::memory_order_relaxed);
    s.calls[1] = g_nRecv.load(std::memory_order_relaxed);
    return s;
}

size_t set_rules(const std::vector<PatchRule>& rules) {
    return g_rules.set(rules);
}

void arm_rules(bool on) {
    g_rules.arm(on);
}

RuleStats rule_stats() {
    return g_rules.stats();
}

}
