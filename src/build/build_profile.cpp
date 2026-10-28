#include "build/build_profile.h"
#include "build/signature.h"
#include "util/log.h"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cwchar>
#include <vector>

namespace rfte {
namespace {

bool readable(uintptr_t a, size_t n) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery((LPCVOID)a, &mbi, sizeof mbi) || mbi.State != MEM_COMMIT) {
        return false;
    }
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) {
        return false;
    }
    return (uintptr_t)mbi.BaseAddress + mbi.RegionSize >= a + n;
}

std::vector<CodeRange> exec_ranges(uintptr_t base) {
    std::vector<CodeRange> out;
    auto* dos = (const IMAGE_DOS_HEADER*)base;
    if (!readable(base, sizeof *dos) || dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return out;
    }
    auto* nt = (const IMAGE_NT_HEADERS32*)(base + dos->e_lfanew);
    if (!readable((uintptr_t)nt, sizeof *nt) || nt->Signature != IMAGE_NT_SIGNATURE) {
        return out;
    }
    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            continue;
        }
        const uintptr_t va = base + sec->VirtualAddress;
        if (!readable(va, sec->Misc.VirtualSize)) {
            continue;
        }
        out.push_back(CodeRange{(const uint8_t*)va, sec->Misc.VirtualSize, va});
    }
    return out;
}

uintptr_t resolve(const BuildProfile& p, uintptr_t base, const char* what, uint32_t va, const char* sig,
                  bool& rescanned) {
    rescanned = false;
    if (!va || !sig) {
        return 0;
    }
    Pattern pat;
    if (!parse_pattern(sig, pat)) {
        logmsg("BUG: %s signature for %s does not parse: \"%s\"", what, p.name, sig);
        return 0;
    }
    const uintptr_t addr = base + (va - p.image_base);
    if (readable(addr, pat.bytes.size()) && match_at((const uint8_t*)addr, pat)) {
        logmsg("%s pinned 0x%06X: signature OK", what, va);
        return addr;
    }
    logmsg("%s pinned 0x%06X: signature MISMATCH -- scanning executable sections", what, va);
    const std::vector<CodeRange> ranges = exec_ranges(base);
    const std::vector<uintptr_t> hits = scan(ranges.data(), ranges.size(), pat, 2);
    if (hits.size() == 1) {
        rescanned = true;
        logmsg("%s re-derived by scan: 0x%06X (IDB VA; pinned was 0x%06X)", what,
               (unsigned)(hits[0] - base + p.image_base), va);
        return hits[0];
    }
    logmsg("%s scan: %u hit(s)%s -- unresolved", what, (unsigned)hits.size(), hits.size() > 1 ? " (ambiguous)" : "");
    return 0;
}

ResolvedProfile detect() {
    {
        wchar_t host[MAX_PATH]{};
        GetModuleFileNameW(nullptr, host, MAX_PATH);
        const wchar_t* slash = wcsrchr(host, L'\\');
        logmsg("host: %ls @ 0x%08X", slash ? slash + 1 : host, (unsigned)(uintptr_t)GetModuleHandleW(nullptr));
    }
    size_t n = 0;
    const BuildProfile* table = profile_table(n);
    for (size_t i = 0; i < n; ++i) {
        const BuildProfile& row = table[i];
        HMODULE h = GetModuleHandleW(row.module);
        if (!h) {
            continue;
        }
        const uintptr_t base = (uintptr_t)h;
        ResolvedProfile r;
        r.profile = &row;
        r.module_base = base;
        if (!row.send_sig || !row.analysis_sig) {
            logmsg("%s detected (%ls @ 0x%08X) -- hook addresses not derived yet (docs/HOOKS.md, M4); staying inert",
                   row.name, row.module, (unsigned)base);
            return r;
        }
        logmsg("trying build %s (%ls @ 0x%08X)", row.name, row.module, (unsigned)base);
        r.send_net_message = resolve(row, base, "SendNetMessage", row.send_net_message, row.send_sig, r.send_rescanned);
        r.analysis_zone_packet = resolve(row, base, "AnalysisZoneServerPacket", row.analysis_zone_packet,
                                         row.analysis_sig, r.analysis_rescanned);
        if (r.send_net_message && r.analysis_zone_packet) {
            logmsg("build %s", row.name);
            return r;
        }
        logmsg("%s signatures did not verify -- trying next profile", row.name);
    }
    logmsg("host is not a recognised RF client -- inert");
    return {};
}

}

const ResolvedProfile& active_profile() {
    static const ResolvedProfile r = detect();
    return r;
}

}
