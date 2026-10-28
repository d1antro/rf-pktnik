#pragma once
#include <cstddef>
#include <cstdint>

namespace rfte {

enum class Build {
    Unknown,
    V2232,
    V415,
    V455,
    EP1P2
};

struct BuildProfile {
    Build build;
    const char* name;
    const wchar_t* module;
    uint32_t image_base;
    uint32_t send_net_message;
    uint32_t analysis_zone_packet;
    uint32_t main_cycle_tick;
    const char* send_sig;
    const char* analysis_sig;
    uint8_t send_stack_args = 5;
};

const BuildProfile* profile_table(size_t& count);

struct ResolvedProfile {
    const BuildProfile* profile = nullptr;
    uintptr_t module_base = 0;
    uintptr_t send_net_message = 0;
    uintptr_t analysis_zone_packet = 0;
    bool send_rescanned = false;
    bool analysis_rescanned = false;
};

const ResolvedProfile& active_profile();

}
