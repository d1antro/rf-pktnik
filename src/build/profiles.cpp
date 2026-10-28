#include "build/build_profile.h"

namespace rfte {

// clang-format off
static const BuildProfile kTable[] = {
  { Build::EP1P2, "EP1P2",   L"RF_classic.bin",        0x400000,
    0x507913,
    0x507b36,
    0,
    "55 8B EC 83 EC 08 89 4D F8 83 3D ?? ?? ?? ?? 00 74 3A 6A 02 8B 0D ?? ?? ?? ?? E8",
    "?? ?? ?? ?? ?? 1C 89 4D FC 8B 45 08 33 C9 8A 48 02 89 4D F8 8B 55 F8 83 EA 01 89 55 F8 83 7D F8 64",
    4 },
  { Build::V455,  "4.55",    L"RF_Online.exe",         0x400000,
    0x562d00,
    0x563070,
    0x8f2840,
    "55 8B EC 83 EC 58 53 56 57 89 4D FC 83 3D ?? ?? ?? ?? 00 74 3D 6A 02 8B 0D ?? ?? ?? ?? E8",
    "55 8B EC 83 EC 48 53 56 57 89 4D FC 8B 45 08 0F B6 48 02 89 4D B8 8B 55 B8 83 EA 01 89 55 B8 83 7D B8 64" },
  { Build::V2232, "2.2.3.2", L"RF_Online.bin",         0x400000,
    0x52eb90,
    0x52edf0,
    0x7ed4d0,
    "55 8B EC 83 EC 18 89 4D E8 83 3D ?? ?? ?? ?? 00 74 3D 6A 02 8B 0D ?? ?? ?? ?? E8",
    "55 8B EC 83 EC 1C 89 4D FC 8B 45 08 0F B6 48 02 89 4D F8 8B 55 F8 83 EA 01 89 55 F8 83 7D F8 64" },
  { Build::V415,  "4.15",    L"RF_Online.bin",         0x400000,
    0x553c40,
    0x554000,
    0x8d6460,
    "55 8B EC 83 EC 5C 53 56 57 89 4D FC 83 3D ?? ?? ?? ?? 00 74 3D 6A 02 8B 0D ?? ?? ?? ?? E8",
    "55 8B EC 83 EC 48 53 56 57 89 4D FC 8B 45 08 0F B6 48 02 89 4D B8 8B 55 B8 83 EA 01 89 55 B8 83 7D B8 64" },
};

// clang-format on

const BuildProfile* profile_table(size_t& count) {
    count = sizeof kTable / sizeof kTable[0];
    return kTable;
}

}
