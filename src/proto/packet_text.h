#pragma once
#include "hooks/hooks.h"
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace rfte {
struct Struct;
const char* dir_name(Dir d);
void append_hex_rows(std::string& out, const uint8_t* p, size_t n);
std::string format_packet(const PacketRec& r, double t_ms, std::string_view label = {}, const Struct* layout = nullptr);

struct EditRun {
    size_t off = 0, len = 0;
};

std::vector<EditRun> edit_runs(const std::vector<uint8_t>& before, const std::vector<uint8_t>& after);
std::string edit_run_text(const PacketRec& r, const EditRun& e);
std::string hex_line(const uint8_t* p, size_t n);
bool parse_hex(std::string_view s, std::vector<uint8_t>& out, size_t max_len = (size_t)kMaxAction,
               size_t* bad_at = nullptr);
std::string format_snippet(const PacketRec& r, std::string_view label = {}, const Struct* layout = nullptr);
}
