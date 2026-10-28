#pragma once
#include <cstddef>

namespace rfte {

void log_init(void* self_module);
void logmsg(const char* fmt, ...);
void lograw(const char* text, size_t len);
void log_close();

}
