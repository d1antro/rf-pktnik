#include "util/log.h"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdarg>
#include <cstdio>
#include <cwchar>
#include <mutex>

namespace rfte {
namespace {
std::mutex g_logMtx;
FILE* g_logFile = nullptr;
}

void log_init(void* self_module) {
    wchar_t path[MAX_PATH]{};
    DWORD n = GetModuleFileNameW((HMODULE)self_module, path, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        return;
    }
    wchar_t* slash = wcsrchr(path, L'\\');
    wchar_t* name = slash ? slash + 1 : path;
    const wchar_t kName[] = L"RFTrafficEditor.log";
    if ((size_t)(name - path) + sizeof kName / sizeof kName[0] > MAX_PATH) {
        return;
    }
    wcscpy(name, kName);
    std::lock_guard<std::mutex> lk(g_logMtx);
    if (!g_logFile) {
        g_logFile = _wfopen(path, L"w");
    }
}

void logmsg(const char* fmt, ...) {
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);

    SYSTEMTIME t;
    GetLocalTime(&t);
    char line[1100];
    snprintf(line, sizeof line, "[%02u:%02u:%02u.%03u] [%5lu] %s\n", t.wHour, t.wMinute, t.wSecond, t.wMilliseconds,
             GetCurrentThreadId(), msg);

    OutputDebugStringA(line);
    std::lock_guard<std::mutex> lk(g_logMtx);
    if (!g_logFile) {
        return;
    }
    fputs(line, g_logFile);
    fflush(g_logFile);
}

void lograw(const char* text, size_t len) {
    std::lock_guard<std::mutex> lk(g_logMtx);
    if (!g_logFile || !text || !len) {
        return;
    }
    fwrite(text, 1, len, g_logFile);
    fflush(g_logFile);
}

void log_close() {
    std::lock_guard<std::mutex> lk(g_logMtx);
    if (g_logFile) {
        fclose(g_logFile);
        g_logFile = nullptr;
    }
}

}
