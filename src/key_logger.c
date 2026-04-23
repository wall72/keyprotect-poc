#include "key_logger.h"
#include <string.h>

static FILE* g_keyLogFile = NULL;

BOOL InitializeKeyLogger(char* logPath, DWORD logPathSize) {
    if (logPath == NULL || logPathSize == 0) {
        return FALSE;
    }

    GetModuleFileNameA(NULL, logPath, logPathSize);
    char* lastSlash = strrchr(logPath, '\\');
    if (lastSlash != NULL) {
        *(lastSlash + 1) = '\0';
    }
    strcat_s(logPath, logPathSize, "keylog.txt");

    g_keyLogFile = fopen(logPath, "a");
    if (g_keyLogFile == NULL) {
        return FALSE;
    }

    fprintf(g_keyLogFile, "===== Keyboard session started =====\n");
    fflush(g_keyLogFile);
    return TRUE;
}

void WriteKeyLogEntry(const char* action, DWORD vkCode, const char* processName, BOOL isAllowed) {
    if (g_keyLogFile == NULL || action == NULL) {
        return;
    }

    SYSTEMTIME localTime = {0};
    GetLocalTime(&localTime);

    fprintf(
        g_keyLogFile,
        "%04d-%02d-%02d %02d:%02d:%02d.%03d | %-7s | VK=0x%02lX (%lu) | Process=%s | Allowed=%s\n",
        localTime.wYear,
        localTime.wMonth,
        localTime.wDay,
        localTime.wHour,
        localTime.wMinute,
        localTime.wSecond,
        localTime.wMilliseconds,
        action,
        (unsigned long)vkCode,
        (unsigned long)vkCode,
        (processName != NULL && processName[0] != '\0') ? processName : "unknown",
        isAllowed ? "yes" : "no"
    );
    fflush(g_keyLogFile);
}

void CloseKeyLogger(void) {
    if (g_keyLogFile == NULL) {
        return;
    }

    fprintf(g_keyLogFile, "===== Keyboard session ended =====\n");
    fclose(g_keyLogFile);
    g_keyLogFile = NULL;
}
