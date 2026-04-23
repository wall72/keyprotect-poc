#include "process_filter.h"
#include "config_manager.h"
#include <string.h>

static HWND g_cachedForegroundWindow = NULL;
static DWORD g_cachedForegroundProcessId = 0;
static BOOL g_cachedProcessAllowed = FALSE;
static BOOL g_hasForegroundDecisionCache = FALSE;

static BOOL GetProcessNameById(DWORD processId, char* processName, DWORD bufferSize) {
    if (processName == NULL || bufferSize == 0 || processId == 0) {
        return FALSE;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        return FALSE;
    }

    BOOL result = FALSE;
    if (GetModuleFileNameExA(hProcess, NULL, processName, bufferSize) > 0) {
        char* fileName = PathFindFileNameA(processName);
        if (fileName != processName) {
            strcpy_s(processName, bufferSize, fileName);
        }
        result = TRUE;
    }

    CloseHandle(hProcess);
    return result;
}

BOOL GetCurrentProcessName(char* processName, DWORD bufferSize) {
    if (processName == NULL || bufferSize == 0) {
        return FALSE;
    }

    HWND hwnd = GetForegroundWindow();
    if (hwnd == NULL) {
        return FALSE;
    }

    DWORD processId = 0;
    GetWindowThreadProcessId(hwnd, &processId);
    if (processId == 0) {
        return FALSE;
    }

    return GetProcessNameById(processId, processName, bufferSize);
}

BOOL TryGetForegroundProcessAllowance(BOOL* isAllowed) {
    if (isAllowed == NULL) {
        return FALSE;
    }

    HWND hwnd = GetForegroundWindow();
    if (hwnd == NULL) {
        return FALSE;
    }

    DWORD processId = 0;
    GetWindowThreadProcessId(hwnd, &processId);
    if (processId == 0) {
        return FALSE;
    }

    if (g_hasForegroundDecisionCache &&
        g_cachedForegroundWindow == hwnd &&
        g_cachedForegroundProcessId == processId) {
        *isAllowed = g_cachedProcessAllowed;
        return TRUE;
    }

    char processName[MAX_PATH] = {0};
    if (!GetProcessNameById(processId, processName, MAX_PATH)) {
        return FALSE;
    }

    g_cachedForegroundWindow = hwnd;
    g_cachedForegroundProcessId = processId;
    g_cachedProcessAllowed = IsAllowedProcess(processName);
    g_hasForegroundDecisionCache = TRUE;

    *isAllowed = g_cachedProcessAllowed;
    return TRUE;
}

void ResetForegroundDecisionCache(void) {
    g_cachedForegroundWindow = NULL;
    g_cachedForegroundProcessId = 0;
    g_cachedProcessAllowed = FALSE;
    g_hasForegroundDecisionCache = FALSE;
}
