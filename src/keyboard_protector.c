#include "keyboard_protector.h"
#include <ctype.h>
#include <string.h>

#define MAX_ALLOWED_PROCESSES 100
#define KEYPROTECTOR_INJECTED_TAG ((ULONG_PTR)0x4B50524FUL)
#define CONFIG_SECTION_BUFFER_SIZE 8192

#if defined(DEBUG)
#define HOOK_DEBUG_LOG(...) printf(__VA_ARGS__)
#else
#define HOOK_DEBUG_LOG(...) ((void)0)
#endif

HHOOK g_keyboardHook = NULL;
volatile BOOL g_running = TRUE;

static unsigned int g_keySalt[256] = {0};
static unsigned int g_encryptedKeycode[256] = {0};
static BOOL g_forwardedKeyDown[256] = {FALSE};
static char g_allowedProcesses[MAX_ALLOWED_PROCESSES][MAX_PATH] = {0};
static int g_allowedProcessCount = 0;
static BOOL g_bypassMode = FALSE;
static BOOL g_loggedEmptyAllowlist = FALSE;
static BOOL g_loggedProcessLookupFailure = FALSE;
static HWND g_cachedForegroundWindow = NULL;
static DWORD g_cachedForegroundProcessId = 0;
static BOOL g_cachedProcessAllowed = FALSE;
static BOOL g_hasForegroundDecisionCache = FALSE;
static FILE* g_keyLogFile = NULL;
static KeyProtectorStatus g_runtimeStatus = KEYPROTECTOR_STATUS_OK;

static int GetStatusSeverity(KeyProtectorStatus status) {
    switch (status) {
        case KEYPROTECTOR_STATUS_OK:
            return 0;
        case KEYPROTECTOR_STATUS_CONFIG_NOT_FOUND:
        case KEYPROTECTOR_STATUS_CONFIG_SECTION_MISSING:
        case KEYPROTECTOR_STATUS_CONFIG_EMPTY_ALLOWLIST:
        case KEYPROTECTOR_STATUS_CONFIG_INVALID_ENTRY:
        case KEYPROTECTOR_STATUS_PROCESS_LOOKUP_FAILED:
        case KEYPROTECTOR_STATUS_LOG_OPEN_FAILED:
            return 1;
        case KEYPROTECTOR_STATUS_HOOK_INSTALL_FAILED:
        case KEYPROTECTOR_STATUS_MESSAGE_LOOP_FAILED:
            return 2;
        default:
            return 1;
    }
}

static void UpdateRuntimeStatus(KeyProtectorStatus status) {
    if (status == KEYPROTECTOR_STATUS_OK) {
        return;
    }

    if (GetStatusSeverity(status) >= GetStatusSeverity(g_runtimeStatus)) {
        g_runtimeStatus = status;
    }
}

const char* KeyProtectorStatusToString(KeyProtectorStatus status) {
    switch (status) {
        case KEYPROTECTOR_STATUS_OK:
            return "ok";
        case KEYPROTECTOR_STATUS_CONFIG_NOT_FOUND:
            return "config-not-found";
        case KEYPROTECTOR_STATUS_CONFIG_SECTION_MISSING:
            return "config-section-missing";
        case KEYPROTECTOR_STATUS_CONFIG_EMPTY_ALLOWLIST:
            return "config-empty-allowlist";
        case KEYPROTECTOR_STATUS_CONFIG_INVALID_ENTRY:
            return "config-invalid-entry";
        case KEYPROTECTOR_STATUS_PROCESS_LOOKUP_FAILED:
            return "process-lookup-failed";
        case KEYPROTECTOR_STATUS_LOG_OPEN_FAILED:
            return "log-open-failed";
        case KEYPROTECTOR_STATUS_HOOK_INSTALL_FAILED:
            return "hook-install-failed";
        case KEYPROTECTOR_STATUS_MESSAGE_LOOP_FAILED:
            return "message-loop-failed";
        default:
            return "unknown";
    }
}

BOOL IsFatalStatus(KeyProtectorStatus status) {
    return status == KEYPROTECTOR_STATUS_HOOK_INSTALL_FAILED ||
           status == KEYPROTECTOR_STATUS_MESSAGE_LOOP_FAILED;
}

KeyProtectorStatus GetRuntimeStatus(void) {
    return g_runtimeStatus;
}

void RequestShutdown(void) {
    if (!g_running) {
        return;
    }

    g_running = FALSE;
    PostQuitMessage(0);
}

static void WriteKeyLog(const char* action, DWORD vkCode, const char* processName, BOOL isAllowed) {
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

static void ResetTrackedKeyState(unsigned int keycode) {
    if (keycode < 256) {
        g_keySalt[keycode] = 0;
        g_encryptedKeycode[keycode] = 0;
        g_forwardedKeyDown[keycode] = FALSE;
    }
}

static BOOL IsSelfInjectedEvent(const KBDLLHOOKSTRUCT* pKbdStruct) {
    if (pKbdStruct == NULL) {
        return FALSE;
    }

    return ((pKbdStruct->flags & LLKHF_INJECTED) != 0) &&
           (pKbdStruct->dwExtraInfo == KEYPROTECTOR_INJECTED_TAG);
}

static BOOL IsModifierPressed(int vkCode) {
    return (GetAsyncKeyState(vkCode) & 0x8000) != 0;
}

static BOOL IsBypassToggleKey(const KBDLLHOOKSTRUCT* pKbdStruct) {
    if (pKbdStruct == NULL) {
        return FALSE;
    }

    return pKbdStruct->vkCode == VK_PAUSE &&
           IsModifierPressed(VK_CONTROL) &&
           IsModifierPressed(VK_MENU) &&
           IsModifierPressed(VK_SHIFT);
}

static BOOL ShouldFailOpen(void) {
    return g_allowedProcessCount == 0;
}

static void TrimWhitespace(char* text) {
    char* start = text;
    char* end = NULL;
    size_t length = 0;

    if (text == NULL) {
        return;
    }

    while (*start != '\0' && isspace((unsigned char)*start)) {
        start++;
    }

    if (start != text) {
        memmove(text, start, strlen(start) + 1);
    }

    length = strlen(text);
    if (length == 0) {
        return;
    }

    end = text + length - 1;
    while (end >= text && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }
}

static void TrimMatchingQuotes(char* text) {
    size_t length = 0;

    if (text == NULL) {
        return;
    }

    length = strlen(text);
    if (length >= 2 && text[0] == '"' && text[length - 1] == '"') {
        memmove(text, text + 1, length - 2);
        text[length - 2] = '\0';
    }
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

static BOOL TryGetForegroundProcessAllowance(BOOL* isAllowed) {
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

KeyProtectorStatus LoadAllowedProcessesFromIni(const char* iniFilePath) {
    char configPath[MAX_PATH] = {0};
    char sectionBuffer[CONFIG_SECTION_BUFFER_SIZE] = {0};
    KeyProtectorStatus status = KEYPROTECTOR_STATUS_OK;
    int count = 0;

    FreeAllowedProcesses();

    if (iniFilePath == NULL || iniFilePath[0] == '\0') {
        GetModuleFileNameA(NULL, configPath, MAX_PATH);
        char* lastSlash = strrchr(configPath, '\\');
        if (lastSlash != NULL) {
            *(lastSlash + 1) = '\0';
        }
        strcat_s(configPath, MAX_PATH, "config.ini");
    } else {
        strcpy_s(configPath, MAX_PATH, iniFilePath);
    }

    printf("[config] Loading INI file: %s\n", configPath);

    if (GetFileAttributesA(configPath) == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "[warning] INI file not found: %s\n", configPath);
        fprintf(stderr, "[safety] Blocking is disabled until a valid allowlist is configured.\n");
        return KEYPROTECTOR_STATUS_CONFIG_NOT_FOUND;
    }

    DWORD sectionLength = GetPrivateProfileSectionA(
        "AllowedProcesses",
        sectionBuffer,
        CONFIG_SECTION_BUFFER_SIZE,
        configPath
    );

    if (sectionLength == 0) {
        fprintf(stderr, "[warning] [AllowedProcesses] section is missing or empty in %s\n", configPath);
        fprintf(stderr, "[safety] Blocking is disabled until a valid allowlist is configured.\n");
        return KEYPROTECTOR_STATUS_CONFIG_SECTION_MISSING;
    }

    if (sectionLength >= CONFIG_SECTION_BUFFER_SIZE - 2) {
        fprintf(stderr, "[warning] [AllowedProcesses] section was truncated while loading %s\n", configPath);
        status = KEYPROTECTOR_STATUS_CONFIG_INVALID_ENTRY;
    }

    for (char* entry = sectionBuffer; *entry != '\0'; entry += strlen(entry) + 1) {
        char* equals = strchr(entry, '=');
        char normalizedProcessName[MAX_PATH] = {0};
        BOOL isDuplicate = FALSE;

        if (equals == NULL) {
            fprintf(stderr, "[warning] Invalid config entry ignored: %s\n", entry);
            status = KEYPROTECTOR_STATUS_CONFIG_INVALID_ENTRY;
            continue;
        }

        strcpy_s(normalizedProcessName, MAX_PATH, equals + 1);
        TrimWhitespace(normalizedProcessName);
        TrimMatchingQuotes(normalizedProcessName);
        TrimWhitespace(normalizedProcessName);

        if (normalizedProcessName[0] == '\0') {
            fprintf(stderr, "[warning] Empty process name ignored for key: %.*s\n", (int)(equals - entry), entry);
            status = KEYPROTECTOR_STATUS_CONFIG_INVALID_ENTRY;
            continue;
        }

        char* baseName = PathFindFileNameA(normalizedProcessName);
        if (baseName != normalizedProcessName && baseName[0] != '\0') {
            memmove(normalizedProcessName, baseName, strlen(baseName) + 1);
        }

        TrimWhitespace(normalizedProcessName);
        TrimMatchingQuotes(normalizedProcessName);
        TrimWhitespace(normalizedProcessName);

        if (normalizedProcessName[0] == '\0' ||
            strchr(normalizedProcessName, '\\') != NULL ||
            strchr(normalizedProcessName, '/') != NULL ||
            strchr(normalizedProcessName, ':') != NULL) {
            fprintf(stderr, "[warning] Unsupported process name ignored: %s\n", equals + 1);
            status = KEYPROTECTOR_STATUS_CONFIG_INVALID_ENTRY;
            continue;
        }

        for (int i = 0; i < count; i++) {
            if (_stricmp(normalizedProcessName, g_allowedProcesses[i]) == 0) {
                isDuplicate = TRUE;
                break;
            }
        }

        if (isDuplicate) {
            fprintf(stderr, "[warning] Duplicate process entry ignored: %s\n", normalizedProcessName);
            status = KEYPROTECTOR_STATUS_CONFIG_INVALID_ENTRY;
            continue;
        }

        if (count >= MAX_ALLOWED_PROCESSES) {
            fprintf(stderr, "[warning] Maximum allowlist size reached. Remaining entries were ignored.\n");
            status = KEYPROTECTOR_STATUS_CONFIG_INVALID_ENTRY;
            break;
        }

        strcpy_s(g_allowedProcesses[count], MAX_PATH, normalizedProcessName);
        count++;
        printf("[config] Allowed process: %s\n", normalizedProcessName);
    }

    g_allowedProcessCount = count;
    g_loggedEmptyAllowlist = FALSE;

    if (count == 0) {
        if (status == KEYPROTECTOR_STATUS_OK) {
            status = KEYPROTECTOR_STATUS_CONFIG_EMPTY_ALLOWLIST;
        }
        fprintf(stderr, "[warning] No valid allowed process was configured in %s\n", configPath);
        fprintf(stderr, "[safety] Blocking is disabled until a valid allowlist is configured.\n");
        return status;
    }

    printf("[config] Loaded %d allowed process entries\n", count);
    if (status == KEYPROTECTOR_STATUS_CONFIG_INVALID_ENTRY) {
        fprintf(stderr, "[warning] Some config entries were ignored during validation.\n");
    }

    return status;
}

void FreeAllowedProcesses(void) {
    for (int i = 0; i < g_allowedProcessCount; i++) {
        g_allowedProcesses[i][0] = '\0';
    }
    g_allowedProcessCount = 0;
}

BOOL IsAllowedProcess(const char* processName) {
    if (processName == NULL) {
        return FALSE;
    }

    for (int i = 0; i < g_allowedProcessCount; i++) {
        if (_stricmp(processName, g_allowedProcesses[i]) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

BOOL SendDecryptedKey(DWORD vkCode, BOOL isKeyDown) {
    INPUT input = {0};
    input.type = INPUT_KEYBOARD;
    input.ki.wVk = (WORD)vkCode;
    input.ki.dwFlags = isKeyDown ? 0 : KEYEVENTF_KEYUP;
    input.ki.time = 0;
    input.ki.dwExtraInfo = KEYPROTECTOR_INJECTED_TAG;

    UINT result = SendInput(1, &input, sizeof(INPUT));
    return (result == 1);
}

LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode < 0) {
        return CallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
    }

    KBDLLHOOKSTRUCT* pKbdStruct = (KBDLLHOOKSTRUCT*)lParam;
    if (pKbdStruct == NULL) {
        return CallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
    }

    if (IsBypassToggleKey(pKbdStruct)) {
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            g_bypassMode = !g_bypassMode;
            HOOK_DEBUG_LOG("[safety] Emergency bypass %s (Ctrl+Alt+Shift+Pause)\n",
                           g_bypassMode ? "enabled" : "disabled");
        }
        return 1;
    }

    if (IsSelfInjectedEvent(pKbdStruct)) {
        return CallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
    }

    if (pKbdStruct->vkCode == VK_ESCAPE) {
        RequestShutdown();
        return CallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
    }

    if (g_bypassMode) {
        return CallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
    }

    if (ShouldFailOpen()) {
        g_loggedEmptyAllowlist = TRUE;
        return CallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
    }

    if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
        unsigned int originalKeycode = (unsigned int)pKbdStruct->vkCode;
        unsigned int salt = GetTickCount();
        unsigned int encryptedKeycode = encrypt_keycode_with_salt(originalKeycode, salt);
        char processName[MAX_PATH] = {0};
        BOOL gotProcessName = GetCurrentProcessName(processName, MAX_PATH);
        BOOL isAllowed = FALSE;

        if (originalKeycode < 256) {
            g_keySalt[originalKeycode] = salt;
            g_encryptedKeycode[originalKeycode] = encryptedKeycode;
            g_forwardedKeyDown[originalKeycode] = FALSE;
        }

        if (!TryGetForegroundProcessAllowance(&isAllowed)) {
            UpdateRuntimeStatus(KEYPROTECTOR_STATUS_PROCESS_LOOKUP_FAILED);
            g_loggedProcessLookupFailure = TRUE;
            WriteKeyLog("KEYDOWN", originalKeycode, gotProcessName ? processName : NULL, FALSE);
            ResetTrackedKeyState(originalKeycode);
            return CallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
        }

        g_loggedProcessLookupFailure = FALSE;
        WriteKeyLog("KEYDOWN", originalKeycode, gotProcessName ? processName : NULL, isAllowed);

        if (!isAllowed) {
            ResetTrackedKeyState(originalKeycode);
            return 1;
        }

        if (!SendDecryptedKey(decrypt_keycode_with_salt(encryptedKeycode, salt), TRUE)) {
            ResetTrackedKeyState(originalKeycode);
            return CallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
        }

        if (originalKeycode < 256) {
            g_forwardedKeyDown[originalKeycode] = TRUE;
        }

        return 1;
    }

    if (wParam == WM_KEYUP || wParam == WM_SYSKEYUP) {
        unsigned int originalKeycode = (unsigned int)pKbdStruct->vkCode;
        char processName[MAX_PATH] = {0};
        BOOL gotProcessName = GetCurrentProcessName(processName, MAX_PATH);
        BOOL isAllowed = FALSE;

        if (!TryGetForegroundProcessAllowance(&isAllowed)) {
            UpdateRuntimeStatus(KEYPROTECTOR_STATUS_PROCESS_LOOKUP_FAILED);
            g_loggedProcessLookupFailure = TRUE;
            WriteKeyLog("KEYUP", originalKeycode, gotProcessName ? processName : NULL, FALSE);
            ResetTrackedKeyState(originalKeycode);
            return CallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
        }

        g_loggedProcessLookupFailure = FALSE;
        WriteKeyLog("KEYUP", originalKeycode, gotProcessName ? processName : NULL, isAllowed);

        if (!isAllowed) {
            ResetTrackedKeyState(originalKeycode);
            return 1;
        }

        if (originalKeycode < 256 && g_forwardedKeyDown[originalKeycode] && g_keySalt[originalKeycode] != 0) {
            unsigned int decryptedKeycode = decrypt_keycode_with_salt(
                g_encryptedKeycode[originalKeycode],
                g_keySalt[originalKeycode]
            );

            if (!SendDecryptedKey(decryptedKeycode, FALSE)) {
                ResetTrackedKeyState(originalKeycode);
                return CallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
            }

            ResetTrackedKeyState(originalKeycode);
            return 1;
        }

        ResetTrackedKeyState(originalKeycode);
        return 1;
    }

    return CallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
}

KeyProtectorStatus SetHook(void) {
    BOOL isAdmin = FALSE;
    char logPath[MAX_PATH] = {0};
    KeyProtectorStatus configStatus = KEYPROTECTOR_STATUS_OK;

    g_running = TRUE;
    g_bypassMode = FALSE;
    g_loggedEmptyAllowlist = FALSE;
    g_loggedProcessLookupFailure = FALSE;
    g_cachedForegroundWindow = NULL;
    g_cachedForegroundProcessId = 0;
    g_cachedProcessAllowed = FALSE;
    g_hasForegroundDecisionCache = FALSE;
    g_runtimeStatus = KEYPROTECTOR_STATUS_OK;

    OSVERSIONINFO osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

    if (GetVersionEx(&osvi) && osvi.dwMajorVersion >= 6) {
        HANDLE hToken = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            typedef struct _TOKEN_ELEVATION_INFO {
                DWORD TokenIsElevated;
            } TOKEN_ELEVATION_INFO;

            TOKEN_ELEVATION_INFO elevation;
            DWORD size = sizeof(elevation);

            if (GetTokenInformation(hToken, (TOKEN_INFORMATION_CLASS)20,
                                    &elevation, size, &size)) {
                isAdmin = elevation.TokenIsElevated;
            }
            CloseHandle(hToken);
        }
    }

    configStatus = LoadAllowedProcessesFromIni(NULL);
    UpdateRuntimeStatus(configStatus);

    GetModuleFileNameA(NULL, logPath, MAX_PATH);
    char* lastSlash = strrchr(logPath, '\\');
    if (lastSlash != NULL) {
        *(lastSlash + 1) = '\0';
    }
    strcat_s(logPath, MAX_PATH, "keylog.txt");
    g_keyLogFile = fopen(logPath, "a");
    if (g_keyLogFile == NULL) {
        fprintf(stderr, "[warning] Failed to open key log file: %s\n", logPath);
        UpdateRuntimeStatus(KEYPROTECTOR_STATUS_LOG_OPEN_FAILED);
    }

    g_keyboardHook = SetWindowsHookEx(
        WH_KEYBOARD_LL,
        LowLevelKeyboardProc,
        GetModuleHandle(NULL),
        0
    );

    if (g_keyboardHook == NULL) {
        DWORD error = GetLastError();
        fprintf(stderr, "[error] Failed to install keyboard hook. (Error Code: %lu)\n", error);
        if (error == ERROR_ACCESS_DENIED) {
            fprintf(stderr, "[warning] Administrator privileges may be required.\n");
        }
        UpdateRuntimeStatus(KEYPROTECTOR_STATUS_HOOK_INSTALL_FAILED);
        UnsetHook();
        return KEYPROTECTOR_STATUS_HOOK_INSTALL_FAILED;
    }

    if (g_keyLogFile != NULL) {
        fprintf(g_keyLogFile, "===== Keyboard session started =====\n");
        fflush(g_keyLogFile);
        printf("[info] Key logging file: %s\n", logPath);
    }

    printf("[success] Keyboard protector hook is active.\n");
    if (isAdmin) {
        printf("[info] Running with administrator privileges.\n");
    }
    if (configStatus != KEYPROTECTOR_STATUS_OK) {
        printf("[info] Startup completed with degraded mode: %s\n", KeyProtectorStatusToString(configStatus));
    }
    printf("---------------------------------------------------------\n");
    printf("Esc: exit program\n");
    printf("Ctrl+Alt+Shift+Pause: toggle emergency bypass\n\n");

    return GetRuntimeStatus();
}

void UnsetHook(void) {
    if (g_keyboardHook != NULL) {
        UnhookWindowsHookEx(g_keyboardHook);
        g_keyboardHook = NULL;
    }

    for (int i = 0; i < 256; i++) {
        ResetTrackedKeyState((unsigned int)i);
    }

    FreeAllowedProcesses();
    g_cachedForegroundWindow = NULL;
    g_cachedForegroundProcessId = 0;
    g_cachedProcessAllowed = FALSE;
    g_hasForegroundDecisionCache = FALSE;
    g_bypassMode = FALSE;
    g_loggedEmptyAllowlist = FALSE;
    g_loggedProcessLookupFailure = FALSE;

    if (g_keyLogFile != NULL) {
        fprintf(g_keyLogFile, "===== Keyboard session ended =====\n");
        fclose(g_keyLogFile);
        g_keyLogFile = NULL;
    }
}
