#include "keyboard_protector.h"
#include <string.h>

#define MAX_ALLOWED_PROCESSES 100
#define KEYPROTECTOR_INJECTED_TAG ((ULONG_PTR)0x4B50524FUL)

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

BOOL GetCurrentProcessName(char* processName, DWORD bufferSize) {
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
    if (!GetCurrentProcessName(processName, MAX_PATH)) {
        return FALSE;
    }

    g_cachedForegroundWindow = hwnd;
    g_cachedForegroundProcessId = processId;
    g_cachedProcessAllowed = IsAllowedProcess(processName);
    g_hasForegroundDecisionCache = TRUE;

    *isAllowed = g_cachedProcessAllowed;
    return TRUE;
}

BOOL LoadAllowedProcessesFromIni(const char* iniFilePath) {
    FreeAllowedProcesses();

    char configPath[MAX_PATH] = {0};
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

    DWORD fileAttr = GetFileAttributesA(configPath);
    if (fileAttr == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "[warning] INI file not found: %s\n", configPath);
        fprintf(stderr, "[safety] Blocking is disabled until a valid allowlist is configured.\n");
        return FALSE;
    }

    char buffer[MAX_PATH] = {0};
    int count = 0;

    for (int i = 1; i <= MAX_ALLOWED_PROCESSES; i++) {
        char keyName[32] = {0};
        sprintf_s(keyName, sizeof(keyName), "Process%d", i);

        DWORD result = GetPrivateProfileStringA(
            "AllowedProcesses",
            keyName,
            "",
            buffer,
            MAX_PATH,
            configPath
        );

        if (result > 0 && buffer[0] != '\0') {
            strcpy_s(g_allowedProcesses[count], MAX_PATH, buffer);
            count++;
            printf("[config] Allowed process: %s\n", buffer);
        } else {
            break;
        }
    }

    g_allowedProcessCount = count;
    g_loggedEmptyAllowlist = FALSE;

    if (count == 0) {
        fprintf(stderr, "[warning] No allowed process was configured in %s\n", configPath);
        fprintf(stderr, "[safety] Blocking is disabled until a valid allowlist is configured.\n");
        return FALSE;
    }

    printf("[config] Loaded %d allowed process entries\n", count);
    return TRUE;
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
        g_running = FALSE;
        PostQuitMessage(0);
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
        unsigned int original_keycode = (unsigned int)pKbdStruct->vkCode;
        unsigned int salt = GetTickCount();
        unsigned int encrypted_keycode = encrypt_keycode_with_salt(original_keycode, salt);

        if (original_keycode < 256) {
            g_keySalt[original_keycode] = salt;
            g_encryptedKeycode[original_keycode] = encrypted_keycode;
            g_forwardedKeyDown[original_keycode] = FALSE;
        }

        BOOL isAllowed = FALSE;
        if (!TryGetForegroundProcessAllowance(&isAllowed)) {
            g_loggedProcessLookupFailure = TRUE;
            ResetTrackedKeyState(original_keycode);
            return CallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
        }

        g_loggedProcessLookupFailure = FALSE;

        if (!isAllowed) {
            ResetTrackedKeyState(original_keycode);
            return 1;
        }

        unsigned int decrypted_keycode = decrypt_keycode_with_salt(encrypted_keycode, salt);

        if (!SendDecryptedKey(decrypted_keycode, TRUE)) {
            ResetTrackedKeyState(original_keycode);
            return CallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
        }

        if (original_keycode < 256) {
            g_forwardedKeyDown[original_keycode] = TRUE;
        }

        return 1;
    }

    if (wParam == WM_KEYUP || wParam == WM_SYSKEYUP) {
        unsigned int original_keycode = (unsigned int)pKbdStruct->vkCode;

        if (original_keycode < 256 && g_forwardedKeyDown[original_keycode] && g_keySalt[original_keycode] != 0) {
            unsigned int decrypted_keycode = decrypt_keycode_with_salt(
                g_encryptedKeycode[original_keycode],
                g_keySalt[original_keycode]
            );

            if (!SendDecryptedKey(decrypted_keycode, FALSE)) {
                ResetTrackedKeyState(original_keycode);
                return CallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
            }

            ResetTrackedKeyState(original_keycode);
            return 1;
        }

        ResetTrackedKeyState(original_keycode);
        return 1;
    }

    return CallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
}

void SetHook(void) {
    BOOL isAdmin = FALSE;

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
        exit(1);
    }

    LoadAllowedProcessesFromIni(NULL);

    printf("[success] Keyboard protector hook is active.\n");
    if (isAdmin) {
        printf("[info] Running with administrator privileges.\n");
    }
    printf("---------------------------------------------------------\n");
    printf("Esc: exit program\n");
    printf("Ctrl+Alt+Shift+Pause: toggle emergency bypass\n\n");
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
}
