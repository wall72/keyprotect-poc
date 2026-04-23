#include "keyboard_protector.h"
#include "config_manager.h"
#include "input_forwarder.h"
#include "key_logger.h"
#include "process_filter.h"

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
static BOOL g_bypassMode = FALSE;
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

static void ResetTrackedKeyState(unsigned int keycode) {
    if (keycode < 256) {
        g_keySalt[keycode] = 0;
        g_encryptedKeycode[keycode] = 0;
        g_forwardedKeyDown[keycode] = FALSE;
    }
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
    return GetAllowedProcessCount() == 0;
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

    if (g_bypassMode || ShouldFailOpen()) {
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
            WriteKeyLogEntry("KEYDOWN", originalKeycode, gotProcessName ? processName : NULL, FALSE);
            ResetTrackedKeyState(originalKeycode);
            return CallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
        }

        WriteKeyLogEntry("KEYDOWN", originalKeycode, gotProcessName ? processName : NULL, isAllowed);

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
            WriteKeyLogEntry("KEYUP", originalKeycode, gotProcessName ? processName : NULL, FALSE);
            ResetTrackedKeyState(originalKeycode);
            return CallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
        }

        WriteKeyLogEntry("KEYUP", originalKeycode, gotProcessName ? processName : NULL, isAllowed);

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
    ResetForegroundDecisionCache();
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

    if (!InitializeKeyLogger(logPath, MAX_PATH)) {
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

    if (logPath[0] != '\0') {
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
    ResetForegroundDecisionCache();
    g_bypassMode = FALSE;
    CloseKeyLogger();
}
