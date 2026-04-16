#ifndef KEYBOARD_PROTECTOR_H
#define KEYBOARD_PROTECTOR_H

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <psapi.h>
#include <shlwapi.h>

typedef enum KeyProtectorStatus {
    KEYPROTECTOR_STATUS_OK = 0,
    KEYPROTECTOR_STATUS_CONFIG_NOT_FOUND = 10,
    KEYPROTECTOR_STATUS_CONFIG_SECTION_MISSING = 11,
    KEYPROTECTOR_STATUS_CONFIG_EMPTY_ALLOWLIST = 12,
    KEYPROTECTOR_STATUS_CONFIG_INVALID_ENTRY = 13,
    KEYPROTECTOR_STATUS_PROCESS_LOOKUP_FAILED = 20,
    KEYPROTECTOR_STATUS_LOG_OPEN_FAILED = 21,
    KEYPROTECTOR_STATUS_HOOK_INSTALL_FAILED = 22,
    KEYPROTECTOR_STATUS_MESSAGE_LOOP_FAILED = 23
} KeyProtectorStatus;

unsigned int encrypt_keycode_with_salt(unsigned int key_code, unsigned int salt);
unsigned int decrypt_keycode_with_salt(unsigned int encrypted_code, unsigned int salt);
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);
KeyProtectorStatus SetHook(void);
void UnsetHook(void);
void RequestShutdown(void);
KeyProtectorStatus GetRuntimeStatus(void);
const char* KeyProtectorStatusToString(KeyProtectorStatus status);
BOOL IsFatalStatus(KeyProtectorStatus status);
extern HHOOK g_keyboardHook;
BOOL GetCurrentProcessName(char* processName, DWORD bufferSize);
BOOL IsAllowedProcess(const char* processName);
BOOL SendDecryptedKey(DWORD vkCode, BOOL isKeyDown);
KeyProtectorStatus LoadAllowedProcessesFromIni(const char* iniFilePath);
void FreeAllowedProcesses(void);

#endif // KEYBOARD_PROTECTOR_H
