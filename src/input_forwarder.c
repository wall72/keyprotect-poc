#include "input_forwarder.h"

#define KEYPROTECTOR_INJECTED_TAG ((ULONG_PTR)0x4B50524FUL)

ULONG_PTR GetInjectedEventTag(void) {
    return KEYPROTECTOR_INJECTED_TAG;
}

BOOL IsSelfInjectedEvent(const KBDLLHOOKSTRUCT* pKbdStruct) {
    if (pKbdStruct == NULL) {
        return FALSE;
    }

    return ((pKbdStruct->flags & LLKHF_INJECTED) != 0) &&
           (pKbdStruct->dwExtraInfo == KEYPROTECTOR_INJECTED_TAG);
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
