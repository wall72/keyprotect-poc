#ifndef INPUT_FORWARDER_H
#define INPUT_FORWARDER_H

#include "keyboard_protector.h"

ULONG_PTR GetInjectedEventTag(void);
BOOL IsSelfInjectedEvent(const KBDLLHOOKSTRUCT* pKbdStruct);
BOOL SendDecryptedKey(DWORD vkCode, BOOL isKeyDown);

#endif // INPUT_FORWARDER_H
