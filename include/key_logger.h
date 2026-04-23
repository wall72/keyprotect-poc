#ifndef KEY_LOGGER_H
#define KEY_LOGGER_H

#include "keyboard_protector.h"

BOOL InitializeKeyLogger(char* logPath, DWORD logPathSize);
void WriteKeyLogEntry(const char* action, DWORD vkCode, const char* processName, BOOL isAllowed);
void CloseKeyLogger(void);

#endif // KEY_LOGGER_H
