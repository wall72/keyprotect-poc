#ifndef PROCESS_FILTER_H
#define PROCESS_FILTER_H

#include "keyboard_protector.h"

BOOL GetCurrentProcessName(char* processName, DWORD bufferSize);
BOOL TryGetForegroundProcessAllowance(BOOL* isAllowed);
void ResetForegroundDecisionCache(void);

#endif // PROCESS_FILTER_H
