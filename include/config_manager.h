#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include "keyboard_protector.h"

KeyProtectorStatus LoadAllowedProcessesFromIni(const char* iniFilePath);
void FreeAllowedProcesses(void);
BOOL IsAllowedProcess(const char* processName);
int GetAllowedProcessCount(void);

#endif // CONFIG_MANAGER_H
