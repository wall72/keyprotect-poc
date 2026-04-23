#include "config_manager.h"
#include <ctype.h>
#include <string.h>

#define MAX_ALLOWED_PROCESSES 100
#define CONFIG_SECTION_BUFFER_SIZE 8192

static char g_allowedProcesses[MAX_ALLOWED_PROCESSES][MAX_PATH] = {0};
static int g_allowedProcessCount = 0;

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

int GetAllowedProcessCount(void) {
    return g_allowedProcessCount;
}
