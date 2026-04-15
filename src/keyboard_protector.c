#include "keyboard_protector.h"

/**
 * @brief 전역 키보드 후크 핸들
 */
HHOOK g_keyboardHook = NULL;

/**
 * @brief 프로그램 실행 상태 플래그
 * @details TRUE일 때 프로그램이 실행 중이며, FALSE로 설정되면 종료됩니다.
 */
volatile BOOL g_running = TRUE;

/**
 * @brief 키 코드별 솔트 값 저장 (최대 256개 키)
 * @details 각 키 코드에 대한 솔트를 저장하여 키 업 이벤트에서 복호화할 수 있도록 합니다.
 */
static unsigned int g_keySalt[256] = {0};

/**
 * @brief 키 코드별 암호화된 키 코드 저장
 * @details 각 키 코드에 대한 암호화된 값을 저장합니다.
 */
static unsigned int g_encryptedKeycode[256] = {0};

/**
 * @brief 허용된 프로세스 목록 (최대 100개)
 */
#define MAX_ALLOWED_PROCESSES 100
static char g_allowedProcesses[MAX_ALLOWED_PROCESSES][MAX_PATH] = {0};
static int g_allowedProcessCount = 0;

/**
 * @brief 현재 포커스된 창의 프로세스 실행 파일 이름을 가져옵니다.
 * @param processName 버퍼에 저장될 프로세스 이름 (최대 MAX_PATH)
 * @param bufferSize 버퍼 크기
 * @return BOOL 성공 시 TRUE, 실패 시 FALSE
 */
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
        // 전체 경로에서 파일 이름만 추출
        char* fileName = PathFindFileNameA(processName);
        if (fileName != processName) {
            // 파일 이름을 버퍼의 시작 위치로 이동
            strcpy_s(processName, bufferSize, fileName);
        }
        result = TRUE;
    }
    
    CloseHandle(hProcess);
    return result;
}

/**
 * @brief INI 파일에서 허용된 프로세스 목록을 로드합니다.
 * @param iniFilePath INI 파일 경로 (NULL이면 기본 경로 사용)
 * @return BOOL 성공 시 TRUE, 실패 시 FALSE
 */
BOOL LoadAllowedProcessesFromIni(const char* iniFilePath) {
    // 기존 목록 초기화
    FreeAllowedProcesses();
    
    // INI 파일 경로 결정
    char configPath[MAX_PATH] = {0};
    if (iniFilePath == NULL || iniFilePath[0] == '\0') {
        // 실행 파일과 같은 디렉토리에 config.ini 파일 사용
        GetModuleFileNameA(NULL, configPath, MAX_PATH);
        char* lastSlash = strrchr(configPath, '\\');
        if (lastSlash != NULL) {
            *(lastSlash + 1) = '\0';
        }
        strcat_s(configPath, MAX_PATH, "config.ini");
    } else {
        strcpy_s(configPath, MAX_PATH, iniFilePath);
    }
    
    printf("[설정] INI 파일 로드 시도: %s\n", configPath);
    
    // INI 파일 존재 확인
    DWORD fileAttr = GetFileAttributesA(configPath);
    if (fileAttr == INVALID_FILE_ATTRIBUTES) {
        fprintf(stderr, "[경고] INI 파일을 찾을 수 없습니다: %s\n", configPath);
        fprintf(stderr, "[정보] 기본 설정으로 notepad++.exe만 허용합니다.\n");
        // 기본값으로 notepad++.exe 추가
        strcpy_s(g_allowedProcesses[0], MAX_PATH, "notepad++.exe");
        g_allowedProcessCount = 1;
        return FALSE;
    }
    
    // INI 파일에서 프로세스 목록 읽기
    // [AllowedProcesses] 섹션에서 Process1, Process2, ... 형식으로 읽기
    char buffer[MAX_PATH] = {0};
    int count = 0;
    
    for (int i = 1; i <= MAX_ALLOWED_PROCESSES; i++) {
        char keyName[32] = {0};
        sprintf_s(keyName, sizeof(keyName), "Process%d", i);
        
        DWORD result = GetPrivateProfileStringA(
            "AllowedProcesses",  // 섹션 이름
            keyName,             // 키 이름
            "",                  // 기본값
            buffer,              // 버퍼
            MAX_PATH,            // 버퍼 크기
            configPath           // INI 파일 경로
        );
        
        if (result > 0 && buffer[0] != '\0') {
            // 프로세스 이름 복사
            strcpy_s(g_allowedProcesses[count], MAX_PATH, buffer);
            count++;
            printf("[설정] 허용 프로세스 추가: %s\n", buffer);
        } else {
            // 더 이상 읽을 항목이 없으면 종료
            break;
        }
    }
    
    if (count == 0) {
        fprintf(stderr, "[경고] INI 파일에서 허용 프로세스를 찾을 수 없습니다.\n");
        fprintf(stderr, "[정보] 기본 설정으로 notepad++.exe만 허용합니다.\n");
        // 기본값으로 notepad++.exe 추가
        strcpy_s(g_allowedProcesses[0], MAX_PATH, "notepad++.exe");
        g_allowedProcessCount = 1;
        return FALSE;
    }
    
    g_allowedProcessCount = count;
    printf("[설정] 총 %d개의 허용 프로세스가 로드되었습니다.\n", count);
    return TRUE;
}

/**
 * @brief 로드된 허용 프로세스 목록을 해제합니다.
 */
void FreeAllowedProcesses(void) {
    for (int i = 0; i < g_allowedProcessCount; i++) {
        g_allowedProcesses[i][0] = '\0';
    }
    g_allowedProcessCount = 0;
}

/**
 * @brief 특정 프로세스 이름이 허용된 프로세스인지 확인합니다.
 * @param processName 확인할 프로세스 이름
 * @return BOOL 허용된 프로세스면 TRUE, 아니면 FALSE
 */
BOOL IsAllowedProcess(const char* processName) {
    if (processName == NULL) {
        return FALSE;
    }
    
    // 허용된 프로세스 목록과 비교
    for (int i = 0; i < g_allowedProcessCount; i++) {
        if (_stricmp(processName, g_allowedProcesses[i]) == 0) {
            return TRUE;
        }
    }
    
    return FALSE;
}

/**
 * @brief 복호화된 키 코드를 SendInput을 사용하여 전달합니다.
 * @param vkCode 전달할 가상 키 코드
 * @param isKeyDown 키 다운 이벤트인지 여부 (TRUE: 키 다운, FALSE: 키 업)
 * @return BOOL 성공 시 TRUE, 실패 시 FALSE
 */
BOOL SendDecryptedKey(DWORD vkCode, BOOL isKeyDown) {
    INPUT input = {0};
    input.type = INPUT_KEYBOARD;
    input.ki.wVk = (WORD)vkCode;
    input.ki.dwFlags = isKeyDown ? 0 : KEYEVENTF_KEYUP;
    input.ki.time = 0;
    input.ki.dwExtraInfo = 0;
    
    UINT result = SendInput(1, &input, sizeof(INPUT));
    return (result == 1);
}

/**
 * @brief 키보드 입력이 발생할 때마다 호출되는 저수준 키보드 후크 프로시저
 * @param nCode 후크 프로시저가 메시지를 처리할지 다음 프로시저로 전달할지 결정하는 코드
 * @param wParam 메시지 타입 (WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, WM_SYSKEYUP)
 * @param lParam KBDLLHOOKSTRUCT 구조체에 대한 포인터
 * @return LRESULT 메시지를 차단하려면 0이 아닌 값을 반환, 전달하려면 CallNextHookEx의 반환값을 반환
 */
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    // nCode가 0보다 작으면 시스템에서 후크를 처리해야 함
    if (nCode >= 0) {
        // 키보드 데이터 구조체 포인터
        KBDLLHOOKSTRUCT* pKbdStruct = (KBDLLHOOKSTRUCT*)lParam;
        
        // Esc 키 (VK_ESCAPE)는 종료를 위해 예외적으로 허용
        if (pKbdStruct->vkCode == VK_ESCAPE) {
            printf("\n[알림] Esc 키가 눌렸습니다. 후크를 해제하고 종료합니다.\n");
            // 프로그램 종료 신호 전송
            g_running = FALSE;
            PostQuitMessage(0);
            // 다음 후크로 전달 (즉, 차단하지 않음)
            return CallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
        }
        
        // 키 다운 이벤트 처리
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            // 원본 키 코드
            unsigned int original_keycode = (unsigned int)pKbdStruct->vkCode;
            
            // 솔트 생성: 현재 시간(밀리초)을 기반으로 생성
            unsigned int salt = GetTickCount();
            
            // 키 코드 암호화
            unsigned int encrypted_keycode = encrypt_keycode_with_salt(original_keycode, salt);
            
            // 솔트와 암호화된 키 코드 저장 (복호화를 위해)
            // 키 코드는 0-255 범위이므로 배열 인덱스로 사용 가능
            if (original_keycode < 256) {
                g_keySalt[original_keycode] = salt;
                g_encryptedKeycode[original_keycode] = encrypted_keycode;
            }
            
            // 암호화된 키 코드 출력
            printf("[키 감지] 원본 KeyCode: %u | 솔트: %u | 암호화된 KeyCode: %u\n", 
                   original_keycode, salt, encrypted_keycode);
            
            // 현재 포커스된 프로세스 확인
            char processName[MAX_PATH] = {0};
            if (GetCurrentProcessName(processName, MAX_PATH)) {
                if (IsAllowedProcess(processName)) {
                    // 허용된 프로세스: 복호화하여 전달
                    unsigned int decrypted_keycode = decrypt_keycode_with_salt(encrypted_keycode, salt);
                    printf("[복호화] 프로세스: %s | 복호화된 KeyCode: %u\n", processName, decrypted_keycode);
                    
                    // 복호화된 키를 SendInput으로 전달
                    SendDecryptedKey(decrypted_keycode, TRUE);
                    
                    // 원본 키 입력은 차단
                    return 1; // 키 입력 차단
                } else {
                    // 허용되지 않은 프로세스: 키 입력 차단
                    printf("[차단] 프로세스: %s | 키 입력이 차단되었습니다.\n", processName);
                    return 1; // 키 입력 차단
                }
            } else {
                // 프로세스 이름을 가져올 수 없는 경우: 안전을 위해 차단
                printf("[경고] 프로세스 정보를 가져올 수 없습니다. 키 입력을 차단합니다.\n");
                return 1; // 키 입력 차단
            }
        }
        // 키 업 이벤트 처리
        else if (wParam == WM_KEYUP || wParam == WM_SYSKEYUP) {
            unsigned int original_keycode = (unsigned int)pKbdStruct->vkCode;
            
            // 현재 포커스된 프로세스 확인
            char processName[MAX_PATH] = {0};
            if (GetCurrentProcessName(processName, MAX_PATH)) {
                if (IsAllowedProcess(processName)) {
                    // 허용된 프로세스: 복호화된 키 업 이벤트 전달
                    if (original_keycode < 256 && g_keySalt[original_keycode] != 0) {
                        unsigned int decrypted_keycode = decrypt_keycode_with_salt(
                            g_encryptedKeycode[original_keycode], 
                            g_keySalt[original_keycode]
                        );
                        SendDecryptedKey(decrypted_keycode, FALSE);
                        
                        // 솔트 초기화 (다음 키 입력을 위해)
                        g_keySalt[original_keycode] = 0;
                        g_encryptedKeycode[original_keycode] = 0;
                    }
                    
                    // 원본 키 입력은 차단
                    return 1; // 키 입력 차단
                } else {
                    // 허용되지 않은 프로세스: 키 입력 차단
                    if (original_keycode < 256) {
                        // 솔트 초기화
                        g_keySalt[original_keycode] = 0;
                        g_encryptedKeycode[original_keycode] = 0;
                    }
                    return 1; // 키 입력 차단
                }
            } else {
                // 프로세스 이름을 가져올 수 없는 경우: 안전을 위해 차단
                if (original_keycode < 256) {
                    // 솔트 초기화
                    g_keySalt[original_keycode] = 0;
                    g_encryptedKeycode[original_keycode] = 0;
                }
                return 1; // 키 입력 차단
            }
        }
    }
    
    // 이외의 모든 메시지는 다음 후크로 전달
    return CallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
}

/**
 * @brief 키보드 후크를 설치하고 설정하는 함수
 * @details 관리자 권한을 확인하고 WH_KEYBOARD_LL 저수준 키보드 후크를 시스템 전역에 설치합니다.
 *          Windows XP 호환성을 위해 관리자 권한 확인은 Windows Vista 이상에서만 수행됩니다.
 */
void SetHook() {
    // 관리자 권한 확인 (선택사항, Windows 7 이상에서만 동작)
    // TOKEN_ELEVATION은 Windows Vista 이상에서만 지원됨
    // Windows XP 호환성을 위해 조건부로 처리
    BOOL isAdmin = FALSE;
    
    OSVERSIONINFO osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    
    // Windows Vista (6.0) 이상에서만 관리자 권한 확인
    if (GetVersionEx(&osvi) && osvi.dwMajorVersion >= 6) {
        HANDLE hToken = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            // TOKEN_INFORMATION_CLASS 20 = TokenElevation
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
    // Windows XP에서는 관리자 권한 확인을 건너뜀
    // 후크는 성공하면 자동으로 실행됨

    // WH_KEYBOARD_LL (저수준 키보드 후크)를 시스템 전역에 설치
    g_keyboardHook = SetWindowsHookEx(
        WH_KEYBOARD_LL,           // 후크 타입
        LowLevelKeyboardProc,     // 후크 프로시저
        GetModuleHandle(NULL),    // 인스턴스 핸들
        0                         // 스레드 ID (0 = 시스템 전역)
    );

    if (g_keyboardHook == NULL) {
        DWORD error = GetLastError();
        fprintf(stderr, "[오류] 키보드 후크 설치에 실패했습니다. (Error Code: %lu)\n", error);
        if (error == ERROR_ACCESS_DENIED) {
            fprintf(stderr, "[경고] 관리자 권한이 필요할 수 있습니다.\n");
        }
        exit(1);
    }
    
    // INI 파일에서 허용 프로세스 목록 로드
    LoadAllowedProcessesFromIni(NULL);
    
    printf("[성공] 키보드 보안 툴이 실행되었습니다. 모든 키 입력이 암호화되어 출력됩니다.\n");
    if (isAdmin) {
        printf("[정보] 관리자 권한으로 실행 중입니다.\n");
    }
    printf("---------------------------------------------------------\n");
    printf("Esc 키를 눌러 종료하십시오.\n\n");
}

/**
 * @brief 설치된 키보드 후크를 해제하는 함수
 */
void UnsetHook() {
    if (g_keyboardHook != NULL) {
        UnhookWindowsHookEx(g_keyboardHook);
        g_keyboardHook = NULL;
    }
    // 허용 프로세스 목록 해제
    FreeAllowedProcesses();
}