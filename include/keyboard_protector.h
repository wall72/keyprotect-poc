#ifndef KEYBOARD_PROTECTOR_H
#define KEYBOARD_PROTECTOR_H

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <psapi.h>
#include <shlwapi.h>

/**
 * @brief 키 코드를 솔트와 키를 사용하여 암호화합니다.
 * @param key_code 암호화할 키 코드
 * @param salt 암호화에 사용할 솔트 값 (매번 다르게 생성 권장)
 * @return unsigned int 암호화된 키 코드
 */
unsigned int encrypt_keycode_with_salt(unsigned int key_code, unsigned int salt);

/**
 * @brief 암호화된 키 코드를 솔트와 키를 사용하여 복호화합니다.
 * @param encrypted_code 복호화할 암호화된 키 코드
 * @param salt 암호화에 사용했던 동일한 솔트 값
 * @return unsigned int 복호화된 (원래의) 키 코드
 */
unsigned int decrypt_keycode_with_salt(unsigned int encrypted_code, unsigned int salt);

/**
 * @brief 키보드 입력이 발생할 때마다 호출되는 저수준 키보드 후크 프로시저
 * @param nCode 후크 프로시저가 메시지를 처리할지 다음 프로시저로 전달할지 결정하는 코드
 * @param wParam 메시지 타입 (WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, WM_SYSKEYUP)
 * @param lParam KBDLLHOOKSTRUCT 구조체에 대한 포인터
 * @return LRESULT 메시지를 차단하려면 0이 아닌 값을 반환, 전달하려면 CallNextHookEx의 반환값을 반환
 */
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);

/**
 * @brief 키보드 후크를 설치하고 설정하는 함수
 * @details 관리자 권한을 확인하고 WH_KEYBOARD_LL 저수준 키보드 후크를 시스템 전역에 설치합니다.
 */
void SetHook(void);

/**
 * @brief 설치된 키보드 후크를 해제하는 함수
 */
void UnsetHook(void);

/**
 * @brief 전역 키보드 후크 핸들
 */
extern HHOOK g_keyboardHook;

/**
 * @brief 현재 포커스된 창의 프로세스 실행 파일 이름을 가져옵니다.
 * @param processName 버퍼에 저장될 프로세스 이름 (최대 MAX_PATH)
 * @param bufferSize 버퍼 크기
 * @return BOOL 성공 시 TRUE, 실패 시 FALSE
 */
BOOL GetCurrentProcessName(char* processName, DWORD bufferSize);

/**
 * @brief 특정 프로세스 이름이 허용된 프로세스인지 확인합니다.
 * @param processName 확인할 프로세스 이름
 * @return BOOL 허용된 프로세스면 TRUE, 아니면 FALSE
 */
BOOL IsAllowedProcess(const char* processName);

/**
 * @brief 복호화된 키 코드를 SendInput을 사용하여 전달합니다.
 * @param vkCode 전달할 가상 키 코드
 * @param isKeyDown 키 다운 이벤트인지 여부 (TRUE: 키 다운, FALSE: 키 업)
 * @return BOOL 성공 시 TRUE, 실패 시 FALSE
 */
BOOL SendDecryptedKey(DWORD vkCode, BOOL isKeyDown);

/**
 * @brief INI 파일에서 허용된 프로세스 목록을 로드합니다.
 * @param iniFilePath INI 파일 경로 (NULL이면 기본 경로 사용)
 * @return BOOL 성공 시 TRUE, 실패 시 FALSE
 */
BOOL LoadAllowedProcessesFromIni(const char* iniFilePath);

/**
 * @brief 로드된 허용 프로세스 목록을 해제합니다.
 */
void FreeAllowedProcesses(void);

#endif // KEYBOARD_PROTECTOR_H