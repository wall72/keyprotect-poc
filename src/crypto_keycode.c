#include <stdio.h>

/**
 * @brief 고정된 암호화 키 (Key)
 * @details XOR 암호화에 사용되는 고정 키 값
 */
#define ENCRYPTION_KEY 0xAA

/**
 * @brief 키 코드를 솔트와 키를 사용하여 암호화합니다.
 * @param key_code 암호화할 키 코드
 * @param salt 암호화에 사용할 솔트 값 (매번 다르게 생성 권장)
 * @return unsigned int 암호화된 키 코드
 */
unsigned int encrypt_keycode_with_salt(unsigned int key_code, unsigned int salt) {
    // 1. 키 코드에 솔트를 XOR하여 섞습니다.
    unsigned int combined_value = key_code ^ salt;
    
    // 2. 최종적으로 고정 키로 한 번 더 XOR 연산하여 암호화합니다.
    unsigned int encrypted_code = combined_value ^ ENCRYPTION_KEY;
    
    return encrypted_code;
}

/**
 * @brief 암호화된 키 코드를 솔트와 키를 사용하여 복호화합니다.
 * @param encrypted_code 복호화할 암호화된 키 코드
 * @param salt 암호화에 사용했던 동일한 솔트 값
 * @return unsigned int 복호화된 (원래의) 키 코드
 */
unsigned int decrypt_keycode_with_salt(unsigned int encrypted_code, unsigned int salt) {
    // 복호화는 암호화의 역순입니다.
    
    // 1. 고정 키로 XOR하여 솔트가 섞인 중간 값으로 되돌립니다.
    unsigned int combined_value = encrypted_code ^ ENCRYPTION_KEY;
    
    // 2. 솔트로 다시 XOR하여 원래의 키 코드를 복원합니다.
    unsigned int decrypted_code = combined_value ^ salt;
    
    return decrypted_code;
}