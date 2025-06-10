#ifndef _BROCM_DEFINE_H_
#define _BROCM_DEFINE_H_

/**
 * @file brocm_define.h
 * @brief BROCM 암호 모듈에서 공용으로 사용되는 상수, 구조체 등 정의
 */

#define BROCM_BLOCK_CHAR_MAX_LEN				1048576 // 1MB
// #define BROCM_BLOCK_CHAR_MAX_LEN				4194304 // 4MB

/* ==============================================
 * 블록암호 상수 정의
 * ============================================== */
#define BROCM_MAX_ROUND_KEYS 192

#define BROCM_BLOCK_BYTE_LEN 16
#define BROCM_BLOCK_WORD_LEN 4

#define BROCM_SYMMETRIC_KEY_128_BIT_LEN		    128
#define BROCM_SYMMETRIC_KEY_192_BIT_LEN		    192
#define BROCM_SYMMETRIC_KEY_256_BIT_LEN		    256
#define BROCM_SYMMETRIC_KEY_128_BYTE_LEN		16
#define BROCM_SYMMETRIC_KEY_192_BYTE_LEN		24
#define BROCM_SYMMETRIC_KEY_256_BYTE_LEN		32
#define BROCM_SYMMETRIC_KEY_128_WORD_LEN		4
#define BROCM_SYMMETRIC_KEY_192_WORD_LEN		6
#define BROCM_SYMMETRIC_KEY_256_WORD_LEN		8

// 알고리즘 종류를 나타내는 열거형
typedef enum {
    BROCM_ALGO_ARIA=0,
    BROCM_ALGO_LEA,
    BROCM_ALGO_MAX_NUM
} brocm_algo_t;

// 운영모드 종류를 나타내는 열거형
typedef enum {
    BROCM_MODE_ECB = 0,
    BROCM_MODE_CBC,
    BROCM_MODE_CTR,
    BROCM_MODE_CCM,
    BROCM_MODE_GCM,
    BROCM_MODE_MAX_NUM
} brocm_mode_t;

// 패딩 종류를 나타내는 열거형
typedef enum {
    BROCM_PAD_NONE = 0,  // 패딩 없음 (블록 크기의 배수인 데이터용)
    BROCM_PAD_PKCS7,     // PKCS#7 패딩
    BROCM_PAD_ANSIX923,  // ANSI X.923 패딩
    BROCM_PAD_ISO7816,   // ISO/IEC 7816-4 패딩
    BROCM_PAD_MAX        // 패딩 종류 개수
} brocm_padding_t;

// 암호화 방향 (전방향/역방향)
typedef enum {
    BROCM_DIR_ENCRYPT = 0,
    BROCM_DIR_DECRYPT,
} brocm_direction_t;


/* ==============================================
 * 해시 상수 정의
 * ============================================== */
#define BROCM_HASH_SHA224   				224
#define BROCM_HASH_SHA256   				256
#define BROCM_HASH_SHA384   				384
#define BROCM_HASH_SHA512   				512

#define BROCM_HASH_224_BYTE_LEN				28
#define BROCM_HASH_256_BYTE_LEN				32
#define BROCM_HASH_384_BYTE_LEN				48
#define BROCM_HASH_512_BYTE_LEN				64

/* ==============================================
 * 메시지인증코드 상수 정의
 * ============================================== */
typedef enum {
    BROCM_SHA224_HMAC = 0,
    BROCM_SHA256_HMAC,
    BROCM_SHA384_HMAC,
    BROCM_SHA512_HMAC
} brocm_hmac_algorithm_t;

/* ==============================================
 * 키유도 상수 정의
 * ============================================== */
#define BROCM_PBKDF_MIN_PSSWD_LEN_BYTE_LEN  9
#define BROCM_PBKDF_MIN_SALT_LEN_BYTE_LEN   16
#define BROCM_PBKDF_MIN_COUNT_NUM           100000

/* ==============================================
 * 공개키 관련 상수 정의
 * ============================================== */
#define BROCM_ASSYMMETRIC_KEY_2048_BIT_LEN	    2048
#define BROCM_ASSYMMETRIC_KEY_3072_BIT_LEN	    3072
#define BROCM_ASSYMMETRIC_KEY_2048_BYTE_LEN	    256
#define BROCM_ASSYMMETRIC_KEY_3072_BYTE_LEN	    384
#define BROCM_ASSYMMETRIC_KEY_2048_WORD_LEN	    64
#define BROCM_ASSYMMETRIC_KEY_3072_WORD_LEN	    96
#define BROCM_ASSYMMETRIC_KEY_224_BIT_LEN		224
#define BROCM_ASSYMMETRIC_KEY_256_BIT_LEN		256
#define BROCM_ASSYMMETRIC_KEY_224_BYTE_LEN		28
#define BROCM_ASSYMMETRIC_KEY_256_BYTE_LEN		32
#define BROCM_ASSYMMETRIC_KEY_224_WORD_LEN		7
#define BROCM_ASSYMMETRIC_KEY_256_WORD_LEN		8

/* ==============================================
 * 키 공유 관련 상수 정의
 * ============================================== */
#define BROCM_DSA_224   						224
#define BROCM_DSA_256		   					256

#define BROCM_ECC_P224   						224
#define BROCM_ECC_P256		   					256

#define BROCM_ALG_DH							1
#define BROCM_ALG_ECDH							2


#endif
