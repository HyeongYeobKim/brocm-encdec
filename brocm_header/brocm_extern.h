#ifndef _BROCM_EXTERN_H_
#define _BROCM_EXTERN_H_

/**
 * @file brocm_extern.h
 * @brief BROCM 암호 모듈의 외부 인터페이스 정의
 * 
 * __attribute__((visibility("default")))는 GCC 컴파일러 확장 기능으로,
 * 심볼의 가시성을 제어합니다. "default" 가시성은 해당 심볼이 공개적으로
 * 노출되어 외부 모듈에서 접근 가능하도록 합니다. 이는 공유 라이브러리에서
 * 외부로 노출할 API 함수를 명시적으로 지정할 때 사용됩니다.
 */
#define BROCM_DL_EXPORT	__attribute__((visibility("default"))) extern

BROCM_DL_EXPORT unsigned int brocm_bc_encrypt(
	unsigned int* pOutput,
	unsigned char* pMac,
	unsigned int Mac_length,
	unsigned int* pInput,
	unsigned int Input_length,
	unsigned char* pIV,
	unsigned int IV_length,
	unsigned char* pAut,
	unsigned int Aut_length,
	unsigned int* pKey,
	unsigned int Key_length,
	unsigned char Algorithm,
	unsigned char Mode);

BROCM_DL_EXPORT unsigned int brocm_bc_decrypt(
	unsigned int* pOutput,
	unsigned int* pInput,
	unsigned int Input_length,
	unsigned char* pMac,
	unsigned int Mac_length,
	unsigned char* pIV,
	unsigned int IV_length,
	unsigned char* pAut,
	unsigned int Aut_length,
	unsigned int* pKey,
	unsigned int Key_length,
	unsigned char Algorithm,
	unsigned char Mode);

BROCM_DL_EXPORT unsigned int brocm_drbg(
	unsigned char* pRand,
	unsigned int Rand_length,
	unsigned char Entropy[][32],
	unsigned int EntropyLen,
	unsigned int EntropyCount,
	unsigned char* Nonce,
	unsigned int NonceLen,
	unsigned int UseDf,
	unsigned int UseNonce);

BROCM_DL_EXPORT unsigned int brocm_hash(
	unsigned char* pDigest,
	unsigned char* pMsg,
	const unsigned int Msg_length,
	const unsigned int Hash_type);

BROCM_DL_EXPORT unsigned int brocm_pbkdf(
    unsigned char* MK,
    unsigned int MK_length,
    unsigned char* Password,
    unsigned int Password_length,
    unsigned char* Salt,
    unsigned int Salt_length,
    unsigned int C,
    unsigned int hmac_size);

    
BROCM_DL_EXPORT unsigned int brocm_gen_param_dh(
	unsigned char* pP,
	unsigned char* pQ,
	unsigned char* pG,
	unsigned int P_length,
	unsigned int Q_length);
    
BROCM_DL_EXPORT unsigned int brocm_gen_kt_dh(
	unsigned char* pKT,
	unsigned int* KT_length,
	unsigned char* pR,
	unsigned int R_length,
	unsigned char* pP,
	unsigned char* pQ,
	unsigned char* pG,
	unsigned int P_length,
	unsigned int Q_length);

BROCM_DL_EXPORT unsigned int brocm_gen_sk_dh(
	unsigned char* pSK,
	unsigned int* SK_length,
	unsigned char* pKT,
	unsigned int KT_length,
	unsigned char* pR,
	unsigned int R_length,
	unsigned char* pP,
	unsigned char* pQ,
	unsigned char* pG,
	unsigned int P_length,
	unsigned int Q_length);
    
BROCM_DL_EXPORT unsigned int brocm_gen_kt_ecdh(
	unsigned char* pKTx,
	unsigned char* pKTy,
	unsigned char* pR,
	unsigned int	R_length,
	unsigned int	DParam);

BROCM_DL_EXPORT unsigned int brocm_gen_sk_ecdh(
	unsigned char* pSKx,
	unsigned char* pSKy,
	unsigned char* pKTx,
	unsigned char* pKTy,
	unsigned char* pR,
	unsigned int R_length,
	unsigned int DParam);

BROCM_DL_EXPORT unsigned int brocm_gen_rn(
    unsigned char* pRN,
    unsigned int RN_len);

BROCM_DL_EXPORT unsigned int brocm_gen_key_rsa(
	unsigned char* pN,
	unsigned int* N_length,
	unsigned char* pD,
	unsigned int* D_length,
	unsigned int E,
	unsigned int nbit);

BROCM_DL_EXPORT unsigned int brocm_gen_mac(
	unsigned char* pMAC,
	unsigned int MAC_length,
	unsigned char* pMsg,
	unsigned int Msg_length,
	unsigned char* pKey,
	unsigned int Key_length,
	unsigned char Algorithm);

BROCM_DL_EXPORT unsigned int brocm_verify_mac(
	unsigned char* pMsg,
	unsigned int Msg_length,
	unsigned char* pMAC,
	unsigned int MAC_length,
	unsigned char* pKey,
	unsigned int Key_length,
	unsigned char Algorithm);

BROCM_DL_EXPORT unsigned int brocm_encrypt_rsa(
	unsigned char* pOutput,
	unsigned int* Output_length,
	unsigned char* pInput,
	unsigned int Input_length,
	unsigned char* pPublic_key_n,
	unsigned int Public_key_n_length,
	unsigned int Public_key_e,
	unsigned char* pLabel,
	unsigned int Label_length,
	unsigned char* pSeed,
	unsigned int Hash_type);

BROCM_DL_EXPORT unsigned int brocm_decrypt_rsa(
	unsigned char* pOutput,
	unsigned int* Output_length,
	unsigned char* pInput,
	unsigned int Input_length,
	unsigned char* pPrivate_key_n,
	unsigned int Private_key_n_length,
	unsigned char* pPrivate_key_d,
	unsigned int Private_key_d_length,
	unsigned char* pLabel,
	unsigned int Label_length,
	unsigned int Hash_type);

BROCM_DL_EXPORT unsigned int brocm_sign_rsa(
	unsigned char* pSign,
	unsigned int* Sign_length,
	unsigned char* pMsg,
	unsigned int Msg_length,
	unsigned char* pPrivate_key_n,
	unsigned int Private_key_n_length,
	unsigned char* pPrivate_key_d,
	unsigned int Private_key_d_length,
	unsigned char* pSalt,
	unsigned int Salt_length,
	unsigned int Hash_type);

BROCM_DL_EXPORT unsigned int brocm_verify_rsa(
	unsigned char* pSign,
	unsigned int Sign_length,
	unsigned char* pMsg,
	unsigned int Msg_length,
	unsigned char* pPublic_key_n,
	unsigned int Public_key_n_length,
	unsigned int Public_key_e,
	unsigned int Salt_length,
	unsigned int Hash_type);

#endif
