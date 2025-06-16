# BROCM (Block cipher and Random number generator Open Cryptographic Module)

## 프로젝트 개요
BROCM은 2025년도 국민대학교 사이버보안학과 암호알고리즘 수업의 일환으로 개발된 암호 모듈 기반의 암복호화 프로그램입니다.

## 암호모듈에 구현된 암호 알고리즘

### 블록 암호
- ARIA (Academy, Research Institute, Agency)
- LEA (Lightweight Encryption Algorithm)

### 운영 모드
- ECB (Electronic Codebook)
- CBC (Cipher Block Chaining)
- CTR (Counter)
- CCM (Counter with CBC-MAC)
- GCM (Galois/Counter Mode)

### 해시 함수
- SHA2 (Secure Hash Algorithm 2)
  - SHA-224
  - SHA-256
  - SHA-384
  - SHA-512

### 메시지 인증
- HMAC (Hash-based Message Authentication Code)
  - HMAC-SHA224
  - HMAC-SHA256
  - HMAC-SHA384
  - HMAC-SHA512

### 난수 발생기
- CTR-DRBG (Counter Mode Deterministic Random Bit Generator)
  - ARIA-128-CTR 기반

### 키 관리
- 키 유도: PBKDF (Password-Based Key Derivation Function)
  - HMAC 기반
- 키 설정: 
  - ECDH (Elliptic Curve Diffie-Hellman)
  - DH (Diffie-Hellman)

### 공개키 암호
- RSA-OAEP (RSA Optimal Asymmetric Encryption Padding)

### 전자서명
- RSA-PSS (RSA Probabilistic Signature Scheme)

## 대용량 파일 암호화 유틸리티 (encdec)

### 주요 특징
- 대용량 파일 처리 (4GB 이상 지원)
- 64MB 청크 단위 처리로 메모리 효율성 확보
- ARIA-128-CTR 모드 사용
- PBKDF2-HMAC-SHA256 기반 키 유도
- 파일별 고유 salt와 nonce 사용

### 파일 구조
```
[암호화된 파일 구조]
+----------------+----------------+------------------+
|     Salt       |    Nonce      |  암호화된 데이터  |
|    (32바이트)   |   (16바이트)   |                  |
+----------------+----------------+------------------+
```

### 빌드 및 설치
```bash
make
```

### 사용 방법
```bash
./encdec <enc/dec> <password> <input_file> <output_file>
```

#### 매개변수
- `enc/dec`: 암호화 또는 복호화 모드
- `password`: 8자 이상의 비밀번호
- `input_file`: 입력 파일 경로
- `output_file`: 출력 파일 경로

#### 예시
```bash
# 파일 암호화
./encdec enc mypassword input.txt encrypted.bin

# 파일 복호화
./encdec dec mypassword encrypted.bin decrypted.txt
```

### 특징
1. 키 관리
   - PBKDF2-HMAC-SHA256으로 32바이트 DEK 생성
   - 100,000회 반복으로 키 강화
   - 사용 후 메모리에서 안전하게 제거

2. 암호화
   - ARIA-128-CTR 모드 사용
   - 파일별 고유 salt (32바이트)
   - 파일별 고유 nonce (16바이트)
   - 32바이트 정렬된 블록 단위 처리


## 연락처
- 소속: 국민대학교 사이버보안학과
- 이메일: gudduq159@kookmin.ac.kr
