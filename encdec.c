/*
 * Copyright (c) 2024 Kookmin University
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: gudduq159@kookmin.ac.kr
 * Department of Cybersecurity, Kookmin University
 *
 * 파일 암/복호화 처리 단위 정보
 * ---------------------------
 * 1. 파일 처리 단위 (File Processing Units)
 *    - 청크 단위 (CHUNK_SIZE): 64MB (64 * 1024 * 1024 bytes)
 *    - 메모리 버퍼 크기: CHUNK_SIZE + 정렬 패딩(31) + 여유 공간(64)
 *    - 4GB 이상 파일: off_t 타입(64비트)으로 처리, 64MB 청크 단위로 순차 처리
 *
 * 2. 암호화 처리 단위 (Encryption Processing Units)
 *    - 블록 최대 크기: BROCM_BLOCK_CHAR_MAX_LEN - 1000 bytes
 *    - 실제 처리 크기: 32바이트 정렬 (aligned_size = (current_block + 31) & ~31)
 *    - 암호화 입출력: 4바이트 단위(word) 처리 (byte2word/word2byte 변환)
 *
 * 3. 메모리 사용 (Memory Usage per Chunk)
 *    - 원본 데이터 버퍼: CHUNK_SIZE (64MB)
 *    - 정수 변환 버퍼: ((CHUNK_SIZE + 31) & ~31) + 64) * 2 (입력/출력용)
 *    - 추가 메모리: salt(32B), nonce(16B), key(32B) 등
 *
 * 4. 파일 구조 (Encrypted File Structure)
 *    - 헤더: salt(32B) + CTR nonce(16B) = 48B
 *    - 데이터: 암호화된 원본 데이터
 *
 * 5. 키/Salt/CTR 관리 구조 (Key/Salt/CTR Management)
 *    - 키 생성: PBKDF2-HMAC-SHA256(password, salt, 100000회)로 32바이트 DEK 생성
 *    - Salt 관리: 파일별 32바이트 랜덤 salt 생성, 파일 헤더에 저장
 *    - CTR Nonce: 파일별 16바이트 랜덤 nonce 생성, 파일 헤더에 저장
 *    - 메모리 보안: 키 관련 메모리는 사용 후 secure_zero_memory()로 안전하게 삭제
 */

#define _FILE_OFFSET_BITS 64
#define _LARGEFILE64_SOURCE
#define _LARGEFILE_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <time.h>

#include "../brocm_header/brocm_define.h"
#include "../brocm_header/brocm_extern.h"
#include "../brocm_header/brocm_return.h"

#define RED_COLOR     "\x1b[31m"
#define GREEN_COLOR   "\x1b[32m"
#define BLUE_COLOR    "\x1b[34m"
#define YELLOW_COLOR  "\x1b[33m"
#define RESET_COLOR   "\x1b[0m"

// 청크 크기 정의 (64MB)
#define CHUNK_SIZE (64 * 1024 * 1024)

// 진행률 표시 함수
void print_progress(off_t processed, off_t total) {
    double percentage = (double)processed * 100.0 / total;
    printf("%s\r[encdec] Progress: %.1f%% (%lld/%lld bytes)%s", 
           YELLOW_COLOR, percentage, (long long)processed, (long long)total, RESET_COLOR);
    fflush(stdout);
}

void secure_zero_memory(void *data, size_t size) {
    if (!data || size == 0) {
        return;
    }

    volatile unsigned char *p = (volatile unsigned char *)data;

    for (int i = 0; i < 3; i++) {
        for (size_t j = 0; j < size; j++) {
            p[j] = 0;
        }
    }
}


unsigned int byte2word(unsigned int* dest, unsigned char* src, unsigned int src_length) {
    unsigned int i = 0;
    unsigned int remain = 0;

    for (i = 0; i < src_length; i++) {
        remain = i % 4;

        if (remain == 0)
            dest[i / 4] = ((unsigned int)src[i] << 24);
        else if (remain == 1)   
            dest[i / 4] ^= ((unsigned int)src[i] << 16);
        else if (remain == 2)
            dest[i / 4] ^= ((unsigned int)src[i] << 8);
        else
            dest[i / 4] ^= ((unsigned int)src[i]);
    }

    return 0;
}

unsigned int word2byte(unsigned char* dest, unsigned int* src, unsigned int src_length) {
    unsigned int i = 0;
    unsigned int remain = 0;

    for (i = 0; i < src_length; i++) {
        remain = i % 4;
        if (remain == 0)
            dest[i] = (unsigned char)(src[i / 4] >> 24);
        else if (remain == 1)
            dest[i] = (unsigned char)(src[i / 4] >> 16);
        else if (remain == 2)
            dest[i] = (unsigned char)(src[i / 4] >> 8);
        else
            dest[i] = (unsigned char)(src[i / 4]);
    }
    return 0;
}

int main(int argc, char *argv[])
{
	char *mode;                  
	char *password;             
	char *input_file;           
	char *output_file;          
	clock_t start_time, end_time;
	double cpu_time_used;

	FILE *fp_in;                
	FILE *fp_out;               

	unsigned char salt[32];              
	unsigned char dec_ctr_nonce[16];     
	unsigned char dek[32];               
	unsigned char enc_ctr_nonce[16];     

	unsigned int dek_int[8];             

	unsigned char *chunk_buffer;         
	unsigned int *input_chunk_int;       
	unsigned int *output_chunk_int;      

	unsigned int ret;                    
	off_t file_size;              
	off_t processed_size;         
	size_t chunk_size;           
	size_t buf_size;                     
	size_t i;                     // int를 size_t로 변경

	unsigned int block_size;             
	unsigned int remaining;              
	off_t offset;                 // unsigned int를 off_t로 변경
	unsigned int current_block;          
	unsigned int aligned_size;           

	/*
	*	파라미터 유효성 검증
	*/
	if (argc != 5) {
		printf(RED_COLOR "[encdec] Usage: %s <enc/dec> <password> <input_file> <output_file>\n" RESET_COLOR, argv[0]);
		return -1;
	}

	mode = argv[1];
	
	if (strlen(argv[2]) < 8) {
		printf(RED_COLOR "[encdec] Password must be at least 8 characters long\n" RESET_COLOR);
		return -1;
	}
	
	size_t password_len = strlen(argv[2]);
	password = (char*)malloc(password_len + 1);
	if (!password) {
		printf("[encdec] Failed to allocate memory for password\n");
		return -1;
	}
	
	for(i = 0; i < password_len; i++) {
		if(!isprint((unsigned char)argv[2][i])) {
			printf("[encdec] Password contains invalid characters\n");
			free(password);
			return -1;
		}
	}
	
	memcpy(password, argv[2], password_len);
	password[password_len] = '\0';
	secure_zero_memory(argv[2], password_len);

	input_file = argv[3];
	output_file = argv[4];


	if (strcmp(mode, "enc") != 0 && strcmp(mode, "dec") != 0) {
		printf(RED_COLOR "[encdec] Invalid mode. Use 'enc' or 'dec'\n" RESET_COLOR);
		secure_zero_memory(password, password_len);
		free(password);
		return -1;
	}

	if (strlen(password) == 0) {
		printf(RED_COLOR "[encdec] Password cannot be empty\n" RESET_COLOR);
		secure_zero_memory(password, password_len);
		free(password);
		return -1;
	}
	/*
	*	enc : salt || ctr 을 파일 헤더에서 읽음
	*	dec : salt, ctr 생성
	*/
	if (strcmp(mode, "enc") == 0) {
		start_time = clock();
		// salt 생성
		ret = brocm_gen_rn(salt, 32);
		if (ret != BROCM_GEN_RN_SUCCESS) {
			printf(RED_COLOR "[encdec] brocm_gen_rn() failed with error 0x%08x\n" RESET_COLOR, ret);
			secure_zero_memory(password, password_len);
			free(password);
			return -1;
		}

		// CTR nonce 생성
		if (brocm_gen_rn(enc_ctr_nonce, 16) != BROCM_GEN_RN_SUCCESS) {
			printf(RED_COLOR "[encdec] Failed to generate encryption CTR nonce\n" RESET_COLOR);
			secure_zero_memory(password, password_len);
			secure_zero_memory(dek, 32);
			free(password);
			return -1;
		}

		// salt로 dek 생성
		ret = brocm_pbkdf(dek, 32*8,
						(unsigned char*)password, password_len, 
						salt, 32, 
						100000, 
						BROCM_HASH_SHA256);

		if (ret != BROCM_PBKDF_SUCCESS) {
			printf(RED_COLOR "[encdec] brocm_pbkdf for dek generation failed with error 0x%08x\n" RESET_COLOR, ret);
			secure_zero_memory(password, password_len);
			secure_zero_memory(dek, 32);
			free(password);
			return -1;
		}

		byte2word(dek_int, dek, 32);

		// 입력 파일 크기 확인
		fp_in = fopen(input_file, "rb");
		if (!fp_in) {
			printf(RED_COLOR "[encdec] Failed to open input file\n" RESET_COLOR);
			secure_zero_memory(password, password_len);
			secure_zero_memory(dek, 32);
			fclose(fp_in);
			free(password);
			return -1;
		}

		// fseek/ftell 대신 fseeko/ftello 사용
		if (fseeko(fp_in, 0, SEEK_END) != 0) {
			printf(RED_COLOR "[encdec] Failed to seek input file\n" RESET_COLOR);
			secure_zero_memory(password, password_len);
			secure_zero_memory(dek, 32);
			fclose(fp_in);
			free(password);
			return -1;
		}
		
		file_size = ftello(fp_in);
		if (file_size == -1) {
			printf(RED_COLOR "[encdec] Failed to get file size\n" RESET_COLOR);
			secure_zero_memory(password, password_len);
			secure_zero_memory(dek, 32);
			fclose(fp_in);
			free(password);
			return -1;
		}
		
		if (fseeko(fp_in, 0, SEEK_SET) != 0) {
			printf(RED_COLOR "[encdec] Failed to seek input file\n" RESET_COLOR);
			secure_zero_memory(password, password_len);
			secure_zero_memory(dek, 32);
			fclose(fp_in);
			free(password);
			return -1;
		}

		// 출력 파일 열기
		fp_out = fopen(output_file, "wb");
		if (!fp_out) {
			printf(RED_COLOR "[encdec] Failed to open output file\n" RESET_COLOR);
			secure_zero_memory(password, password_len);
			secure_zero_memory(dek, 32);
			fclose(fp_in);
			free(password);
			return -1;
		}

		// 파일 헤더 작성 (salt || CTR nonce)
		if (fwrite(salt, 1, 32, fp_out) != 32 ||
			fwrite(enc_ctr_nonce, 1, 16, fp_out) != 16) {
			printf(RED_COLOR "[encdec] Failed to write file header\n" RESET_COLOR);
			secure_zero_memory(password, password_len);
			secure_zero_memory(dek, 32);
			fclose(fp_in);
			fclose(fp_out);
			free(password);
			return -1;
		}

		// 청크 버퍼 할당
		chunk_buffer = (unsigned char *)malloc(CHUNK_SIZE);
		buf_size = ((CHUNK_SIZE + 31) & ~31) + 64;
		input_chunk_int = (unsigned int *)calloc(buf_size / 4, sizeof(unsigned int));
		output_chunk_int = (unsigned int *)calloc(buf_size / 4, sizeof(unsigned int));

		if (!chunk_buffer || !input_chunk_int || !output_chunk_int) {
			printf(RED_COLOR "[encdec] Failed to allocate memory for buffers\n" RESET_COLOR);
			secure_zero_memory(password, password_len);
			secure_zero_memory(dek, 32);
			if (chunk_buffer) free(chunk_buffer);
			if (input_chunk_int) free(input_chunk_int);
			if (output_chunk_int) free(output_chunk_int);
			fclose(fp_in);
			fclose(fp_out);
			free(password);
			return -1;
		}

		// 청크 단위로 암호화 처리
		processed_size = 0;
		while (processed_size < file_size) {
			// 현재 청크 크기 계산
			chunk_size = (file_size - processed_size) < CHUNK_SIZE ? 
						(file_size - processed_size) : CHUNK_SIZE;

			// 청크 읽기
			if (fread(chunk_buffer, 1, chunk_size, fp_in) != chunk_size) {
				printf(RED_COLOR "[encdec] Failed to read input file\n" RESET_COLOR);
				secure_zero_memory(password, password_len);
				secure_zero_memory(dek, 32);
				free(chunk_buffer);
				free(input_chunk_int);
				free(output_chunk_int);
				fclose(fp_in);
				fclose(fp_out);
				free(password);
				return -1;
			}

			// byte to word 변환
			byte2word(input_chunk_int, chunk_buffer, chunk_size);

			// 청크 암호화
			block_size = BROCM_BLOCK_CHAR_MAX_LEN-1000;
			remaining = chunk_size;
			offset = 0;

			while (remaining > 0) {
				current_block = (remaining > block_size) ? block_size : remaining;
				aligned_size = (current_block + 31) & ~31;

				ret = brocm_bc_encrypt(output_chunk_int + (offset/4),
									NULL, 0,
									input_chunk_int + (offset/4), aligned_size,
									enc_ctr_nonce, 16,
									NULL, 0,
									dek_int, 32,
									BROCM_ALGO_ARIA,
									BROCM_MODE_CTR);

				if (ret != BROCM_ENCRYPT_BC_SUCCESS) {
					printf(RED_COLOR "[encdec] brocm_bc_encrypt failed with error %d (0x%x) at offset %lu\n" RESET_COLOR, 
						   ret, ret, (unsigned long)(offset + processed_size));
					secure_zero_memory(password, password_len);
					secure_zero_memory(dek, 32);
					free(chunk_buffer);
					free(input_chunk_int);
					free(output_chunk_int);
					fclose(fp_in);
					fclose(fp_out);
					free(password);
					return -1;
				}

				offset += current_block;
				remaining -= current_block;
			}

			// word to byte 변환
			word2byte(chunk_buffer, output_chunk_int, chunk_size);

			// 암호화된 청크 쓰기
			if (fwrite(chunk_buffer, 1, chunk_size, fp_out) != chunk_size) {
				printf(RED_COLOR "\n[encdec] Failed to write encrypted data\n" RESET_COLOR);
				secure_zero_memory(password, password_len);
				secure_zero_memory(dek, 32);
				free(chunk_buffer);
				free(input_chunk_int);
				free(output_chunk_int);
				fclose(fp_in);
				fclose(fp_out);
				free(password);
				return -1;
			}

			processed_size += chunk_size;
			print_progress(processed_size, file_size);
		}

		free(chunk_buffer);
		free(input_chunk_int);
		free(output_chunk_int);
		fclose(fp_in);
		fclose(fp_out);

		printf("\n" RESET_COLOR "[encdec] File encryption completed successfully: %s -> %s (%zu bytes)\n" RESET_COLOR, 
			   input_file, output_file, file_size);
		
		end_time = clock();
		cpu_time_used = ((double) (end_time - start_time)) / CLOCKS_PER_SEC;
		printf(GREEN_COLOR "[encdec] Total processing time: %.2f seconds\n" RESET_COLOR, cpu_time_used);

	} else {  // dec mode
		start_time = clock();
		// 입력 파일 열기
		fp_in = fopen(input_file, "rb");
		if (!fp_in) {
			printf(RED_COLOR "[encdec] Failed to open input file\n" RESET_COLOR);
			secure_zero_memory(password, password_len);
			free(password);
			return -1;
		}

		// 파일 크기 확인
		if (fseeko(fp_in, 0, SEEK_END) != 0) {
			printf(RED_COLOR "[encdec] Failed to seek input file\n" RESET_COLOR);
			secure_zero_memory(password, password_len);
			fclose(fp_in);
			free(password);
			return -1;
		}
		
		file_size = ftello(fp_in);
		if (file_size == -1) {
			printf(RED_COLOR "[encdec] Failed to get file size\n" RESET_COLOR);
			secure_zero_memory(password, password_len);
			fclose(fp_in);
			free(password);
			return -1;
		}
		
		if (fseeko(fp_in, 0, SEEK_SET) != 0) {
			printf(RED_COLOR "[encdec] Failed to seek input file\n" RESET_COLOR);
			secure_zero_memory(password, password_len);
			fclose(fp_in);
			free(password);
			return -1;
		}

		// 최소 파일 크기 검증 (salt + nonce = 48 bytes)
		if (file_size < 48) {
			printf(RED_COLOR "[encdec] Invalid encrypted file format\n" RESET_COLOR);
			secure_zero_memory(password, password_len);
			fclose(fp_in);
			free(password);
			return -1;
		}

		// 파일 헤더 읽기 (salt || CTR nonce)
		if (fread(salt, 1, 32, fp_in) != 32 ||
			fread(dec_ctr_nonce, 1, 16, fp_in) != 16) {
			printf(RED_COLOR "[encdec] Failed to read file header\n" RESET_COLOR);
			secure_zero_memory(password, password_len);
			fclose(fp_in);
			free(password);
			return -1;
		}

		// 실제 암호화된 데이터 크기 계산
		file_size -= 48;  // salt(32) + nonce(16) = 48 bytes

		// salt로 dek 생성
		ret = brocm_pbkdf(dek, 32*8,
						(unsigned char*)password, password_len, 
						salt, 32, 
						100000, 
						BROCM_HASH_SHA256);

		if (ret != BROCM_PBKDF_SUCCESS) {
			printf(RED_COLOR "[encdec] brocm_pbkdf for dek generation failed with error 0x%08x\n" RESET_COLOR, ret);
			secure_zero_memory(password, password_len);
			fclose(fp_in);
			free(password);
			return -1;
		}

		byte2word(dek_int, dek, 32);

		// 청크 버퍼 할당
		chunk_buffer = (unsigned char *)malloc(CHUNK_SIZE);
		buf_size = ((CHUNK_SIZE + 31) & ~31) + 64;
		input_chunk_int = (unsigned int *)calloc(buf_size / 4, sizeof(unsigned int));
		output_chunk_int = (unsigned int *)calloc(buf_size / 4, sizeof(unsigned int));

		if (!chunk_buffer || !input_chunk_int || !output_chunk_int) {
			printf(RED_COLOR "[encdec] Failed to allocate memory for buffers\n" RESET_COLOR);
			secure_zero_memory(password, password_len);
			secure_zero_memory(dek, 32);
			if (chunk_buffer) free(chunk_buffer);
			if (input_chunk_int) free(input_chunk_int);
			if (output_chunk_int) free(output_chunk_int);
			fclose(fp_in);
			free(password);
			return -1;
		}

		// 출력 파일 열기
		fp_out = fopen(output_file, "wb");
		if (!fp_out) {
			printf(RED_COLOR "[encdec] Failed to open output file\n" RESET_COLOR);
			secure_zero_memory(password, password_len);
			secure_zero_memory(dek, 32);
			free(chunk_buffer);
			free(input_chunk_int);
			free(output_chunk_int);
			fclose(fp_in);
			free(password);
			return -1;
		}

		// 청크 단위로 복호화 처리
		processed_size = 0;
		while (processed_size < file_size) {
			// 현재 청크 크기 계산
			chunk_size = (file_size - processed_size) < CHUNK_SIZE ? 
						(file_size - processed_size) : CHUNK_SIZE;

			// 청크 읽기
			if (fread(chunk_buffer, 1, chunk_size, fp_in) != chunk_size) {
				printf(RED_COLOR "[encdec] Failed to read input file\n" RESET_COLOR);
				secure_zero_memory(password, password_len);
				secure_zero_memory(dek, 32);
				free(chunk_buffer);
				free(input_chunk_int);
				free(output_chunk_int);
				fclose(fp_in);
				fclose(fp_out);
				free(password);
				return -1;
			}

			// byte to word 변환
			byte2word(input_chunk_int, chunk_buffer, chunk_size);

			// 청크 복호화
			block_size = BROCM_BLOCK_CHAR_MAX_LEN-1000;
			remaining = chunk_size;
			offset = 0;

			while (remaining > 0) {
				current_block = (remaining > block_size) ? block_size : remaining;
				aligned_size = (current_block + 31) & ~31;

				ret = brocm_bc_decrypt(output_chunk_int + (offset/4),
									input_chunk_int + (offset/4), aligned_size,
									NULL, 0,
									dec_ctr_nonce, 16,
									NULL, 0,
									dek_int, 32,
									BROCM_ALGO_ARIA,
									BROCM_MODE_CTR);

				if (ret != BROCM_DECRYPT_BC_SUCCESS) {
					printf(RED_COLOR "[encdec] brocm_bc_decrypt failed with error %d at offset %lu\n" RESET_COLOR, 
						   ret, (unsigned long)(offset + processed_size));
					secure_zero_memory(password, password_len);
					secure_zero_memory(dek, 32);
					free(chunk_buffer);
					free(input_chunk_int);
					free(output_chunk_int);
					fclose(fp_in);
					fclose(fp_out);
					free(password);
					return -1;
				}

				offset += current_block;
				remaining -= current_block;
			}

			// word to byte 변환
			word2byte(chunk_buffer, output_chunk_int, chunk_size);

			// 복호화된 청크 쓰기
			if (fwrite(chunk_buffer, 1, chunk_size, fp_out) != chunk_size) {
				printf(RED_COLOR "\n[encdec] Failed to write decrypted data\n" RESET_COLOR);
				secure_zero_memory(password, password_len);
				secure_zero_memory(dek, 32);
				free(chunk_buffer);
				free(input_chunk_int);
				free(output_chunk_int);
				fclose(fp_in);
				fclose(fp_out);
				free(password);
				return -1;
			}

			processed_size += chunk_size;
			print_progress(processed_size, file_size);
		}

		free(chunk_buffer);
		free(input_chunk_int);
		free(output_chunk_int);
		fclose(fp_in);
		fclose(fp_out);

		printf("\n" GREEN_COLOR "[encdec] File decryption completed successfully: %s -> %s (%zu bytes)\n" RESET_COLOR, 
			   input_file, output_file, file_size);

		end_time = clock();
		cpu_time_used = ((double) (end_time - start_time)) / CLOCKS_PER_SEC;
		printf(GREEN_COLOR "[encdec] Total processing time: %.2f seconds\n" RESET_COLOR, cpu_time_used);
	}

	secure_zero_memory(password, password_len);
	secure_zero_memory(dek, 32);
	free(password);
	// printf(RESET_COLOR "[encdec] File encryption/decryption utility completed successfully\n" RESET_COLOR);

	return 0;
}
