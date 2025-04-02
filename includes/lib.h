#pragma once

#include <stddef.h>
#include <stdint.h>

#define BLOCK_SIZE 16
#define xtime(x) (uint8_t)(((x) << 1) ^ ((((x) >> 7) & 1) * 0x1B)) 

struct key_wrapper {
    uint8_t key[BLOCK_SIZE];
    uint8_t round_key[176];  // 16 * 11 = 176 bytes
};

void encrypt(uint8_t* data, struct key_wrapper* keys);
void decrypt(uint8_t* data, struct key_wrapper* keys);
void key_expansion(uint8_t* key, uint8_t* round_key);
void bytes_matrix(uint8_t* input, uint8_t matrix[4][4]);
void matrix_bytes(uint8_t* output, uint8_t matrix[4][4]);
void pcks7(uint8_t* input);
void inv_pcks7(uint8_t* input);
size_t _strlen(char* input);
void _memcpy(void *to, const void *from, size_t numBytes);
void _memset(void* ptr, int value, size_t num);
