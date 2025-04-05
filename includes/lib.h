#pragma once

#include <stddef.h>
#include <stdint.h>

#define BLOCK_SIZE 16
#define xtime(x) (uint8_t)(((x) << 1) ^ ((((x) >> 7) & 1) * 0x1B)) 

typedef struct {
    uint8_t key[BLOCK_SIZE];
    uint8_t round_key[176];  // BLOCK_SIZE * 11 = 176 bytes
}key_wrapper;

void encrypt(uint8_t* data, key_wrapper* keys);
void decrypt(uint8_t* data, key_wrapper* keys);

void key_expansion(uint8_t* key, uint8_t* round_key);

void pcks7(uint8_t* input);
void inv_pcks7(uint8_t* input);

void _memcpy(void *to, const void *from, size_t numBytes);
void _memset(void* ptr, int value, size_t num);
size_t _strlen(char* input);
