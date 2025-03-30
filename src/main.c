#include <stdio.h>
#include "../include/lib.h"

// clang -Wall -Werror -pedantic -O2 -flto main.c lib.c -o ../aesEnc

int main(void){
    struct key_wrapper keys = {0};
    uint8_t key[BLOCK_SIZE] = {0x6b,0x3c,0x33,0x09,0x39,0x43,0xf2,0xa0,0xde,0xa6,0xfc,0x94,0xda,0x56,0xf9,0x91};
    uint8_t data[BLOCK_SIZE] = "hello world!";
    _memcpy(keys.key, key, BLOCK_SIZE);
    key_expansion(keys.round_key, keys.round_key);
    encrypt(data, &keys);
    printf("%s\n", data);
    decrypt(data, &keys);
    printf("%s\n", data);
    return 0;
}
