#include <stdio.h>
#include "../include/lib.h"

// clang -Wall -Werror -pedantic -O2 -flto main.c lib.c -o aesEnc

int main(void){
    key_wrapper keys = {0};
    uint8_t key[BLOCK_SIZE] =   { 0x6b, 0x3c, 0x33, 0x09, 0x39, 0x43, 0xf2, 0xa0, 0xde, 0xfc, 0xfc, 0x94, 0xda, 0x56, 0xf9, 0x91 };
    uint8_t nonce[BLOCK_SIZE] = { 0x53, 0x48, 0x83, 0xEC, 0x08, 0x49, 0xBA, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0x41 };

    uint8_t data[] = "What the fuck is thisssss"; // 16

    //pcks7(data);
    _memcpy(keys.key, key, BLOCK_SIZE);
    _memcpy(keys.nonce, nonce, BLOCK_SIZE);

    key_expansion(keys.round_key, keys.round_key);

    printf("'%s' with the length of %lu\n", data, _strlen((char*)data));

    aes_ctr_xcryption(data, &keys);
    printf("'%s' with the length of %lu\n", data, _strlen((char*)data));

    aes_ctr_xcryption(data, &keys);
    //inv_pcks7(data);

    printf("'%s' with the length of %lu\n", data, _strlen((char*)data));
    return 0;
}

/*
@   Security bits
@ 128 - 192 - 256
@     Rounds
@ 10    12    14   

Documentation time~~

Ermmmm look at lib.c and lib.h for your functions

aes_ctr_xcryption() can go wildd as how ever much as you want

while for aes_encrypt() and aes_decrypt() you need to call pkcs7() to pad the text and have it unpad by inv_pkcs7()
*/
