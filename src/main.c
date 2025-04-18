#include <stdio.h>
#include <stdlib.h>
#include "../include/lib.h"

// clang -Wall -Werror -pedantic -O2 -flto main.c lib.c -o aesEnc
/**
 * @brief interesting notes
 * The reason on line 27 there is a +1 behind the buffer
 * is to accomodate for the null characters
 * since the char* starts at 0 and with the buffer
 * being 2 the one at index 0 will fit the 1st char
 * and the index 1 will fit the nullterminator since fgets prepends that
 * and we increase by the extension which is added by buffer which is +2(can grow)
 * this means that we will be at index 2 at the next iteration and then this would mean
 * we are past our nullbyte terminator
 * @return int 
**/
/*
@   Security bits
@ 128 - 192 - 256
@     Rounds
@ 10    12    14   

Pro bittwiddle hack:

To get the remainder of the number with bitwise operations you can use the AND operator
normally:  x % y = z
smartery: x & (y-1) = z
reason i >> 4 works is because l value isnt going beyond 16 and 16 >> 4 is the only value thats nonzero

Documentation time~~

Ermmmm look at lib.c and lib.h for your functions

aes_ctr_xcryption() can go wildd as how ever much as you want

while for aes_encrypt() and aes_decrypt() you need to call pkcs7() to pad the text and have it unpad by inv_pkcs7()
*/
char full_read(char* input, size_t init_size, size_t buffer){
    size_t extension = 0;
    size_t last_extension = 0;
    while(fgets(input + extension, buffer + 1, stdin)){
        last_extension = _strlen(input + extension);
        if(*(input + extension + last_extension - 1) == '\n'){
            *(input + extension + last_extension - 1) = '\0';
            char* tmp = (char*)realloc(input, _strlen(input));
            if(!tmp)
                return 0;
            input = tmp;
            return 1;
        }
        extension += buffer;
        buffer <<= 1;
        char* tmp = (char*)realloc(input, (init_size + extension + buffer));
        if(!tmp)
            return 0;
        input = tmp;
    }
    return 0;
}
int main(void){
    key_wrapper keys = {0};
    uint8_t key[BLOCK_SIZE] =   { 0x6b, 0x3c, 0x33, 0x09, 0x39, 0x43, 0xf2, 0xa0, 0xde, 0xfc, 0xfc, 0x94, 0xda, 0x56, 0xf9, 0x91 };
    uint8_t nonce[BLOCK_SIZE] = { 0x53, 0x48, 0x83, 0xEC, 0x08, 0x49, 0xBA, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, 0x41 };

    char* data = (char*)calloc(0, sizeof(char));
    if(!data){
        perror("[-] Failed to allocate initial memory!\n");
        return -1;
    }
    printf("Enter in data to encrypt: ");
    if(!full_read(data, 0, 8)){
        free(data);
        perror("[-] Failed to read in from stdin!\n");
        return -1;
    }
    
    //pcks7(data);
    _memcpy(keys.key, key, BLOCK_SIZE);
    _memcpy(keys.nonce, nonce, BLOCK_SIZE);

    key_expansion(keys.round_key, keys.round_key);

    printf("'%s' with the length of %lu\n", data, _strlen((char*)data));

    aes_ctr_xcryption((uint8_t*)data, &keys);
    printf("'%s' with the length of %lu\n", data, _strlen((char*)data));
    
    aes_ctr_xcryption((uint8_t*)data, &keys);
    //inv_pcks7(data);

    printf("'%s' with the length of %lu\n", data, _strlen((char*)data));
    return 0;
}
