#include <stdio.h>
#include <stdint.h>

/*
@   Security bits
@ 128 - 192 - 256
@     Rounds
@ 10    12    14   
*/

#define BLOCK_SIZE 16
#define xtime(x) (uint8_t)(((x) << 1) ^ ((((x) >> 7) & 1) * 0x1B)) 

// A possible error here is not parenthesising around each parameter in a #define statement
// clang -Wall -Werror -pedantic -O2 -flto test.c -o aesEnc

static const uint8_t sbox[] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
};
static const uint8_t inv_sbox[] = {
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
};
struct key_wrapper {
    uint8_t key[BLOCK_SIZE];
    uint8_t round_key[176];          // BLOCK_SIZE * 11
};
size_t _strlen(char* input){
    if(!input){
        return 0;
    }
    char* end = input;
    while(*(end)){
        end++;
    }
    return (size_t)(end - input);
}
void _memcpy(void *to, const void *from, size_t numBytes){
    char *d = to;
    const char *s = from;
    while (numBytes--)
        *d++ = *s++;
}
void _memset(void* ptr, int value, size_t num){
    unsigned char* d = ptr;
    while(num--){
        *d++ = value;
    }
}
void pcks7(uint8_t* input){
    size_t len = _strlen((char*)input);
    uint8_t byte = BLOCK_SIZE - len;
    _memset(input + len, byte, byte);
}
void inv_pcks7(uint8_t* input){
    short signature = input[BLOCK_SIZE - 1];
    if(signature > BLOCK_SIZE){
        return;
    }
    _memset(input + BLOCK_SIZE - signature, 0, signature);
}
void add_round_key(uint8_t* state, uint8_t* round_key){
    for(size_t i = 0; i < 4; i++){
        for(size_t j = 0; j < 4; j++){
            state[(i << 2) + j] ^= round_key[(i << 2) + j];
        }
    }
}
void sub_bytes(uint8_t* state, const uint8_t* sbox){
    for(size_t i = 0; i < 4; i++){
        for(size_t j = 0; j < 4; j++){
            state[(i << 2) + j] = sbox[state[(i << 2) + j]];
        }
    }
}
void shift_rows(uint8_t* state){
    uint8_t temp = state[1];
    state[1] = state[5];      // 1st row
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    temp = state[2];             // 2nd row
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    temp = state[3];             // 3rd row
    state[3] = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = temp;
}
void inv_shift_rows(uint8_t* state){
    uint8_t temp = state[13];   
    state[13] = state[9];                  // 1st row
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;
    temp = state[2];                         // 2nd row
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    temp = state[3];                         // 3rd row
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp; 
}
void mix_columns(uint8_t* state){
    uint8_t t = 0;
    uint8_t u = 0;
    for(int i = 0; i < 4; i++){
        u = state[i << 2];
        t = state[i << 2] ^ state[(i << 2) + 1] ^ state[(i << 2) + 2] ^ state[(i << 2) + 3];
        state[(i << 2)] ^= t ^ xtime(state[(i << 2)] ^ state[(i << 2) + 1]);
        state[(i << 2) + 1] ^= t ^ xtime(state[(i << 2) + 1] ^ state[(i << 2) + 2]);
        state[(i << 2) + 2] ^= t ^ xtime(state[(i << 2) + 2] ^ state[(i << 2) + 3]);
        state[(i << 2) + 3] ^= t ^ xtime(state[(i << 2) + 3] ^ u);
    }
}
void inv_mix_columns(uint8_t* state){
    uint8_t u = 0;
    uint8_t v = 0;
    for(int i = 0; i < 4; i++){
        u = xtime(xtime(state[(i << 2)] ^ state[(i << 2) + 2]));
        v = xtime(xtime(state[(i << 2) + 1] ^ state[(i << 2) + 3]));
        state[(i << 2)] ^= u;
        state[(i << 2) + 1] ^= v;
        state[(i << 2) + 2] ^= u;
        state[(i << 2) + 3] ^= v;
    }
    mix_columns(state);
}
void key_expansion(uint8_t* key, uint8_t* round_key){
    const uint8_t r_con[] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
    uint8_t operand[4] = {0};
    uint8_t pidx = 0;
    uint8_t nidx = 0;
    _memcpy(round_key, key, BLOCK_SIZE);
    for(size_t i = 4; i < 44; i++){             // BLOCK_SIZE/4*11
        pidx = (i - 1) << 2;                    // multiply by 4
        nidx = i << 2;                          // multiply by 4
        operand[0] = round_key[pidx+0];
        operand[1] = round_key[pidx+1];
        operand[2] = round_key[pidx+2];
        operand[3] = round_key[pidx+3];
        if(!(i & 0x3)){                         // check if multiple of 4   this is RotWord
           const uint8_t temp = operand[0];
            operand[0] = operand[1];
            operand[1] = operand[2];
            operand[2] = operand[3];
            operand[3] = temp;
            // Sub bytes
            operand[0] = sbox[operand[0]];
            operand[1] = sbox[operand[1]];
            operand[2] = sbox[operand[2]];
            operand[3] = sbox[operand[3]];
            operand[0] ^= r_con[i >> 2];        // this is Rcon  i/4
        }
        round_key[nidx+0] = round_key[pidx - 12] ^ operand[0];
        round_key[nidx+1] = round_key[pidx - 11] ^ operand[1];
        round_key[nidx+2] = round_key[pidx - 10] ^ operand[2];
        round_key[nidx+3] = round_key[pidx -  9] ^ operand[3];
    }  
}
void encrypt(uint8_t* data, struct key_wrapper* keys){
    for(size_t i = 0; i < BLOCK_SIZE; i++){
        data[i] ^= keys->key[i];
    }
    for(size_t i = 1; i < 10; i++){
        sub_bytes(data, sbox);
        shift_rows(data);
        mix_columns(data);
        add_round_key(data, keys->round_key + (i * BLOCK_SIZE));
    }
    sub_bytes(data, sbox);
    shift_rows(data);
    add_round_key(data, keys->round_key + (10 * BLOCK_SIZE));
}
void decrypt(uint8_t* data, struct key_wrapper* keys){
    add_round_key(data, keys->round_key + (10 * BLOCK_SIZE));
    inv_shift_rows(data);
    sub_bytes(data, inv_sbox);
    for(size_t i = 9; i > 0; i--){
        add_round_key(data, keys->round_key + (i * BLOCK_SIZE));
        inv_mix_columns(data);
        inv_shift_rows(data);
        sub_bytes(data, inv_sbox);
    }
    add_round_key(data, keys->key);
}

int main(int argc, char** argv){
    if(argc != 2){
        printf("Usage: %s {key}\n", argv[0]);
        return -1;
    }
    if(_strlen(argv[1]) != BLOCK_SIZE){
        printf("Key must be %d bytes long, currently is %lu\n", BLOCK_SIZE, _strlen(argv[1]));
        return -1;
    }
    uint8_t input[BLOCK_SIZE+1] = {0};
    struct key_wrapper key_wrapper = {0};
    _memcpy(key_wrapper.key, (uint8_t*)argv[1], BLOCK_SIZE);
    key_expansion(key_wrapper.key, key_wrapper.round_key);
    printf("Enter in a block of 16 characters to encrypt: ");    
    if(!fgets((char*)input, sizeof(input), stdin)){
        perror("Failed to read input");
        return -1;
    }
    size_t len = _strlen((char*)input);
    if(len < BLOCK_SIZE){
        input[len-1] = '\0'; 
    }else{
        input[len] = '\0'; 
    }
    printf("Original input: '%s' with length of: %lu\n", input, _strlen((char*)input));
    pcks7(input);
    encrypt(input, &key_wrapper);
    printf("Encrypted text: %s\n", input);
    decrypt(input, &key_wrapper);
    inv_pcks7(input);
    printf("If this is the same as the input, the encryption worked\n--> '%s' with the length of %lu\n", input, _strlen((char*)input));
}



/**
 * @brief 
 * 
 * {0, 1, 2, 3,
 *  4, 5, 6, 7,
 *  8, 9, a, b,
 *  c, d, e, f}
 * 
 * {0:0, 0:1, 0:2, 0:3}
 * {1:0, 1:1, 1:2, 1:3}
 * {2:0, 2:1, 2:2, 2:3}
 * {3:0, 3:1, 3:2, 3:3}
 * 
 * 
 */
