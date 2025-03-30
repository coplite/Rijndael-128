#include "../include/lib.h"
/*
@   Security bits
@ 128 - 192 - 256
@     Rounds
@ 10    12    14   
*/

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
void bytes_matrix(uint8_t* input, uint8_t matrix[4][4]){
    short index = 0;
    for(size_t i = 0; i < 4; i++){
        for(size_t j = 0; j < 4; j++){
            matrix[i][j] = input[index++];
        }
    }
}
void matrix_bytes(uint8_t* input, uint8_t matrix[4][4]){
    short index = 0;
    for(size_t i = 0; i < 4; i++){
        for(size_t j = 0; j < 4; j++){
            input[index++] = matrix[i][j];
        }
    }
}
void add_round_key(uint8_t state[4][4], uint8_t* round_key){
    for(size_t i = 0; i < 4; i++){
        for(size_t j = 0; j < 4; j++){
            state[i][j] ^= round_key[(i << 2) + j];
        }
    }
}
void sub_bytes(uint8_t state[4][4], const uint8_t* sbox){
    for(size_t i = 0; i < 4; i++){
        for(size_t j = 0; j < 4; j++){
            state[i][j] = sbox[state[i][j]];
        }
    }
}
void shift_rows(uint8_t state[4][4]){
    uint8_t temp = state[0][1];
    state[0][1] = state[1][1];      // 1st row
    state[1][1] = state[2][1];
    state[2][1] = state[3][1];
    state[3][1] = temp;
    temp = state[0][2];             // 2nd row
    state[0][2] = state[2][2];
    state[2][2] = temp;
    temp = state[1][2];
    state[1][2] = state[3][2];
    state[3][2] = temp;
    temp = state[0][3];             // 3rd row
    state[0][3] = state[3][3];
    state[3][3] = state[2][3];
    state[2][3] = state[1][3];
    state[1][3] = temp;
}
void inv_shift_rows(uint8_t state[4][4]){
    uint8_t temp = state[3][1];   
    state[3][1] = state[2][1];                  // 1st row
    state[2][1] = state[1][1];
    state[1][1] = state[0][1];
    state[0][1] = temp;
    temp = state[0][2];                         // 2nd row
    state[0][2] = state[2][2];
    state[2][2] = temp;
    temp = state[1][2];
    state[1][2] = state[3][2];
    state[3][2] = temp;
    temp = state[0][3];                         // 3rd row
    state[0][3] = state[1][3];
    state[1][3] = state[2][3];
    state[2][3] = state[3][3];
    state[3][3] = temp; 
}
void mix_columns(uint8_t state[4][4]){
    uint8_t t = 0;
    uint8_t u = 0;
    for(int i = 0; i < 4; i++){
        u = state[i][0];
        t = state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3];
        state[i][0] ^= t ^ xtime(state[i][0] ^ state[i][1]);
        state[i][1] ^= t ^ xtime(state[i][1] ^ state[i][2]);
        state[i][2] ^= t ^ xtime(state[i][2] ^ state[i][3]);
        state[i][3] ^= t ^ xtime(state[i][3] ^ u);
    }
}
void inv_mix_columns(uint8_t state[4][4]){
    uint8_t u = 0;
    uint8_t v = 0;
    for(int i = 0; i < 4; i++){
        u = xtime(xtime(state[i][0] ^ state[i][2]));
        v = xtime(xtime(state[i][1] ^ state[i][3]));
        state[i][0] ^= u;
        state[i][1] ^= v;
        state[i][2] ^= u;
        state[i][3] ^= v;
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
        operand[0] = round_key[pidx + 0];
        operand[1] = round_key[pidx + 1];
        operand[2] = round_key[pidx + 2];
        operand[3] = round_key[pidx + 3];
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
    uint8_t state[4][4] = {0};
    bytes_matrix(data, state);
    for(size_t i = 1; i < 10; i++){
        sub_bytes(state, sbox);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, keys->round_key + (i * BLOCK_SIZE));
    }
    sub_bytes(state, sbox);
    shift_rows(state);
    add_round_key(state, keys->round_key + (10 * BLOCK_SIZE));
    matrix_bytes(data, state);
}
void decrypt(uint8_t* data, struct key_wrapper* keys){
    uint8_t state[4][4] = {0};
    bytes_matrix(data, state);
    add_round_key(state, keys->round_key + (10 * BLOCK_SIZE));
    inv_shift_rows(state);
    sub_bytes(state, inv_sbox);
    for(size_t i = 9; i > 0; i--){
        add_round_key(state, keys->round_key + (i * BLOCK_SIZE));
        inv_mix_columns(state);
        inv_shift_rows(state);
        sub_bytes(state, inv_sbox);
    }
    add_round_key(state, keys->key);
    matrix_bytes(data, state);
}
