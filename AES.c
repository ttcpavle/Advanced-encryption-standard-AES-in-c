#include <stdio.h>
#include <stdint.h>

//================================================================================================================
//Federal Information Processing Standards (FIPS) Publication 197 November 26, 2001 - Advanced encryption standard
// https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf
//================================================================================================================

#define AES128 // define AES256, AES192 or AES128 (depending on preferred key size)
#define Nb 4 // number of columns (32bit words) in State

#ifdef AES256
#define Nk 8 // number of 32bit words in cipher key
#define Nr 14 // number of rounds
#elif defined AES192
#define Nk 6
#define Nr 12
#elif defined AES128
#define Nk 4
#define Nr 10
#endif

typedef uint8_t Byte;
typedef uint8_t State[Nb][4];

// pre-computed Rijndael s-box
static const Byte sbox[256] = {
    // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,  // 0
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,  // 1
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,  // 2
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,  // 3
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,  // 4
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,  // 5
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,  // 6
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,  // 7
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,  // 8
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,  // 9
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,  // A
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,  // B
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,  // C
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,  // D
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,  // E
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16   // F
};

//pre-computed inverse s-box
static const Byte isbox[256] = {
    // 0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,  // 0
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,  // 1
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,  // 2
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,  // 3
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,  // 4
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,  // 5
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,  // 6
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,  // 7
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,  // 8
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,  // 9
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,  // A
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,  // B
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,  // C
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,  // D
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,  // E
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d   // F
};

//pre-computed round constants for key expansion
static const Byte Rcon[11] = { 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

// key examples from Appendix A
#ifdef AES256
Byte key[4 * Nk] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4, };
#elif defined AES192
Byte key[4 * Nk] = { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
#elif defined AES128
Byte key[4 * Nk] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
#endif

static inline Byte xtime(Byte x) {
	return ((x << 1) ^ ((x >> 7) & 1) * 0x1b);
}

// by using xtime() we make sure to stay within the GF(2^8)
static Byte galoisMultiply(Byte x, Byte y) {
    return ((y & 1) * x) ^
        ((y >> 1 & 1) * xtime(x)) ^
        ((y >> 2 & 1) * xtime(xtime(x))) ^
        ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
        ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))) ^
        ((y >> 5 & 1) * xtime(xtime(xtime(xtime(xtime(x)))))) ^
        ((y >> 6 & 1) * xtime(xtime(xtime(xtime(xtime(xtime(x))))))) ^
        ((y >> 7 & 1) * xtime(xtime(xtime(xtime(xtime(xtime(xtime(x))))))));
}

Byte getSboxValue(Byte x) {
    return sbox[x];
}

Byte getiSboxValue(Byte x) {
    return isbox[x];
}

void copyState(State from, State to) {
    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < 4; j++) {
            to[i][j] = from[i][j];
        }
    }
}

// print state columns as rows
void printState(State s) {
    printf("------------\n");
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < Nb; j++) {
            printf("%02x ", s[j][i]);
        }
        printf("|\n");
    }
    printf("------------\n");
}

void subBytes(State s) {
    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < 4; j++) {
            s[i][j] = getSboxValue(s[i][j]);
        }
    }
}

void shiftRows(State state) {
    Byte temp;
    // first row unaffected

    // 2nd row shift by 1 
    temp = state[0][1];
    state[0][1] = state[1][1];
    state[1][1] = state[2][1];
    state[2][1] = state[3][1];
    state[3][1] = temp;

    // 3rd row shift by 2
    temp = state[0][2];
    state[0][2] = state[2][2];
    state[2][2] = temp;

    temp = state[1][2];
    state[1][2] = state[3][2];
    state[3][2] = temp;

    // 4th row shift by 3
    temp = state[0][3];
    state[0][3] = state[3][3];
    state[3][3] = state[2][3];
    state[2][3] = state[1][3];
    state[1][3] = temp;

}

void mixColumns(State s) {

    State temp;

    for (int column = 0; column < Nb; column++) {
        temp[column][0] = galoisMultiply(0x02, s[column][0]) ^ galoisMultiply(0x03, s[column][1]) ^ s[column][2] ^ s[column][3];
        temp[column][1] = s[column][0] ^ galoisMultiply(0x02, s[column][1]) ^ galoisMultiply(0x03, s[column][2]) ^ s[column][3];
        temp[column][2] = s[column][0] ^ s[column][1] ^ galoisMultiply(0x02, s[column][2]) ^ galoisMultiply(0x03, s[column][3]);
        temp[column][3] = galoisMultiply(0x03, s[column][0]) ^ s[column][1] ^ s[column][2] ^ galoisMultiply(0x02, s[column][3]);
    }

    copyState(temp, s);
}

void xorWord(Byte* word1, const Byte* word2) {
    for (int i = 0; i < 4; i++) {
        word1[i] ^= word2[i];
    }
}

void subWord(Byte* word) {
    for (int i = 0; i < 4; i++) {
        word[i] = getSboxValue(word[i]);
    }
}

void rotWord(Byte* word) {
    Byte temp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = temp;
}

void copyWord(Byte* word1, const Byte* word2) {
    for (int i = 0; i < 4; i++) {
        word1[i] = word2[i];
    }
}

void printWord(Byte* word) {
    for (int i = 0; i < 4; i++) {
        printf("%02x ", word[i]);
    }
    printf("\n");
}

void addRoundKey(State s, const Byte expendedKey[Nb * (Nr + 1)], int round) {
    for (int j= 0; j < 4; j++) {
        xorWord(s[j], &expendedKey[4 * Nb * round + j * Nb]);
    }
}

void keyExpansion(Byte key[4 * Nk], Byte expandedKey[4 * Nb * (Nr + 1)]) {
    Byte temp[4];

    // copy each 32bit word from key to expandedKey (there is Nk word of 4 bytes)
    for (int i = 0; i < Nk; i++) {
        copyWord(&expandedKey[4 * i], &key[4 * i]);
    }
    int i = Nk; //words in expandedKey
    while (i < Nb * (Nr + 1)) {
        copyWord(temp, &expandedKey[4 * (i - 1)]); // temp is word before 'i' word in expandedKey
        if (i % Nk == 0) {
            rotWord(temp);
            subWord(temp);
            temp[0] ^= Rcon[i / Nk];
        }
        else if (Nk > 6 && i % Nk == 4) {
            subWord(temp);
        }
        
        for (int j = 0; j < 4; j++) {
            expandedKey[i * 4 + j] = expandedKey[4 * (i - Nk) + j] ^ temp[j];
        }
        i++;
    }
}

void Cipher(State in, State out, Byte expandedKey[4 * Nb * (Nr + 1)]) {
    State state;
    copyState(in, state);
    addRoundKey(state, expandedKey, 0);
    for (int round = 1; round < Nr; round++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, expandedKey, round);
    }
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, expandedKey, Nr);
    copyState(state, out);
}

void invShiftRows(State state) {
    Byte temp;
    // first row unaffected

    // 2nd row shift by 1 
    temp = state[3][1];
    state[3][1] = state[2][1];
    state[2][1] = state[1][1];
    state[1][1] = state[0][1];
    state[0][1] = temp;

    // 3rd row shift by 2
    temp = state[0][2];
    state[0][2] = state[2][2];
    state[2][2] = temp;

    temp = state[1][2];
    state[1][2] = state[3][2];
    state[3][2] = temp;

    // 4th row shift by 3
    temp = state[0][3];
    state[0][3] = state[1][3];
    state[1][3] = state[2][3];
    state[2][3] = state[3][3];
    state[3][3] = temp;
}

void invSubBytes(State s) {
    for (int i = 0; i < Nb; i++) {
        for (int j = 0; j < 4; j++) {
            s[i][j] = getiSboxValue(s[i][j]);
        }
    }
}

void invMixColumns(State s) {
    State temp;

    for (int column = 0; column < Nb; column++) {
        temp[column][0] = galoisMultiply(0x0e, s[column][0]) ^ galoisMultiply(0x0b, s[column][1]) ^ galoisMultiply(0x0d, s[column][2]) ^ galoisMultiply(0x09, s[column][3]);
        temp[column][1] = galoisMultiply(0x09, s[column][0]) ^ galoisMultiply(0x0e, s[column][1]) ^ galoisMultiply(0x0b, s[column][2]) ^ galoisMultiply(0x0d, s[column][3]);
        temp[column][2] = galoisMultiply(0x0d, s[column][0]) ^ galoisMultiply(0x09, s[column][1]) ^ galoisMultiply(0x0e, s[column][2]) ^ galoisMultiply(0x0b, s[column][3]);
        temp[column][3] = galoisMultiply(0x0b, s[column][0]) ^ galoisMultiply(0x0d, s[column][1]) ^ galoisMultiply(0x09, s[column][2]) ^ galoisMultiply(0x0e, s[column][3]);
    }

    copyState(temp, s);
}

void invCipher(State in, State out, Byte expandedKey[4 * Nb * (Nr + 1)]) {
    State state;
    copyState(in, state);
    addRoundKey(state, expandedKey, Nr);
    for (int round = Nr - 1; round > 0; round--) {
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, expandedKey, round);
        invMixColumns(state);
    }
    invShiftRows(state);
    invSubBytes(state);
    addRoundKey(state, expandedKey, 0);
    copyState(state, out);
}

int main() {
    // Appendix A input example
    State input = {
        //row1  row2  row3  row4
        { 0x32, 0x43, 0xf6, 0xa8 }, // column 1
        { 0x88, 0x5a, 0x30, 0x8d }, // column 2
        { 0x31, 0x31, 0x98, 0xa2 }, // column 3
        { 0xe0, 0x37, 0x07, 0x34 }, // column 4
    };
    Byte expandedKey[4 * Nb * (Nr + 1)];
    State output;
    keyExpansion(key, expandedKey);
    printf("\nOriginal data: \n");
    printState(input);
    Cipher(input, output, expandedKey);
    printf("\nEncrypted data: \n");
    printState(output);
    invCipher(output, output, expandedKey);
    printf("\nDecrypted data: \n");
    printState(output);
	return 0;
}