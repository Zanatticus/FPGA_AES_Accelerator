#ifndef AES_HLS_H_
#define AES_HLS_H_
#include <hls_stream.h>
#include <ap_axi_sdata.h>

#include <stdio.h>
#include <stdlib.h>


enum errorCode
{
    SUCCESS = 0,
    ERROR_AES_UNKNOWN_KEYSIZE,
    ERROR_MEMORY_ALLOCATION_FAILED,
};
enum keySize
{
    SIZE_16 = 16,
    SIZE_24 = 24,
    SIZE_32 = 32
};
unsigned char getSBoxValue(unsigned char num);
unsigned char getSBoxInvert(unsigned char num);
void rotate(unsigned char *word);
unsigned char getRconValue(unsigned char num);
// Key Schedule Core
void core(unsigned char *word, int iteration);
// Key Expansion
void expandKey(unsigned char *expandedKey, unsigned char *key, enum keySize, size_t expandedKeySize);
// AES Encryption
void subBytes(unsigned char *state);
void shiftRows(unsigned char *state);
void shiftRow(unsigned char *state, unsigned char nbr);
void addRoundKey(unsigned char *state, unsigned char *roundKey);
unsigned char galois_multiplication(unsigned char a, unsigned char b);
void mixColumns(unsigned char *state);
void mixColumn(unsigned char *column);
void aes_round(unsigned char *state, unsigned char *roundKey);
void createRoundKey(unsigned char *expandedKey, unsigned char *roundKey);
void aes_main(unsigned char *state, unsigned char *expandedKey, int nbrRounds);
char aes_encrypt(unsigned char *input, unsigned char *output, unsigned char *key, enum keySize size);
// AES Decryption
void invSubBytes(unsigned char *state);
void invShiftRows(unsigned char *state);
void invShiftRow(unsigned char *state, unsigned char nbr);
void invMixColumns(unsigned char *state);
void invMixColumn(unsigned char *column);
void aes_invRound(unsigned char *state, unsigned char *roundKey);
void aes_invMain(unsigned char *state, unsigned char *expandedKey, int nbrRounds);
char aes_decrypt(unsigned char *input, unsigned char *output, unsigned char *key, enum keySize size);


typedef hls::stream<ap_axis<64, 1, 1, 1> > AXI_STREAM;

void aes (
    AXI_STREAM *plaintext,
    AXI_STREAM *ciphertext,
    AXI_STREAM *key,
    unsigned int key_size,
    AXI_STREAM *decryptedtext
);

#endif