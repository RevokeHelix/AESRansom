/*******************************************************************************
 * AES-128 in C (CBC Mode)
 *
 * Usage:
 *   aes_cbc encrypt <input_file> <output_file> <hex_key_32chars>
 *   aes_cbc decrypt <input_file> <output_file> <hex_key_32chars>
 *
 * Example key (128-bit in hex): 2b7e151628aed2a6abf7158809cf4f3c
 ******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

/* S-box */
static const uint8_t Sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5, 0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0, 0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc, 0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a, 0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0, 0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b, 0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85, 0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5, 0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17, 0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88, 0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c, 0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9, 0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6, 0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e, 0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94, 0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68, 0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

/* Inverse S-box */
static const uint8_t InvSbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38, 0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87, 0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d, 0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2, 0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16, 0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda, 0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a, 0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02, 0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea, 0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85, 0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89, 0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20, 0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31, 0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d, 0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0, 0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26, 0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

/* Rcon (for AES-128) */
static const uint8_t Rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 
    0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
};

/* Forward declaration of functions */
static void  sub_bytes(uint8_t *state);
static void  inv_sub_bytes(uint8_t *state);
static void  shift_rows(uint8_t *state);
static void  inv_shift_rows(uint8_t *state);
static uint8_t xtime(uint8_t a);
static uint8_t mul(uint8_t a, uint8_t b);
static void  mix_columns(uint8_t *state);
static void  inv_mix_columns(uint8_t *state);
static void  add_round_key(uint8_t *state, const uint8_t *round_key);
static void  key_expansion(const uint8_t *key, uint8_t *key_schedule);
static void  encrypt_block(const uint8_t *plaintext, const uint8_t *key_schedule, uint8_t *ciphertext);
static void  decrypt_block(const uint8_t *ciphertext, const uint8_t *key_schedule, uint8_t *plaintext);
static uint8_t* pkcs7_pad(const uint8_t *data, size_t len, size_t *out_len);
static uint8_t* pkcs7_unpad(uint8_t *data, size_t *len);
static void  encrypt_cbc(const uint8_t *plaintext, size_t pt_len,
                         const uint8_t *key, uint8_t **out_ciphertext, 
                         size_t *out_ct_len);
static void  decrypt_cbc(const uint8_t *ciphertext, size_t ct_len,
                         const uint8_t *key, uint8_t **out_plaintext,
                         size_t *out_pt_len);

/* Helper to read entire file into buffer */
static uint8_t* read_file(const char *filename, size_t *file_len)
{
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    long length = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (length < 0) {
        fclose(fp);
        return NULL;
    }
    uint8_t *buffer = (uint8_t*)malloc(length);
    if (!buffer) {
        fclose(fp);
        return NULL;
    }
    if (fread(buffer, 1, length, fp) != (size_t)length) {
        fclose(fp);
        free(buffer);
        return NULL;
    }
    fclose(fp);
    *file_len = (size_t)length;
    return buffer;
}

/* Helper to write entire buffer to file */
static int write_file(const char *filename, const uint8_t *data, size_t len)
{
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        return 0;
    }
    size_t written = fwrite(data, 1, len, fp);
    fclose(fp);
    return (written == len);
}

/* Convert hex string (32 chars for 16 bytes) to a 16-byte array */
static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
    if (strlen(hex) != out_len * 2) {
        return 0; /* length mismatch */
    }
    for (size_t i = 0; i < out_len; i++) {
        unsigned int val;
        if (sscanf(&hex[i*2], "%2x", &val) != 1) {
            return 0;
        }
        out[i] = (uint8_t)val;
    }
    return 1;
}

/******************************************************************************
 * AES Functions
 ******************************************************************************/

static void sub_bytes(uint8_t *state)
{
    for (int i = 0; i < 16; i++) {
        state[i] = Sbox[state[i]];
    }
}

static void inv_sub_bytes(uint8_t *state)
{
    for (int i = 0; i < 16; i++) {
        state[i] = InvSbox[state[i]];
    }
}

static void shift_rows(uint8_t *state)
{
    /* state is 16 bytes:
       [ 0,  1,  2,  3 ]
       [ 4,  5,  6,  7 ]
       [ 8,  9, 10, 11 ]
       [12, 13, 14, 15 ]
       
       Shift rows:
       row0: no shift
       row1: shift left by 1
       row2: shift left by 2
       row3: shift left by 3
    */
    uint8_t tmp[16];
    memcpy(tmp, state, 16);

    state[0]  = tmp[0];
    state[1]  = tmp[5];
    state[2]  = tmp[10];
    state[3]  = tmp[15];

    state[4]  = tmp[4];
    state[5]  = tmp[9];
    state[6]  = tmp[14];
    state[7]  = tmp[3];

    state[8]  = tmp[8];
    state[9]  = tmp[13];
    state[10] = tmp[2];
    state[11] = tmp[7];

    state[12] = tmp[12];
    state[13] = tmp[1];
    state[14] = tmp[6];
    state[15] = tmp[11];
}

static void inv_shift_rows(uint8_t *state)
{
    /* Inverse shift rows:
       row1: shift right by 1
       row2: shift right by 2
       row3: shift right by 3
    */
    uint8_t tmp[16];
    memcpy(tmp, state, 16);

    state[0]  = tmp[0];
    state[1]  = tmp[13];
    state[2]  = tmp[10];
    state[3]  = tmp[7];

    state[4]  = tmp[4];
    state[5]  = tmp[1];
    state[6]  = tmp[14];
    state[7]  = tmp[11];

    state[8]  = tmp[8];
    state[9]  = tmp[5];
    state[10] = tmp[2];
    state[11] = tmp[15];

    state[12] = tmp[12];
    state[13] = tmp[9];
    state[14] = tmp[6];
    state[15] = tmp[3];
}

static uint8_t xtime(uint8_t a)
{
    /* multiplication by 2 in GF(2^8) */
    if (a & 0x80) {
        return (uint8_t)((a << 1) ^ 0x1B);
    } else {
        return (uint8_t)(a << 1);
    }
}

static uint8_t mul(uint8_t a, uint8_t b)
{
    /* GF(2^8) multiplication */
    uint8_t p = 0;
    uint8_t counter;
    uint8_t carry;
    for (counter = 0; counter < 8; counter++) {
        if (b & 1) {
            p ^= a;
        }
        carry = (uint8_t)(a & 0x80);
        a <<= 1;
        if (carry) {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    return p;
}

static void mix_columns(uint8_t *state)
{
    for (int i = 0; i < 16; i += 4) {
        uint8_t s0 = state[i+0];
        uint8_t s1 = state[i+1];
        uint8_t s2 = state[i+2];
        uint8_t s3 = state[i+3];

        state[i+0] = (uint8_t)(mul(s0, 2) ^ mul(s1, 3) ^ s2 ^ s3);
        state[i+1] = (uint8_t)(s0 ^ mul(s1, 2) ^ mul(s2, 3) ^ s3);
        state[i+2] = (uint8_t)(s0 ^ s1 ^ mul(s2, 2) ^ mul(s3, 3));
        state[i+3] = (uint8_t)(mul(s0, 3) ^ s1 ^ s2 ^ mul(s3, 2));
    }
}

static void inv_mix_columns(uint8_t *state)
{
    for (int i = 0; i < 16; i += 4) {
        uint8_t s0 = state[i+0];
        uint8_t s1 = state[i+1];
        uint8_t s2 = state[i+2];
        uint8_t s3 = state[i+3];

        state[i+0] = (uint8_t)(mul(s0, 0x0E) ^ mul(s1, 0x0B) ^ mul(s2, 0x0D) ^ mul(s3, 0x09));
        state[i+1] = (uint8_t)(mul(s0, 0x09) ^ mul(s1, 0x0E) ^ mul(s2, 0x0B) ^ mul(s3, 0x0D));
        state[i+2] = (uint8_t)(mul(s0, 0x0D) ^ mul(s1, 0x09) ^ mul(s2, 0x0E) ^ mul(s3, 0x0B));
        state[i+3] = (uint8_t)(mul(s0, 0x0B) ^ mul(s1, 0x0D) ^ mul(s2, 0x09) ^ mul(s3, 0x0E));
    }
}

static void add_round_key(uint8_t *state, const uint8_t *round_key)
{
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

/* Expand the key into 176 bytes (for AES-128: 11 round keys of 16 bytes each) */
static void key_expansion(const uint8_t *key, uint8_t *key_schedule)
{
    /* Nk=4 words, Nb=4, Nr=10 for AES-128 */
    const int Nk = 4;
    const int Nb = 4;
    const int Nr = 10;

    /* Copy the original key as first 16 bytes */
    memcpy(key_schedule, key, 16);

    /* Each word is 4 bytes. total words = Nb*(Nr+1) = 44 for AES-128. */
    int i = Nk;
    uint8_t temp[4];

    while (i < Nb * (Nr + 1)) {
        memcpy(temp, &key_schedule[(i - 1) * 4], 4);

        if ((i % Nk) == 0) {
            /* RotWord */
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            /* SubWord */
            temp[0] = Sbox[temp[0]];
            temp[1] = Sbox[temp[1]];
            temp[2] = Sbox[temp[2]];
            temp[3] = Sbox[temp[3]];

            /* Rcon */
            temp[0] ^= Rcon[i / Nk];
        }
        /* XOR with the word Nk positions before */
        key_schedule[i*4 + 0] = key_schedule[(i - Nk)*4 + 0] ^ temp[0];
        key_schedule[i*4 + 1] = key_schedule[(i - Nk)*4 + 1] ^ temp[1];
        key_schedule[i*4 + 2] = key_schedule[(i - Nk)*4 + 2] ^ temp[2];
        key_schedule[i*4 + 3] = key_schedule[(i - Nk)*4 + 3] ^ temp[3];

        i++;
    }
}

static void encrypt_block(const uint8_t *plaintext, const uint8_t *key_schedule, uint8_t *ciphertext)
{
    uint8_t state[16];
    memcpy(state, plaintext, 16);

    /* Initial round key addition */
    add_round_key(state, key_schedule); /* first 16 bytes (round 0) */

    /* Rounds 1-9 */
    for (int round = 1; round < 10; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, key_schedule + round * 16);
    }

    /* Round 10 (final) */
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, key_schedule + 10 * 16);

    memcpy(ciphertext, state, 16);
}

static void decrypt_block(const uint8_t *ciphertext, const uint8_t *key_schedule, uint8_t *plaintext)
{
    uint8_t state[16];
    memcpy(state, ciphertext, 16);

    /* Initial round key addition (round 10) */
    add_round_key(state, key_schedule + 10 * 16);

    /* Rounds 9-1 */
    for (int round = 9; round > 0; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, key_schedule + round * 16);
        inv_mix_columns(state);
    }

    /* Round 0 */
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, key_schedule);

    memcpy(plaintext, state, 16);
}

/******************************************************************************
 * PKCS#7 Padding
 ******************************************************************************/
static uint8_t* pkcs7_pad(const uint8_t *data, size_t len, size_t *out_len)
{
    size_t pad_len = 16 - (len % 16);
    *out_len = len + pad_len;
    uint8_t *padded = (uint8_t*)malloc(*out_len);
    if (!padded) {
        return NULL;
    }
    memcpy(padded, data, len);
    /* pad with pad_len bytes each set to pad_len */
    for (size_t i = 0; i < pad_len; i++) {
        padded[len + i] = (uint8_t)pad_len;
    }
    return padded;
}

static uint8_t* pkcs7_unpad(uint8_t *data, size_t *len)
{
    if (*len == 0) {
        return data;
    }
    uint8_t pad_len = data[*len - 1];
    if (pad_len > 16) {
        /* Invalid padding */
        return data;
    }
    /* Check if the last pad_len bytes are all pad_len (optional strict check) */
    for (size_t i = 0; i < pad_len; i++) {
        if (data[*len - 1 - i] != pad_len) {
            /* Invalid padding data, handle error if needed */
            return data;
        }
    }
    *len -= pad_len;
    return data;
}

/******************************************************************************
 * CBC Mode
 ******************************************************************************/
static void encrypt_cbc(const uint8_t *plaintext, size_t pt_len,
                        const uint8_t *key, uint8_t **out_ciphertext,
                        size_t *out_ct_len)
{
    /* Expand key */
    uint8_t key_schedule[176]; /* 16 * (10+1) = 176 bytes */
    key_expansion(key, key_schedule);

    /* Generate random IV (16 bytes) */
    uint8_t iv[16];
    for (int i = 0; i < 16; i++) {
        iv[i] = (uint8_t)(rand() & 0xFF);
    }

    /* PKCS#7 pad */
    size_t padded_len = 0;
    uint8_t *padded = pkcs7_pad(plaintext, pt_len, &padded_len);

    *out_ct_len = 16 + padded_len; /* IV + actual ciphertext */
    *out_ciphertext = (uint8_t*)malloc(*out_ct_len);
    if (!*out_ciphertext) {
        free(padded);
        return;
    }

    /* Copy IV to output first */
    memcpy(*out_ciphertext, iv, 16);

    /* Encrypt block by block */
    const uint8_t *current_block = padded;
    uint8_t *ciphertext_pos = *out_ciphertext + 16;
    uint8_t xor_block[16];

    /* previous_block for CBC = IV initially */
    memcpy(xor_block, iv, 16);

    for (size_t offset = 0; offset < padded_len; offset += 16) {
        /* XOR with previous block */
        uint8_t buffer[16];
        for (int i = 0; i < 16; i++) {
            buffer[i] = current_block[i] ^ xor_block[i];
        }

        /* Encrypt */
        encrypt_block(buffer, key_schedule, ciphertext_pos);

        /* Update xor_block = this ciphertext */
        memcpy(xor_block, ciphertext_pos, 16);

        ciphertext_pos += 16;
        current_block += 16;
    }

    free(padded);
}

static void decrypt_cbc(const uint8_t *ciphertext, size_t ct_len,
                        const uint8_t *key, uint8_t **out_plaintext,
                        size_t *out_pt_len)
{
    if (ct_len < 16) {
        /* Invalid (no room for IV) */
        *out_plaintext = NULL;
        *out_pt_len = 0;
        return;
    }

    /* Expand key */
    uint8_t key_schedule[176];
    key_expansion(key, key_schedule);

    /* First 16 bytes are IV */
    uint8_t iv[16];
    memcpy(iv, ciphertext, 16);

    const uint8_t *ct_blocks = ciphertext + 16;
    size_t blocks_len = ct_len - 16;

    if (blocks_len % 16 != 0) {
        /* Invalid length */
        *out_plaintext = NULL;
        *out_pt_len = 0;
        return;
    }

    /* Allocate for padded plaintext (same size as blocks_len) */
    *out_pt_len = blocks_len;
    *out_plaintext = (uint8_t*)malloc(*out_pt_len);
    if (!*out_plaintext) {
        *out_pt_len = 0;
        return;
    }

    uint8_t previous_block[16];
    memcpy(previous_block, iv, 16);

    uint8_t buffer[16];

    for (size_t offset = 0; offset < blocks_len; offset += 16) {
        /* Decrypt block */
        decrypt_block(ct_blocks + offset, key_schedule, buffer);

        /* XOR with previous_block to get plaintext */
        for (int i = 0; i < 16; i++) {
            (*out_plaintext)[offset + i] = buffer[i] ^ previous_block[i];
        }

        /* Update previous_block = ciphertext block */
        memcpy(previous_block, ct_blocks + offset, 16);
    }

    /* Unpad (in place) */
    *out_plaintext = pkcs7_unpad(*out_plaintext, out_pt_len);
}

/******************************************************************************
 * File-level encryption/decryption
 ******************************************************************************/
static int encrypt_file(const char *infile, const char *outfile, const uint8_t *key)
{
    size_t pt_len = 0;
    uint8_t *plaintext = read_file(infile, &pt_len);
    if (!plaintext) {
        fprintf(stderr, "Error: Could not read file '%s'.\n", infile);
        return 0;
    }

    uint8_t *ciphertext = NULL;
    size_t ct_len = 0;

    encrypt_cbc(plaintext, pt_len, key, &ciphertext, &ct_len);

    free(plaintext);

    if (!ciphertext) {
        fprintf(stderr, "Error: Encryption failed.\n");
        return 0;
    }

    if (!write_file(outfile, ciphertext, ct_len)) {
        fprintf(stderr, "Error: Could not write encrypted file '%s'.\n", outfile);
        free(ciphertext);
        return 0;
    }

    free(ciphertext);
    return 1;
}

static int decrypt_file(const char *infile, const char *outfile, const uint8_t *key)
{
    size_t ct_len = 0;
    uint8_t *ciphertext = read_file(infile, &ct_len);
    if (!ciphertext) {
        fprintf(stderr, "Error: Could not read file '%s'.\n", infile);
        return 0;
    }

    uint8_t *plaintext = NULL;
    size_t pt_len = 0;

    decrypt_cbc(ciphertext, ct_len, key, &plaintext, &pt_len);

    free(ciphertext);

    if (!plaintext) {
        fprintf(stderr, "Error: Decryption failed (possibly bad key or corrupted data).\n");
        return 0;
    }

    if (!write_file(outfile, plaintext, pt_len)) {
        fprintf(stderr, "Error: Could not write decrypted file '%s'.\n", outfile);
        free(plaintext);
        return 0;
    }

    free(plaintext);
    return 1;
}

/******************************************************************************
 * Main (CLI)
 ******************************************************************************/
int main(int argc, char *argv[])
{
    if (argc != 5) {
        fprintf(stderr, "Usage: %s [encrypt|decrypt] <input_file> <output_file> <hex_key_32>\n", argv[0]);
        return 1;
    }

    /* Initialize random for IV generation */
    srand((unsigned int)time(NULL));

    const char *operation = argv[1];
    const char *input_file = argv[2];
    const char *output_file = argv[3];
    const char *hex_key = argv[4];

    uint8_t key[16];
    if (!hex_to_bytes(hex_key, key, 16)) {
        fprintf(stderr, "Error: Key must be exactly 32 hex characters.\n");
        return 1;
    }

    if (strcmp(operation, "encrypt") == 0) {
        if (!encrypt_file(input_file, output_file, key)) {
            return 1;
        }
        printf("File encrypted successfully: %s\n", output_file);
    } else if (strcmp(operation, "decrypt") == 0) {
        if (!decrypt_file(input_file, output_file, key)) {
            return 1;
        }
        printf("File decrypted successfully: %s\n", output_file);
    } else {
        fprintf(stderr, "Invalid operation '%s'. Use 'encrypt' or 'decrypt'.\n", operation);
        return 1;
    }

    return 0;
}

