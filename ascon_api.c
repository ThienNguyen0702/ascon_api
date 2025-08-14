#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

typedef struct{
    uint8_t *key;
    uint8_t *nonce;
    uint8_t *adata; 
    uint8_t  adlen;
    uint8_t *plaintext;
    uint8_t  ptlen;
    uint8_t *ciphertext;
    uint8_t *tag;
}ascon_aead_t;

// Utility Functions
uint64_t rotr(uint64_t x, int n) {
    return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFFULL;
}

uint64_t bytes_to_int(const uint8_t* b) {
    uint64_t result = 0;
    for (int i = 0; i < 8; i++) {
        result = (result << 8) | b[i];
    }
    return result;
}

// ASCON Permutation Layers
uint64_t constant_layer(uint64_t x2, int rounds, int counter) {
    if (rounds == 6) {
        return x2 ^ (0x96 - (counter - 1) * 15);
    } else if (rounds == 8) {
        return x2 ^ (0xb4 - (counter - 1) * 15);
    } else {
        return x2 ^ (0xf0 - (counter - 1) * 15);
    }
}

void substitution_layer(uint64_t* state) {
    uint64_t x0 = state[0], x1 = state[1], x2 = state[2], x3 = state[3], x4 = state[4];
    x0 ^= x4; x4 ^= x3; x2 ^= x1;
    uint64_t t0 = (~x0) & x1;
    uint64_t t1 = (~x1) & x2;
    uint64_t t2 = (~x2) & x3;
    uint64_t t3 = (~x3) & x4;
    uint64_t t4 = (~x4) & x0;
    x0 ^= t1; x1 ^= t2; x2 ^= t3; x3 ^= t4; x4 ^= t0;
    x1 ^= x0; x0 ^= x4; x3 ^= x2; x2 = ~x2 & 0xFFFFFFFFFFFFFFFFULL;
    state[0] = x0; state[1] = x1; state[2] = x2; state[3] = x3; state[4] = x4;
}

void linear_layer(uint64_t* state) {
    state[0] ^= rotr(state[0], 19) ^ rotr(state[0], 28);
    state[1] ^= rotr(state[1], 61) ^ rotr(state[1], 39);
    state[2] ^= rotr(state[2], 1) ^ rotr(state[2], 6);
    state[3] ^= rotr(state[3], 10) ^ rotr(state[3], 17);
    state[4] ^= rotr(state[4], 7) ^ rotr(state[4], 41);
    for (int i = 0; i < 5; i++) {
        state[i] &= 0xFFFFFFFFFFFFFFFFULL;
    }
}

void ascon_permutation(uint64_t* state, int rounds) {
    for (int r = 1; r <= rounds; r++) {
        state[2] = constant_layer(state[2], rounds, r);
        substitution_layer(state);
        linear_layer(state);
        printf("state: %llx %llx %llx %llx %llx\n", state[0], state[1], state[2], state[3], state[4]);
    }
}

void ascon_encrypt(ascon_aead_t ascon_aead_t) {

    if (!ascon_aead_t.key || !ascon_aead_t.nonce || !ascon_aead_t.adata 
        || !ascon_aead_t.ciphertext || !ascon_aead_t.plaintext) return;

    // Initialization
    uint64_t state[5];
    state[0] = 0x80400c0600000000;
    state[1] = bytes_to_int(ascon_aead_t.key);
    state[2] = bytes_to_int(ascon_aead_t.key + 8);
    state[3] = bytes_to_int(ascon_aead_t.nonce);
    state[4] = bytes_to_int(ascon_aead_t.nonce + 8);
    ascon_permutation(state, 12);
    state[3] ^= bytes_to_int(ascon_aead_t.key);
    state[4] ^= bytes_to_int(ascon_aead_t.key + 8);

    uint8_t rate = 8;
    uint8_t s = ascon_aead_t.adlen / rate + 1; 
    uint8_t t = ascon_aead_t.ptlen / rate + 1;
    uint8_t l = ascon_aead_t.ptlen % rate;
    uint8_t *pad_ad = malloc(s * rate);
    uint8_t *pad_pt = malloc(t * rate);

    // padding associated data
    for (uint8_t i = 0; i < ascon_aead_t.adlen; i++)
        pad_ad[i] = ascon_aead_t.adata[i];
    pad_ad[ascon_aead_t.adlen] = 0x80;
    for (uint8_t i = ascon_aead_t.adlen + 1; i < (s * rate); i++)
        pad_ad[i] = 0x00;

    // padding plaintext
    for (uint8_t i = 0; i < ascon_aead_t.ptlen; i++)
        pad_pt[i] = ascon_aead_t.plaintext[i];
    pad_pt[ascon_aead_t.ptlen] = 0x80;
    for (uint8_t i = ascon_aead_t.ptlen + 1; i < (t * rate); i++)
        pad_pt[i] = 0x00;

    // absorb associated data
    for (uint8_t i = 0; i < s; i++) {
        state[0] ^= bytes_to_int(pad_ad + i * rate);  
        if (rate == 16)
            state[1] ^= bytes_to_int(pad_ad + i * rate + 8);
        ascon_permutation(state, 6);
    }
    state[4] ^= 1;
    free(pad_ad);

    // absorb ciphertext
    for (uint8_t i = 0; i < t-1; i++) {
        state[0] ^= bytes_to_int(pad_pt + i * rate);  
        if (rate == 16)
            state[1] ^= bytes_to_int(pad_pt + i * rate + 8);

        for (int j = 0; j < rate; j++) {
            ascon_aead_t.ciphertext[i * rate + j] = (state[0] >> (8 * (rate - 1 - j))) & 0xFF;
        }
        if (rate == 16) {
            for (int j = 0; j < rate; j++) {
                ascon_aead_t.ciphertext[i * rate + 8 + j] = (state[1] >> (8 * (rate - 1 - j))) & 0xFF;
            }
        }

        ascon_permutation(state, 6);
    }

    state[0] ^= bytes_to_int(pad_pt + (t - 1) * rate);
    if (rate == 16)
        state[1] ^= bytes_to_int(pad_pt + (t - 1) * rate + 8);

    for (int j = 0; j < l; j++) {
        ascon_aead_t.ciphertext[(t - 1) * rate + j] = (state[0] >> (8 * (rate - 1 - j))) & 0xFF;
    }
    free(pad_pt);

    // Finalization
    state[1] ^= bytes_to_int(ascon_aead_t.key);
    state[2] ^= bytes_to_int(ascon_aead_t.key + 8);
    ascon_permutation(state, 12);

    for (int i = 0; i < 8; i++) {
        ascon_aead_t.tag[i]     = ((state[3] >> (56 - 8 * i)) & 0xFF) ^ ascon_aead_t.key[i];
        ascon_aead_t.tag[i + 8] = ((state[4] >> (56 - 8 * i)) & 0xFF) ^ ascon_aead_t.key[i + 8];
    }
}

int main() {
    uint8_t key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t nonce[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t ad[5] = {0x41, 0x53, 0x43, 0x4f, 0x4e};
    uint8_t pt[4] = {0x8b, 0x86, 0xd9, 0x32};
    uint8_t ct[4];
    uint8_t tag[16];

    ascon_aead_t ascon_aead = {
        .key        = key,
        .nonce      = nonce,
        .adata      = ad,
        .adlen      = sizeof(ad),
        .plaintext  = pt,
        .ptlen      = sizeof(pt),
        .ciphertext = ct,
        .tag        = tag
    };

    clock_t start = clock();
    ascon_encrypt(ascon_aead);
    clock_t end = clock();

    double elapsed = (double)(end - start) / CLOCKS_PER_SEC;
    printf("Time taken: %.6f seconds\n", elapsed);
    
    printf("Ciphertext: ");
    for (int i = 0; i < 4; i++) printf("%02X ", ct[i]);
    printf("\nTag: ");
    for (int i = 0; i < 16; i++) printf("%02X ", tag[i]);
    printf("\n");

    return 0;
}