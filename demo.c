#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"
#include "ascon.h"
#include "permutations.h"
#include "crypto_aead.h"
#include "printstate.h"
#include "word.h"

void print_data(unsigned char c, unsigned char* x, unsigned long long xlen) {
  unsigned long long i;
  printf("%c[%d]=", c, (int)xlen);
  for (i = 0; i < xlen; ++i) printf("%02x", x[i]);
  printf("\n");
}

int main() {
  unsigned char n[32] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                         11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                         22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
  unsigned char k[32] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                         11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                         22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
  unsigned char a[32] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                         11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                         22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
  unsigned char m[32] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                         11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                         22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
  unsigned char c[32], h[32], t[32];
  unsigned long long alen = 16;
  unsigned long long mlen = 16;
  unsigned long long clen;
  int result = 0;

    printf("input:\n");
    print_data('k', k, CRYPTO_KEYBYTES);
    print_data('n', n, CRYPTO_NPUBBYTES);
    print_data('a', a, alen);
    print_data('m', m, mlen);
    result |= crypto_aead_encrypt(c, &clen, m, mlen, a, alen, (void*)0, n, k);
    printf("encrypt:\n");
    print_data('c', c, clen - CRYPTO_ABYTES);
    print_data('t', c + clen - CRYPTO_ABYTES, CRYPTO_ABYTES);
    
}
