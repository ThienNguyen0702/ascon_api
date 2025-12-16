#include <stdint.h>
  
// api.h
#define CRYPTO_KEYBYTES 16
#define CRYPTO_NSECBYTES 0
#define CRYPTO_NPUBBYTES 16
#define CRYPTO_ABYTES 16

#ifndef WORDTOU64
#define WORDTOU64
#endif

#ifndef U64LE
#define U64LE
#endif

// ascon.h
typedef struct {
  uint64_t x[5];
} ascon_state_t;

ascon_state_t s;

// word.h
/* get byte from 64-bit Ascon word */
#define GETBYTE(x, i) ((uint8_t)((uint64_t)(x) >> (56 - 8 * (i))))

/* set byte in 64-bit Ascon word */
#define SETBYTE(b, i) ((uint64_t)(b) << (56 - 8 * (i)))

/* set padding byte in 64-bit Ascon word */
#define PAD(i) SETBYTE(0x80, i)

/* define domain separation bit in 64-bit Ascon word */
#define DSEP() SETBYTE(0x01, 7)

/* load bytes into 64-bit Ascon word */
uint64_t LOADBYTES(const uint8_t* bytes, int n) {
  int i;
  uint64_t x = 0;
  for (i = 0; i < n; ++i) x |= SETBYTE(bytes[i], i);
  return x;
}

/* store bytes from 64-bit Ascon word */
void STOREBYTES(uint8_t* bytes, uint64_t x, int n) {
  int i;
  for (i = 0; i < n; ++i) bytes[i] = GETBYTE(x, i);
}

/* clear bytes in 64-bit Ascon word */
uint64_t CLEARBYTES(uint64_t x, int n) {
  int i;
  for (i = 0; i < n; ++i) x &= ~SETBYTE(0xff, i);
  return x;
}

// print state.h
void print_uint64_hex(uint64_t x) {
    // Chia 64-bit thành 4 phần 16-bit và in dưới dạng HEX
    for (int i = 3; i >= 0; --i) {
        uint16_t part = (uint16_t)((x >> (i * 16)) & 0xFFFF);
        
        // Căn chỉnh bằng 0: đảm bảo luôn có 4 chữ số cho mỗi phần 16-bit
        if (part < 0x1000) Serial.print('0');
        if (part < 0x0100) Serial.print('0');
        if (part < 0x0010) Serial.print('0');
        Serial.print(part, HEX);
    }
}

void print(const char* text) { 
  Serial.print(text); 
}

void printbytes(const char* text, const uint8_t* b, uint64_t len) {
  uint64_t i;
  
  Serial.print(" ");
  Serial.print(text);
  Serial.print("[");
  Serial.print((unsigned long)len); 
  Serial.print("]\t= {");

  for (i = 0; i < len; ++i) {
    Serial.print("0x");
    if (b[i] < 0x10) Serial.print("0"); 
    Serial.print(b[i], HEX);

    if (i < len - 1) {
      Serial.print(", ");
    }
  }
  Serial.println("}");
}

void printword(const char* text, const uint64_t x) {
  Serial.print(text);
  Serial.print("=0x");
  
  // Áp dụng các macro (WORDTOU64, U64LE) và sau đó in 64-bit hex
  uint64_t val = U64LE(WORDTOU64(x));
  print_uint64_hex(val);
}

void printstate(const char* text, ascon_state_t* s) {
  Serial.print(text);
  Serial.print(":");
  Serial.println(); // Xuống dòng để dễ đọc

  // In từng từ 64-bit của trạng thái, căn chỉnh bằng khoảng trắng
  Serial.print("    "); printword(" x0", s->x[0]); Serial.println();
  Serial.print("    "); printword(" x1", s->x[1]); Serial.println();
  Serial.print("    "); printword(" x2", s->x[2]); Serial.println();
  Serial.print("    "); printword(" x3", s->x[3]); Serial.println();
  Serial.print("    "); printword(" x4", s->x[4]); Serial.println();
  Serial.println();
}

void print_data(char c, unsigned char* x, unsigned long long xlen) {
  Serial.print((char)c);
  Serial.print("[");
 
  Serial.print((unsigned long)xlen);
  Serial.print("]=");
  
  for (unsigned long long i = 0; i < xlen; ++i) {
 
    if (x[i] < 0x10) Serial.print("0");
    Serial.print(x[i], HEX);
  }
  Serial.println();
}

// round.h
 uint64_t ROR(uint64_t x, int n) {
  return x >> n | x << (-n & 63);
}

void ROUND(ascon_state_t* s, uint8_t C) {
  ascon_state_t t;
  /* addition of round constant */
  s->x[2] ^= C;
  /* printstate(" round constant", s); */
  /* substitution layer */
  s->x[0] ^= s->x[4];
  s->x[4] ^= s->x[3];
  s->x[2] ^= s->x[1];
  /* start of keccak s-box */
  t.x[0] = s->x[0] ^ (~s->x[1] & s->x[2]);
  t.x[1] = s->x[1] ^ (~s->x[2] & s->x[3]);
  t.x[2] = s->x[2] ^ (~s->x[3] & s->x[4]);
  t.x[3] = s->x[3] ^ (~s->x[4] & s->x[0]);
  t.x[4] = s->x[4] ^ (~s->x[0] & s->x[1]);
  /* end of keccak s-box */
  t.x[1] ^= t.x[0];
  t.x[0] ^= t.x[4];
  t.x[3] ^= t.x[2];
  t.x[2] = ~t.x[2];
  /* printstate(" substitution layer", &t); */
  /* linear diffusion layer */
  s->x[0] = t.x[0] ^ ROR(t.x[0], 19) ^ ROR(t.x[0], 28);
  s->x[1] = t.x[1] ^ ROR(t.x[1], 61) ^ ROR(t.x[1], 39);
  s->x[2] = t.x[2] ^ ROR(t.x[2], 1) ^ ROR(t.x[2], 6);
  s->x[3] = t.x[3] ^ ROR(t.x[3], 10) ^ ROR(t.x[3], 17);
  s->x[4] = t.x[4] ^ ROR(t.x[4], 7) ^ ROR(t.x[4], 41);
  //printstate(" round output", s);
}

// permutation.h
void P12(ascon_state_t* s) {
  ROUND(s, 0xf0);
  ROUND(s, 0xe1);
  ROUND(s, 0xd2);
  ROUND(s, 0xc3);
  ROUND(s, 0xb4);
  ROUND(s, 0xa5);
  ROUND(s, 0x96);
  ROUND(s, 0x87);
  ROUND(s, 0x78);
  ROUND(s, 0x69);
  ROUND(s, 0x5a);
  ROUND(s, 0x4b);
}

void P8(ascon_state_t* s) {
  ROUND(s, 0xb4);
  ROUND(s, 0xa5);
  ROUND(s, 0x96);
  ROUND(s, 0x87);
  ROUND(s, 0x78);
  ROUND(s, 0x69);
  ROUND(s, 0x5a);
  ROUND(s, 0x4b);
}

void P6(ascon_state_t* s) {
  ROUND(s, 0x96);
  ROUND(s, 0x87);
  ROUND(s, 0x78);
  ROUND(s, 0x69);
  ROUND(s, 0x5a);
  ROUND(s, 0x4b);
}
// constants.h

#define ASCON_128_KEYBYTES 16

#define ASCON_128_RATE 8
#define ASCON_128_PA_ROUNDS 12
#define ASCON_128_PB_ROUNDS 6

#define ASCON_128_IV                            \
  (((uint64_t)(ASCON_128_KEYBYTES * 8) << 56) | \
   ((uint64_t)(ASCON_128_RATE * 8) << 48) |     \
   ((uint64_t)(ASCON_128_PA_ROUNDS) << 40) |    \
   ((uint64_t)(ASCON_128_PB_ROUNDS) << 32))

// crypto_aead.h
int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                        const unsigned char* m, unsigned long long mlen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* nsec, const unsigned char* npub,
                        const unsigned char* k) {
  (void)nsec;

  /* set ciphertext size */
  *clen = mlen + CRYPTO_ABYTES;

  /* print input bytes */
  // print("encrypt\n");
  // printbytes("k", k, CRYPTO_KEYBYTES);
  // printbytes("n", npub, CRYPTO_NPUBBYTES);
  // printbytes("a", ad, adlen);
  // printbytes("m", m, mlen);

  /* load key and nonce */
  const uint64_t K0 = LOADBYTES(k, 8);
  const uint64_t K1 = LOADBYTES(k + 8, 8);
  const uint64_t N0 = LOADBYTES(npub, 8);
  const uint64_t N1 = LOADBYTES(npub + 8, 8);

  /* initialize */
  //ascon_state_t s;
  s.x[0] = ASCON_128_IV;
  s.x[1] = K0;
  s.x[2] = K1;
  s.x[3] = N0;
  s.x[4] = N1;
  //printstate("init 1st key xor", &s);
  P12(&s);
  s.x[3] ^= K0;
  s.x[4] ^= K1;
  //printstate("init 2nd key xor", &s);

  if (adlen) {
    /* full associated data blocks */
    while (adlen >= ASCON_128_RATE) {
      s.x[0] ^= LOADBYTES(ad, 8);
      //printstate("absorb adata", &s);
      P6(&s);
      ad += ASCON_128_RATE;
      adlen -= ASCON_128_RATE;
    }
    /* final associated data block */
    s.x[0] ^= LOADBYTES(ad, adlen);
    s.x[0] ^= PAD(adlen);
    //printstate("pad adata", &s);
    P6(&s);
  }
  /* domain separation */
  s.x[4] ^= DSEP();
  //("domain separation", &s);

  /* full plaintext blocks */
  while (mlen >= ASCON_128_RATE) {
    s.x[0] ^= LOADBYTES(m, 8);
    STOREBYTES(c, s.x[0], 8);
    //printstate("absorb plaintext", &s);
    P6(&s);
    m += ASCON_128_RATE;
    c += ASCON_128_RATE;
    mlen -= ASCON_128_RATE;
  }
  /* final plaintext block */
  //printstate("absorb plaintext mthien", &s);
  s.x[0] ^= LOADBYTES(m, mlen);

  STOREBYTES(c, s.x[0], mlen);
  s.x[0] ^= PAD(mlen);
  m += mlen;
  c += mlen;
  //printstate("pad plaintext", &s);

  /* finalize */
  s.x[1] ^= K0;
  s.x[2] ^= K1;
  //printstate("final 1st key xor", &s);
  P12(&s);
  s.x[3] ^= K0;
  s.x[4] ^= K1;
  //printstate("final 2nd key xor", &s);

  /* get tag */
  STOREBYTES(c, s.x[3], 8);
  STOREBYTES(c + 8, s.x[4], 8);

  /* print output bytes */
  //printbytes("c", c - *clen + CRYPTO_ABYTES, *clen - CRYPTO_ABYTES);
  //printbytes("t", c, CRYPTO_ABYTES);
  //print("\n");

  return 0;
}

void setup() {
  Serial.begin(115200);
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

    unsigned long start, done;
    start = micros();
    result |= crypto_aead_encrypt(c, &clen, m, mlen, a, alen, (void*)0, n, k);
    done = micros() - start;
    Serial.print("Time (us): ");
    Serial.println(done);

    printf("encrypt:\n");
    print_data('c', c, clen - CRYPTO_ABYTES);
    print_data('t', c + clen - CRYPTO_ABYTES, CRYPTO_ABYTES);
}

void loop() {
  
}