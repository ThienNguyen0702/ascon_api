#ifndef PRINTSTATE_H_
#define PRINTSTATE_H_
#include "ascon.h"
#include "word.h"
#include <string.h>
#include <inttypes.h>

#ifndef WORDTOU64
#define WORDTOU64
#endif

#ifndef U64LE
#define U64LE
#endif

void print(const char* text) { printf("%s", text); }

void printbytes(const char* text, const uint8_t* b, uint64_t len) {
  uint64_t i;
  printf(" %s[%" PRIu64 "]\t= {", text, len);
  for (i = 0; i < len; ++i) printf("0x%02x%s", b[i], i < len - 1 ? ", " : "");
  printf("}\n");
}

void printword(const char* text, const uint64_t x) {
  printf("%s=0x%016" PRIx64, text, U64LE(WORDTOU64(x)));
}

void printstate(const char* text, const ascon_state_t* s) {
  int i;
  printf("%s:", text);
  for (i = strlen(text); i < 17; ++i) printf(" ");
  printword(" x0", s->x[0]);
  printword(" x1", s->x[1]);
  printword(" x2", s->x[2]);
  printword(" x3", s->x[3]);
  printword(" x4", s->x[4]);
  printf("\n");
}

#endif /* PRINTSTATE_H_ */
