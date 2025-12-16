#ifndef CONSTANTS_H_
#define CONSTANTS_H_

#include <stdint.h>

#define ASCON_128_KEYBYTES 16

#define ASCON_128_RATE 8
#define ASCON_128_PA_ROUNDS 12
#define ASCON_128_PB_ROUNDS 6

#define ASCON_128_IV                            \
  (((uint64_t)(ASCON_128_KEYBYTES * 8) << 56) | \
   ((uint64_t)(ASCON_128_RATE * 8) << 48) |     \
   ((uint64_t)(ASCON_128_PA_ROUNDS) << 40) |    \
   ((uint64_t)(ASCON_128_PB_ROUNDS) << 32))

#endif /* CONSTANTS_H_ */