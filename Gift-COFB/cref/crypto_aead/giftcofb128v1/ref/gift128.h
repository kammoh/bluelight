/*
GIFT-128 implementation
Written by: Siang Meng Sim
Email: crypto.s.m.sim@gmail.com
Date: 08 Feb 2019
*/

#include <stdint.h>

#ifdef DEBUG
#else
#define printf(MESSAGE,args...) { \
}
#endif

void dump_block(char name[], uint8_t P[16]);
void dump_halfblock(char name[], uint8_t P[8]);

void giftb128(uint8_t P[16], const uint8_t K[16], uint8_t C[16]);
