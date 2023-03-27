#include "api.h"
#include "crypto_aead.h"
#include "permutations.h"

#define RATE (64 / 8)
#define PA_ROUNDS 12
#define PB_ROUNDS 6
#define IV                                                        \
  ((u64)(8 * (CRYPTO_KEYBYTES)) << 56 | (u64)(8 * (RATE)) << 48 | \
   (u64)(PA_ROUNDS) << 40 | (u64)(PB_ROUNDS) << 32)

int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                        const unsigned char* m, unsigned long long mlen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* nsec, const unsigned char* npub,
                        const unsigned char* k) {
  const u64 K0 = BYTES_TO_U64(k, 8);
  const u64 K1 = BYTES_TO_U64(k + 8, 8);
  const u64 N0 = BYTES_TO_U64(npub, 8);
  const u64 N1 = BYTES_TO_U64(npub + 8, 8);
  state s;
  (void)nsec;

  // set ciphertext size
  *clen = mlen + CRYPTO_ABYTES;

  // initialization
  s.x0 = IV;
  s.x1 = K0;
  s.x2 = K1;
  s.x3 = N0;
  s.x4 = N1;
  printstate("initial value:", s);
  P12(&s);
  printstate("initial after P12:", s);
  s.x3 ^= K0;
  s.x4 ^= K1;

  // process associated data
  if (adlen) {
    while (adlen >= RATE) {
      s.x0 ^= BYTES_TO_U64(ad, 8);
      printstate("after absorb AD:", s);
      P6(&s);
      printstate("after absorb AD permute:", s);
      adlen -= RATE;
      ad += RATE;
    }
    s.x0 ^= BYTES_TO_U64(ad, adlen);
    s.x0 ^= 0x80ull << (56 - 8 * adlen);
    printstate("after absorb AD done", s);
    P6(&s);
    printstate("after absorb AD permute done", s);
  }
  s.x4 ^= 1;

  // process plaintext
  while (mlen >= RATE) {
    s.x0 ^= BYTES_TO_U64(m, 8);
    U64_TO_BYTES(c, s.x0, 8);
    printstate("after absorb PT:", s);
    P6(&s);
    printstate("after absorb PT permute:", s);
    mlen -= RATE;
    m += RATE;
    c += RATE;
  }
  s.x0 ^= BYTES_TO_U64(m, mlen);
  s.x0 ^= 0x80ull << (56 - 8 * mlen);
  U64_TO_BYTES(c, s.x0, mlen);
  c += mlen;

  // finalization
  s.x1 ^= K0;
  s.x2 ^= K1;
  printstate("finalize after mix key1", s);
  P12(&s);
  printstate("finalization: after P12:", s);
  s.x3 ^= K0;
  s.x4 ^= K1;
  printstate("final after mix key2", s);

  // set tag
  U64_TO_BYTES(c, s.x3, 8);
  U64_TO_BYTES(c + 8, s.x4, 8);

  return 0;
}

