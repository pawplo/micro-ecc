#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "uECC.h"

void hex_dump(char *prefix, unsigned char *str, int num)
{
    fprintf(stderr, "%s: ", prefix);
    for(int i=0; i<num; i++)
        fprintf(stderr, "%02x", str[i]);
    fprintf(stderr, "\n\n");
}

int main()
{
//  const struct uECC_Curve_t * curve = uECC_secp160r1();
  const struct uECC_Curve_t * curve = uECC_secp256k1();

//  uint8_t private1[32] = {0};
  uint8_t private1[32] = "\x7a\xb1\xce\x6a\x71\x2b\x26\x2f\xdf\x32\x7b\x29\x10\x11\x24\x94\x3f\x7e\x0b\x49\xa7\x0d\x36\x8a\x61\x56\x9e\x71\x1a\x6f\xa2\x55";
  uint8_t private2[32] = {0};
  
  uint8_t public1[64] = {0};
  uint8_t public2[64] = {0};
  
  uint8_t secret1[32] = {0};
  uint8_t secret2[32] = {0};

//  uECC_make_key(public1, private1, curve);
  uECC_make_key(public2, private2, curve);

  uECC_compute_public_key(private1, public1, curve);
//  uECC_compute_public_key(private2, public2, curve);
  hex_dump("private1", private1, 32);
  hex_dump("public1", public1, 64);
 
  int r = uECC_shared_secret(public2, private1, secret1, curve);
  if (!r) {
    printf("shared_secret() failed (1)\n");
    return 1;
  }

  r = uECC_shared_secret(public1, private2, secret2, curve);
  if (!r) {
    printf("shared_secret() failed (2)\n");
    return 1;
  }

  hex_dump("1", secret1, 32);
  hex_dump("2", secret2, 32);

  if (memcmp(secret1, secret2, 32) != 0) {
    printf("Shared secrets are not identical!\n");
  } else {
    printf("Shared secrets are identical\n");
  }

  return 0;
}
