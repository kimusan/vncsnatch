#ifndef DES_H
#define DES_H

#include <stdint.h>

void des_encrypt_block(const uint8_t key[8], const uint8_t in[8],
                       uint8_t out[8]);

#endif // DES_H
