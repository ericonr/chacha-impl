#ifndef E_CHACHA20_H
#define E_CHACHA20_H

#include <stdint.h>
#include <sys/types.h>

#define CHACHA20_KEY_LEN 32
#define CHACHA20_NONCE_LEN 12

struct chacha_encryption_params {
	uint8_t key[CHACHA20_KEY_LEN];
	uint8_t nonce[CHACHA20_NONCE_LEN];
	uint32_t counter;
};

/* encrypt buffer data of size data_len in place, using parameters defined in params
 * WARNING: doesn't perform authentication, shouldn't be used in most situations */
void chacha20_encrypt_noauth(const struct chacha_encryption_params *params, void *data, size_t data_len);

#endif
