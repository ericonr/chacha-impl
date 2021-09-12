/*
 * Implementation of ChaCha20 with some added flexibility to allow
 * other round sizes.
 *
 * Implemented based on RFC 8439 and its test vectors.
 *
 */

#include <assert.h> /* assert() */
#include <endian.h> /* htole32(), le32toh() */
#include <limits.h> /* CHAR_BIT */
#include <stdint.h> /* uint8_t, uint32_t */
#include <string.h> /* memcpy() */

#include "chacha.h"

struct chacha_state {
	uint32_t v[16];
};

struct chacha_serial_state {
	uint8_t b[16*4];
};

/* quarter round */
#define ROT_L(x,n) do{ x = (x << n) | (x >> (sizeof x * CHAR_BIT - n)); }while(0)
#define QROUND(a,b,c,d) \
	do{ \
	a += b; d ^= a; ROT_L(d, 16); \
	c += d; b ^= c; ROT_L(b, 12); \
	a += b; d ^= a; ROT_L(d, 8); \
	c += d; b ^= c; ROT_L(b, 7); \
	}while(0)

/* chacha inner block; ChaCha20 uses 10 of these */
static inline void chacha_innerblock(struct chacha_state *s)
{
	/* implement the round without loops to avoid branching */
	#define RUN_QROUND(state, i1, i2, i3, i4) QROUND(state->v[i1], state->v[i2], state->v[i3], state->v[i4])
	RUN_QROUND(s, 0, 4, 8, 12);
	RUN_QROUND(s, 1, 5, 9, 13);
	RUN_QROUND(s, 2, 6, 10, 14);
	RUN_QROUND(s, 3, 7, 11, 15);
	RUN_QROUND(s, 0, 5, 10, 15);
	RUN_QROUND(s, 1, 6, 11, 12);
	RUN_QROUND(s, 2, 7, 8, 13);
	RUN_QROUND(s, 3, 4, 9, 14);
	#undef RUN_QROUND
}

static inline void chacha_rounds_withsum(struct chacha_state *s, unsigned rounds)
{
	assert(rounds % 2 == 0);
	rounds /= 2;

	struct chacha_state is = *s;

	for (unsigned i=0; i < rounds; i++) chacha_innerblock(s);
	for (unsigned i=0; i<16; i++) s->v[i] += is.v[i];
}

static inline void chacha_serialize(const struct chacha_state *s, struct chacha_serial_state *dst)
{
	for (unsigned i=0; i<16; i++) {
		uint32_t t = htole32(s->v[i]);
		memcpy(dst->b + i*4, &t, sizeof t);
	}
}

static inline void chacha_init_state(struct chacha_state *s, const struct chacha_encryption_params *p)
{
	/* section 2.3 */
	s->v[0] = 0x61707865;
	s->v[1] = 0x3320646e;
	s->v[2] = 0x79622d32;
	s->v[3] = 0x6b206574;

	s->v[12] = p->counter;

	uint32_t t;
	for (unsigned i=0; i<8; i++) {
		memcpy(&t, p->key + i*4, sizeof t);
		s->v[i+4] = le32toh(t);
	}
	for (unsigned i=0; i<3; i++) {
		memcpy(&t, p->nonce + i*4, sizeof t);
		s->v[i+13] = le32toh(t);
	}
}

static inline void chacha_encrypt(const struct chacha_encryption_params *params, void *data, size_t data_len, unsigned rounds)
{
	struct chacha_encryption_params params_c = *params;
	struct chacha_state s;
	struct chacha_serial_state ss;
	unsigned char *datap = data;

	size_t inter_len = data_len / 64;
	for (size_t i=0; i <= inter_len; i++) {
		unsigned xor_len;

		chacha_init_state(&s, &params_c);
		params_c.counter++;

		chacha_rounds_withsum(&s, rounds);
		chacha_serialize(&s, &ss);

		if (i!=inter_len) xor_len = 64;
		else xor_len = data_len % 64;
		for (unsigned j=0; j < xor_len; j++) datap[i*64+j] ^= ss.b[j];
	}
}

void chacha20_encrypt_noauth(const struct chacha_encryption_params *params, void *data, size_t data_len)
{
	chacha_encrypt(params, data, data_len, 20);
}

#ifdef TEST
#include <stdio.h>
static void print_block(struct chacha_state *s)
{
	for (int i = 0; i < 4; i++) printf("%08x %08x %08x %08x\n", s->v[i*4], s->v[i*4+1], s->v[i*4+2], s->v[i*4+3]);
}

int main()
{
	/* test quarter round - section 2.1.1 */
	uint32_t e=0x11111111, f=0x01020304, g=0x9b8d6f43, h=0x01234567;
	QROUND(e,f,g,h);
	assert(e == 0xea2a92f4);
	assert(f == 0xcb1cf8ce);
	assert(g == 0x4581472e);
	assert(h == 0x5881c4bb);

	/* test inner block (indirectly) - section 2.3.2 */
	struct chacha_state initial1 = {.v = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c, 0x00000001, 0x09000000, 0x4a000000, 0x00000000}}, initial2 = initial1;
	struct chacha_state after_innerblock = {.v = {0x837778ab, 0xe238d763, 0xa67ae21e, 0x5950bb2f, 0xc4f2d0c7, 0xfc62bb2f, 0x8fa018fc, 0x3f5ec7b7, 0x335271c2, 0xf29489f3, 0xeabda8fc, 0x82e46ebd, 0xd19c12b4, 0xb04e16de, 0x9e83d0cb, 0x4e3c50a2}};
	for (int i=0; i<10; i++) chacha_innerblock(&initial1);
	assert(memcmp(&initial1, &after_innerblock, sizeof initial1) == 0);
	/* test full ChaCha20 operation - section 2.3.2 */
	chacha_rounds_withsum(&initial2, 20);
	struct chacha_state after_chacha20block = {.v = {0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3, 0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3, 0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9, 0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2}};
	assert(memcmp(&initial2, &after_chacha20block, sizeof initial2) == 0);
	/* test serialization code - section 2.3.2 */
	struct chacha_serial_state ss, ss_ref = {.b = {0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e}};
	chacha_serialize(&initial2, &ss);
	assert(memcmp(&ss, &ss_ref, sizeof ss) == 0);

	/* test full encryption - 2.4.2 */
	struct chacha_encryption_params enc = {
		.key = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
		.nonce = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00},
		.counter = 1,
	};
	char text[] = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
	uint8_t final_text[] = {0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81, 0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b, 0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57, 0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8, 0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e, 0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36, 0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42, 0x87, 0x4d};
	size_t text_len = strlen(text);
	chacha_encrypt(&enc, text, text_len, 20);
	assert(memcmp(text, final_text, text_len) == 0);
}
#endif
