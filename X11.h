#ifndef X11_H_
#define X11_H_
#endif

#include "miner.h"

// * X11 Functions
#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_luffa.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"

/* This file was automatically generated.  Do not edit! */

void init_X11_contexts();

typedef struct X11_context_holder {
	sph_blake512_context	blake;
	sph_bmw512_context	bmw;
	sph_groestl512_context	groestl;
	sph_skein512_context	skein;
	sph_jh512_context	jh;
	sph_keccak512_context	keccak;
	sph_luffa512_context	luffa;
	sph_cubehash512_context	cubehash;
	sph_shavite512_context	shavite;
	sph_simd512_context	simd;
	sph_echo512_context	echo;
	uint32_t h[8];
}X11_context_holder;

inline void X11_Hash(const void *input, void *state);
inline void be32enc_vect(uint32_t *dst,const uint32_t *src,uint32_t len);
