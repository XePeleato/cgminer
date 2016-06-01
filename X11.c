/* X11 Hashing algorithm for cgminer
						by: XePeleato
						
						Thanks to:
						Colin Percival (ArtForz)
						lucasjones
*/
#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
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

typedef struct {
	sph_blake512_context blake;
	sph_bmw512_context      bmw;
    sph_groestl512_context  groestl;
    sph_skein512_context    skein;
    sph_jh512_context       jh;
    sph_keccak512_context   keccak;
    sph_luffa512_context    luffa;
    sph_cubehash512_context cubehash;
    sph_shavite512_context  shavite;
    sph_simd512_context     simd;
    sph_echo512_context     echo;
}X11_context_holder;

X11_context_holder base_contexts;

void init_X11_contexts()
{
    sph_blake512_init(&base_contexts.blake);   
    sph_bmw512_init(&base_contexts.bmw);   
    sph_groestl512_init(&base_contexts.groestl);   
    sph_skein512_init(&base_contexts.skein);   
    sph_jh512_init(&base_contexts.jh);     
    sph_keccak512_init(&base_contexts.keccak); 
    sph_luffa512_init(&base_contexts.luffa);
    sph_cubehash512_init(&base_contexts.cubehash);
    sph_shavite512_init(&base_contexts.shavite);
    sph_simd512_init(&base_contexts.simd);
    sph_echo512_init(&base_contexts.echo);
}

// Thanks to Colin Percival (sgminer) for this:
be32enc_vect(uint32_t *dst, const uint32_t *src, uint32_t len)
{
	uint32_t i;
	for (i = 0; i < len; i++)
		dst[i] = htobe32(src[i]);
}
// Inline will speed it up

inline void X11_Hash(const void *input, void *state)
{
	init_X11_contexts();
	X11_context_holder ctx;
	
	uint32_t hashA[16], hashB[16];
	//Order: Blake > Bmw > Groestl > Sken > Jh > Meccak > Luffa > Cubehash > Shivite > Simd > Echo
	memcpy(&ctx, &base_contexts, sizeof(base_contexts));
	
	sph_blake512 (&ctx.blake, input, 80);
	sph_blake512_close (&ctx.blake, hashA);
	sph_bmw512 (&ctx.bmw, hashA, 64);    
    sph_bmw512_close(&ctx.bmw, hashB);     
  
    sph_groestl512 (&ctx.groestl, hashB, 64); 
    sph_groestl512_close(&ctx.groestl, hashA);
   
    sph_skein512 (&ctx.skein, hashA, 64); 
    sph_skein512_close(&ctx.skein, hashB); 
   
    sph_jh512 (&ctx.jh, hashB, 64); 
    sph_jh512_close(&ctx.jh, hashA);
  
    sph_keccak512 (&ctx.keccak, hashA, 64); 
    sph_keccak512_close(&ctx.keccak, hashB);
    
    sph_luffa512 (&ctx.luffa, hashB, 64);
    sph_luffa512_close (&ctx.luffa, hashA);    
        
    sph_cubehash512 (&ctx.cubehash, hashA, 64);   
    sph_cubehash512_close(&ctx.cubehash, hashB);  
    
    sph_shavite512 (&ctx.shavite, hashB, 64);   
    sph_shavite512_close(&ctx.shavite, hashA);  
    
    sph_simd512 (&ctx.simd, hashA, 64);   
    sph_simd512_close(&ctx.simd, hashB); 
    
    sph_echo512 (&ctx.echo, hashB, 64);   
    sph_echo512_close(&ctx.echo, hashA);    

    memcpy(state, hashA, 32);

}

static const uint32_t diff1targ = 0x0000ffff;

bool scanhash_darkcoin(struct thr_info *thr, const unsigned char __maybe_unused *pmidstate,
		     unsigned char *pdata, unsigned char __maybe_unused *phash1,
		     unsigned char __maybe_unused *phash, const unsigned char *ptarget,
		     uint32_t max_nonce, uint32_t *last_nonce, uint32_t n)
{
	uint32_t *nonce = (uint32_t *)(pdata + 76);
	char *scratchbuf;
	uint32_t data[20];
	uint32_t tmp_hash7;
	uint32_t Htarg = le32toh(((const uint32_t *)ptarget)[7]);
	bool ret = false;

	be32enc_vect(data, (const uint32_t *)pdata, 19);

	while(1) {
		uint32_t ostate[8];

		*nonce = ++n;
		data[19] = (n);
		xhash(ostate, data);
		tmp_hash7 = (ostate[7]);

		applog(LOG_INFO, "data7 %08lx",
					(long unsigned int)data[7]);

		if (unlikely(tmp_hash7 <= Htarg)) {
			((uint32_t *)pdata)[19] = htobe32(n);
			*last_nonce = n;
			ret = true;
			break;
		}

		if (unlikely((n >= max_nonce) || thr->work_restart)) {
			*last_nonce = n;
			break;
		}
	}

	return ret;
}
