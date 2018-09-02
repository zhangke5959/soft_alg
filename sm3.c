#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/cryptohash.h>
#include <crypto/internal/hash.h>

#define DEBUG 1

typedef struct {
	spinlock_t vpn_sm3_lock;
	unsigned int total[2];      /*!< number of bytes processed  */
	unsigned int state[8];      /*!< intermediate digest state  */
	unsigned char buffer[64];   /*!< data block being processed */
	unsigned char ipad[64];     /*!< HMAC: inner padding        */
	unsigned char opad[64];     /*!< HMAC: outer padding        */
} vpn_sm3_ctx;

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_ULONG_BE
#define GET_ULONG_BE(n,b,i)                               \
{                                                         \
	(n) =     ( (unsigned int) (b)[(i)    ] << 24 )   \
		| ( (unsigned int) (b)[(i) + 1] << 16 )   \
		| ( (unsigned int) (b)[(i) + 2] <<  8 )   \
		| ( (unsigned int) (b)[(i) + 3]       );  \
}
#endif

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                              \
{                                                        \
	(b)[(i)    ] = (unsigned char) ( (n) >> 24 );    \
	(b)[(i) + 1] = (unsigned char) ( (n) >> 16 );    \
	(b)[(i) + 2] = (unsigned char) ( (n) >>  8 );    \
	(b)[(i) + 3] = (unsigned char) ( (n)       );    \
}
#endif

/*
 * SM3 context setup
 */
int sm3_starts( struct shash_desc *desc )
{
	vpn_sm3_ctx *ctx = shash_desc_ctx(desc);
	ctx->total[0] = 0;
	ctx->total[1] = 0;

	ctx->state[0] = 0x7380166F;
	ctx->state[1] = 0x4914B2B9;
	ctx->state[2] = 0x172442D7;
	ctx->state[3] = 0xDA8A0600;
	ctx->state[4] = 0xA96F30BC;
	ctx->state[5] = 0x163138AA;
	ctx->state[6] = 0xE38DEE4D;
	ctx->state[7] = 0xB0FB0E4E;
	return 0;
}

static void sm3_process( vpn_sm3_ctx *ctx, unsigned char data[64] )
{
	unsigned int SS1, SS2, TT1, TT2, W[68],W1[64];
	unsigned int A, B, C, D, E, F, G, H;
	unsigned int T[64];
	unsigned int Temp1,Temp2,Temp3,Temp4,Temp5;
	int j;
#ifdef ALG_DEBUG
	int i;
#endif

	// 	for(j=0; j < 68; j++)
	// 		W[j] = 0;
	// 	for(j=0; j < 64; j++)
	// 		W1[j] = 0;

	for(j = 0; j < 16; j++)
		T[j] = 0x79CC4519;
	for(j =16; j < 64; j++)
		T[j] = 0x7A879D8A;

	GET_ULONG_BE( W[ 0], data,  0 );
	GET_ULONG_BE( W[ 1], data,  4 );
	GET_ULONG_BE( W[ 2], data,  8 );
	GET_ULONG_BE( W[ 3], data, 12 );
	GET_ULONG_BE( W[ 4], data, 16 );
	GET_ULONG_BE( W[ 5], data, 20 );
	GET_ULONG_BE( W[ 6], data, 24 );
	GET_ULONG_BE( W[ 7], data, 28 );
	GET_ULONG_BE( W[ 8], data, 32 );
	GET_ULONG_BE( W[ 9], data, 36 );
	GET_ULONG_BE( W[10], data, 40 );
	GET_ULONG_BE( W[11], data, 44 );
	GET_ULONG_BE( W[12], data, 48 );
	GET_ULONG_BE( W[13], data, 52 );
	GET_ULONG_BE( W[14], data, 56 );
	GET_ULONG_BE( W[15], data, 60 );

#ifdef ALG_DEBUG
	printf("Message with padding:\n");
	for(i=0; i< 8; i++)
		printf("%08x ",W[i]);
	printf("\n");
	for(i=8; i< 16; i++)
		printf("%08x ",W[i]);
	printf("\n");
#endif

#define FF0(x,y,z) ( (x) ^ (y) ^ (z)) 
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x,y,z) ( (x) ^ (y) ^ (z)) 
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )


#define  SHL(x,n) (((x) & 0xFFFFFFFF) << n)
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))
//#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n%32)))

#define P0(x) ((x) ^  ROTL((x),9) ^ ROTL((x),17)) 
#define P1(x) ((x) ^  ROTL((x),15) ^ ROTL((x),23)) 

	for(j = 16; j < 68; j++ )
	{
		//W[j] = P1( W[j-16] ^ W[j-9] ^ ROTL(W[j-3],15)) ^ ROTL(W[j - 13],7 ) ^ W[j-6];
		//Why thd release's result is different with the debug's ?
		//Below is okay. Interesting, Perhaps VC6 has a bug of Optimizaiton.

		Temp1 = W[j-16] ^ W[j-9];
		Temp2 = ROTL(W[j-3],15);
		Temp3 = Temp1 ^ Temp2;
		Temp4 = P1(Temp3);
		Temp5 =  ROTL(W[j - 13],7 ) ^ W[j-6];
		W[j] = Temp4 ^ Temp5;
	}

#ifdef ALG_DEBUG
	printf("Expanding message W0-67:\n");
	for(i=0; i<68; i++)
	{
		printf("%08x ",W[i]);
		if(((i+1) % 8) == 0) printf("\n");
	}
	printf("\n");
#endif

	for(j =  0; j < 64; j++)
	{
		W1[j] = W[j] ^ W[j+4];
	}

#ifdef ALG_DEBUG
	printf("Expanding message W'0-63:\n");
	for(i=0; i<64; i++)
	{
		printf("%08x ",W1[i]);
		if(((i+1) % 8) == 0) printf("\n");
	}
	printf("\n");
#endif

	A = ctx->state[0];
	B = ctx->state[1];
	C = ctx->state[2];
	D = ctx->state[3];
	E = ctx->state[4];
	F = ctx->state[5];
	G = ctx->state[6];
	H = ctx->state[7];
#ifdef ALG_DEBUG
	printf("j     A       B        C         D         E        F        G       H\n");
	printf("   %08x %08x %08x %08x %08x %08x %08x %08x\n",A,B,C,D,E,F,G,H);
#endif

	for(j =0; j < 16; j++)
	{
		SS1 = ROTL((ROTL(A,12) + E + ROTL(T[j],j)), 7); 
		SS2 = SS1 ^ ROTL(A,12);
		TT1 = FF0(A,B,C) + D + SS2 + W1[j];
		TT2 = GG0(E,F,G) + H + SS1 + W[j];
		D = C;
		C = ROTL(B,9);
		B = A;
		A = TT1;
		H = G;
		G = ROTL(F,19);
		F = E;
		E = P0(TT2);
#ifdef ALG_DEBUG
		printf("%02d %08x %08x %08x %08x %08x %08x %08x %08x\n",j,A,B,C,D,E,F,G,H);
#endif
	}

	for(j =16; j < 64; j++)
	{
		SS1 = ROTL((ROTL(A,12) + E + ROTL(T[j],j)), 7); 
		SS2 = SS1 ^ ROTL(A,12);
		TT1 = FF1(A,B,C) + D + SS2 + W1[j];
		TT2 = GG1(E,F,G) + H + SS1 + W[j];
		D = C;
		C = ROTL(B,9);
		B = A;
		A = TT1;
		H = G;
		G = ROTL(F,19);
		F = E;
		E = P0(TT2);
#ifdef ALG_DEBUG
		printf("%02d %08x %08x %08x %08x %08x %08x %08x %08x\n",j,A,B,C,D,E,F,G,H);
		printf("%02d %08x %08x %08x %08x %08x %08x %08x %08x\n",j,A,B,C,D,E,F,G,H);
#endif	
	}

	ctx->state[0] ^= A;
	ctx->state[1] ^= B;
	ctx->state[2] ^= C;
	ctx->state[3] ^= D;
	ctx->state[4] ^= E;
	ctx->state[5] ^= F;
	ctx->state[6] ^= G;
	ctx->state[7] ^= H;
#ifdef ALG_DEBUG
	printf("   %08x %08x %08x %08x %08x %08x %08x %08x\n",ctx->state[0],ctx->state[1],ctx->state[2],
			ctx->state[3],ctx->state[4],ctx->state[5],ctx->state[6],ctx->state[7]);
#endif
}

/*
 * SM3 process buffer
 */
int sm3_update(struct shash_desc *desc, const u8 *input, unsigned int ilen)
{
	vpn_sm3_ctx *ctx = shash_desc_ctx(desc);
	int fill;
	unsigned int left;

#if DEBUG
	printk(" function: %s ,  line= %d \n", __FUNCTION__, __LINE__);
#endif
	if( ilen <= 0 )
		return -1;

	left = ctx->total[0] & 0x3F;
	fill = 64 - left;

	ctx->total[0] += ilen;
	ctx->total[0] &= 0xFFFFFFFF;

	if( ctx->total[0] < (unsigned int) ilen )
		ctx->total[1]++;

	if( left && ilen >= fill )
	{
		memcpy( (void *) (ctx->buffer + left),
				(void *) input, fill );
		sm3_process( ctx, ctx->buffer );
		input += fill;
		ilen  -= fill;
		left = 0;
	}

	while( ilen >= 64 )
	{
		sm3_process( ctx, (u8*)input );
		input += 64;
		ilen  -= 64;
	}

	if( ilen > 0 )
	{
		memcpy( (void *) (ctx->buffer + left),
				(void *) input, ilen );
	}
	return 0;
}

static unsigned char sm3_padding[64] =
{
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * SM3 final digest
 */
int sm3_finish( struct shash_desc *desc, u8 *output)
{
	vpn_sm3_ctx *ctx = shash_desc_ctx(desc);

	unsigned int last, padn;
	unsigned int high, low;
	unsigned char msglen[8];
#if DEBUG
	printk(" function: %s ,  line= %d \n", __FUNCTION__, __LINE__);
#endif

	high = ( ctx->total[0] >> 29 )
		| ( ctx->total[1] <<  3 );
	low  = ( ctx->total[0] <<  3 );

	PUT_ULONG_BE( high, msglen, 0 );
	PUT_ULONG_BE( low,  msglen, 4 );

	last = ctx->total[0] & 0x3F;
	padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

	sm3_update(desc, (const u8 *)sm3_padding, padn );
	sm3_update(desc, msglen, 8 );

	PUT_ULONG_BE( ctx->state[0], output,  0 );
	PUT_ULONG_BE( ctx->state[1], output,  4 );
	PUT_ULONG_BE( ctx->state[2], output,  8 );
	PUT_ULONG_BE( ctx->state[3], output, 12 );
	PUT_ULONG_BE( ctx->state[4], output, 16 );
	PUT_ULONG_BE( ctx->state[5], output, 20 );
	PUT_ULONG_BE( ctx->state[6], output, 24 );
	PUT_ULONG_BE( ctx->state[7], output, 28 );
	return 0;
}

int sm3_finup(struct shash_desc *desc, const u8 *data,
		unsigned int len, u8 *out)
{
#if DEBUG
	printk(" function: %s ,  line= %d \n", __FUNCTION__, __LINE__);
#endif

	sm3_starts(desc);
	sm3_update(desc, data, len);
	return sm3_finish(desc, out);
}

struct shash_alg sm3_alg = {
	.digestsize	=	32,
	.init		=	sm3_starts,
	.update		=	sm3_update,
	.final		=	sm3_finish,
	.finup		=	sm3_finup,
	.descsize	=	sizeof(vpn_sm3_ctx),
	.base		=	{
		.cra_name	=	"sm3",
		.cra_driver_name=	"sm3-generic",
		.cra_flags	=	CRYPTO_ALG_TYPE_SHASH,
		.cra_blocksize	=	64,
		.cra_module	=	THIS_MODULE,
	}
};

int sm3_init(void)
{
	printk(" function: %s ,  line= %d \n", __FUNCTION__, __LINE__);
	return crypto_register_shash(&sm3_alg);
}

void sm3_fini(void)
{
	printk(" function: %s ,  line= %d \n", __FUNCTION__, __LINE__);
	crypto_unregister_shash(&sm3_alg);
}
