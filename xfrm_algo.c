
#define SADB_X_AALG_SM3_256HMAC		10
static struct xfrm_algo_desc aalg_list[] = {
{
	.name = "hmac(sm3)",
	.compat = "sm3",

	.uinfo = {
		.auth = {
			.icv_truncbits = 256,
			.icv_fullbits = 256,
		}
	},

	.pfkey_supported = 1,

	.desc = {
		.sadb_alg_id = SADB_X_AALG_sm3_256HMAC,
		.sadb_alg_ivlen = 0,
		.sadb_alg_minbits = 256,
		.sadb_alg_maxbits = 256
	}
},
};

#define SADB_X_EALG_SM4CBC		24	
static struct xfrm_algo_desc ealg_list[] = {
{
	.name = "cbc(sm4)",
	.compat = "sm4",

	.uinfo = {
		.encr = {
			.blockbits = 128,
			.defkeybits = 128,
		}
	},

	.pfkey_supported = 1,

	.desc = {
		.sadb_alg_id = SADB_X_EALG_SM4CBC,
		.sadb_alg_ivlen = 16,
		.sadb_alg_minbits = 128,
		.sadb_alg_maxbits = 256
	}
},
