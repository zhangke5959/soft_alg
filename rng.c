#include <linux/version.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fips.h>
#include <linux/time.h>
#include <linux/random.h>
#include <linux/crypto.h>
#include <crypto/internal/rng.h>
#include <crypto/rng.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(3,18,0)

struct vpn_rng_ctx {
	spinlock_t vpn_rng_lock;
};

static int vpn_rng_get_random(struct crypto_rng *tfm,
			     const u8 *src, unsigned int slen,
			     u8 *rdata, unsigned int dlen)
{
	struct vpn_rng_ctx *rng = crypto_rng_ctx(tfm);
	int ret = 0;

	spin_lock(&rng->vpn_rng_lock);
	get_random_bytes(rdata, dlen);
	spin_unlock(&rng->vpn_rng_lock);

	return ret;
}

static int _vpn_rng_init(struct crypto_tfm *tfm)
{
	struct vpn_rng_ctx *rng = crypto_tfm_ctx(tfm);
	int ret = 0;

	spin_lock_init(&rng->vpn_rng_lock);

	return ret;
}

static void _vpn_rng_cleanup(struct crypto_tfm *tfm)
{
	struct vpn_rng_ctx *rng = crypto_tfm_ctx(tfm);

	spin_lock(&rng->vpn_rng_lock);
	spin_unlock(&rng->vpn_rng_lock);
}

static int _vpn_rng_reset(struct crypto_rng *tfm,
			    const u8 *seed, unsigned int slen)
{
	return 0;
}

static struct rng_alg vpn_rng_alg = {
	.generate		= vpn_rng_get_random,
	.seed			= _vpn_rng_reset,
	.seedsize		= 0,
	.base			= {
		.cra_name               = "vpnrng",
		.cra_driver_name        = "vpnrng",
		.cra_priority           = 100,
		.cra_ctxsize            = sizeof(struct vpn_rng_ctx),
		.cra_module             = THIS_MODULE,
		.cra_init               = _vpn_rng_init,
		.cra_exit               = _vpn_rng_cleanup,

	}
};

int vpn_rng_init(void)
{
	return crypto_register_rng(&vpn_rng_alg);
}

void vpn_rng_exit(void)
{
	crypto_unregister_rng(&vpn_rng_alg);
}

#else

static int vpn_rng_get_random(struct crypto_rng *tfm, u8 *rdata, unsigned int dlen)
{
        get_random_bytes(rdata, dlen);
        return 0;
}

static int vpn_rng_reset(struct crypto_rng *tfm, u8 *seed, unsigned int slen)
{
        return 0;
}

static struct crypto_alg vpn_rng_alg = {
	.cra_name		= "vpnrng",
	.cra_driver_name	= "vpnrng",
	.cra_priority		= 100,
	.cra_flags		= CRYPTO_ALG_TYPE_RNG,
	.cra_ctxsize		= 0,
	.cra_type		= &crypto_rng_type,
	.cra_module		= THIS_MODULE,
	.cra_u			= {
		.rng = {
			.rng_make_random	= vpn_rng_get_random,
			.rng_reset		= vpn_rng_reset,
			.seedsize		= 0,
		}
	}
};

int vpn_rng_init(void)
{
	return crypto_register_alg(&vpn_rng_alg);
}

void vpn_rng_exit(void)
{
	crypto_unregister_alg(&vpn_rng_alg);
}
#endif
