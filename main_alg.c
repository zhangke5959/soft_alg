#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/cryptohash.h>
#include <linux/crypto.h>

extern int vpn_rng_init(void);
extern void vpn_rng_exit(void);
extern int sm3_init(void);
extern void sm3_fini(void);
extern int sm4_init(void);
extern void sm4_fini(void);

static int __init soft_alg_init(void)
{
	vpn_rng_init();
	sm3_init();
	sm4_init();
	return 0;
}

static void __exit soft_alg_fini(void)
{
	vpn_rng_exit();
	sm3_fini();
	sm4_fini();
}

module_init(soft_alg_init);
module_exit(soft_alg_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("soft sm3 sm4 Algorithm");
