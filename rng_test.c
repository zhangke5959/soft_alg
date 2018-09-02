#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <linux/delay.h>
#include <crypto/rng.h>

int vpn_rng_test(void)
{
	int ret = 0;
	struct crypto_rng *rng;
	unsigned char data[16];

	rng = crypto_alloc_rng("vpnrng", 0, 0);
	if (IS_ERR(rng))
		goto err;

	ret = crypto_rng_reset(rng, NULL, 16);
	if (ret) {
		crypto_free_rng(rng);
		goto err;
	}
	crypto_rng_get_bytes(rng,data, 16);
	crypto_free_rng(rng);
	printk("data: %d,%d,%d,%d,%d,%d,%d,%d \n",
			data[0],data[1],data[2],data[3],
			data[4],data[5],data[6],data[7]);

	return ret;
err:
	printk(" rng err \n");
	return -1;
}

static int __init vpn_rng_init(void)
{

	printk("This module just test how to use alg APIn \n");
	if(vpn_rng_test()){
		printk("rng alg failed \n");
		return -1;
	}
	printk("rng alg succeeded \n");

	return 0;
}

static void __exit vpn_rng_exit(void)
{
	printk("Test is over!!! \n");
	return ;
}

module_init(vpn_rng_init);
module_exit(vpn_rng_exit);
MODULE_LICENSE("GPL");
