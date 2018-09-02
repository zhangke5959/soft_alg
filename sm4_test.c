#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <linux/delay.h>
#include <linux/scatterlist.h>
#include <crypto/aead.h>
#include <crypto/skcipher.h>

#include "debug.h"

int sm4_test(void)
{
	unsigned char key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
	unsigned char src[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
	unsigned char dst[16];
	int ret = 0;
	struct crypto_cipher *tfm;
	char *algo = "sm4";

	tfm = crypto_alloc_cipher(algo, CRYPTO_ALG_TESTED, 0);

	if (IS_ERR(tfm)) {
		pr_err("alg: aead: Failed to load transform for %s: %ld\n", algo,
		       PTR_ERR(tfm));
	}

	crypto_cipher_setkey(tfm, key, 16);
	crypto_cipher_encrypt_one(tfm, dst, src);
	memset(src, 0, 16);
	crypto_cipher_decrypt_one(tfm, src, dst);
	crypto_free_cipher(tfm);

	printHexT("dst", dst, 16);
	printHexT("src", src, 16);

	return ret;
}

static int __init sm4_init(void)
{

	printk("This module just test how to use alg APIn \n");

	if(sm4_test()){
		printk("hash alg failed \n");
		return -1;
	}

	printk("sm4 alg succeeded \n");

	return 0;
}

static void __exit sm4_exit(void)
{
	printk("Test is over!!! \n");
	return ;
}

module_init(sm4_init);
module_exit(sm4_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("zk");
