#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/cryptohash.h>
#include <crypto/internal/hash.h>
#include <linux/slab.h>
#include <linux/crypto.h>

#include "debug.h"

static char str[128] = {
		0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
                0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
                0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
                0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,0x61,0x62,0x63,0x64,
	};

static char out[128] = {
		0xde,0xbe,0x9f,0xf9,0x22,0x75,0xb8,0xa1,0x38,0x60,0x48,0x89,0xc1,0x8e,0x5a,0x4d,
                0x6f,0xdb,0x70,0xe5,0x38,0x7e,0x57,0x65,0x29,0x3d,0xcb,0xa3,0x9c,0x0c,0x57,0x32};

static u32 len = 64;

int sm3_hash(const char *str, u32 len,u8 *out)
{
	u32 digestsize = 0;
	u32 size = 0;
	struct shash_desc *ssm3;
	int err = 0;

	struct crypto_shash *sm3 = crypto_alloc_shash("sm3",0,0);

	if(IS_ERR(sm3)) {
		printk("sm3 transform alloc failed! \n");
		return -1;
	}

	size = sizeof(struct shash_desc) + crypto_shash_descsize(sm3);
	ssm3 = kmalloc(size,GFP_KERNEL);
	if(!ssm3) {
		err = -1;
		goto Kmalloc_err;
	}

	ssm3->tfm = sm3;
	ssm3->flags = 0x0;
	err = crypto_shash_init(ssm3);
	if(err){
		err = -1;
		goto init_err;
	}

	printk("plain length is %d \n",len);
	printHexT("sm3 compare data", out, 32);
	crypto_shash_update(ssm3,str,len);
	err = crypto_shash_final(ssm3,out);

	printHexT("sm3", out, 32);

	printk("sm3 result is %d \n",err);

	digestsize = crypto_shash_digestsize(sm3);
	printk("digest size is %d \n",digestsize);

init_err:
	kfree(ssm3);
Kmalloc_err:
	crypto_free_shash(sm3);
	return err;
}

static int __init sm3_init(void)
{

	printk("This module just test how to use alg APIn \n");

	if(sm3_hash(str, len, out) == -1){
		printk("hash alg failed \n");
		return -1;
	}

	printk("sm3 alg succeeded \n");
	return 0;
}

static void __exit sm3_exit(void)
{
	printk("Test is over!!! \n");
	return ;
}

module_init(sm3_init);
module_exit(sm3_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("zk");
