#include <linux/module.h>

void printHexT(unsigned char *name, unsigned char *c, int n)
{
	int i;
	printk ("\n---------------------[%s ,len = %d, start ]----------------------\n",name,n);
	for (i = 0; i < n; i++) {
		printk("%02X", c[i]);
		if ((i%4) == 3)
		    printk(" ");        

		if ((i%16) == 15)
		    printk("\n");        
	}
	if ((i%16) != 0)
		printk("\n");
	printk("----------------------[%s       end        ]----------------------\n",name);
}
