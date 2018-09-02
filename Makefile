#
#

TOPDIR		?= /lib/modules/$(shell uname -r)/build

obj-m		+= soft_alg.o
soft_alg-objs	= main_alg.o
soft_alg-objs	+= sm3.o
soft_alg-objs	+= sm4.o
soft_alg-objs	+= rng.o
soft_alg-objs	+= debug.o

obj-m			+= soft_sm3_test.o
soft_sm3_test-objs	= sm3_test.o
soft_sm3_test-objs	+= debug.o

obj-m			+= soft_sm4_test.o
soft_sm4_test-objs	= sm4_test.o
soft_sm4_test-objs	+= debug.o

obj-m			+= soft_rng_test.o
soft_rng_test-objs	= rng_test.o
soft_rng_test-objs	+= debug.o


EXTRA_CFLAGS	+= -I$(src)/include

all:
	make -C $(TOPDIR) M=$(PWD) modules

clean:
	make -C $(TOPDIR) M=$(PWD) clean

mrproper:	clean
	$(RM) *~ *.tgz tags
