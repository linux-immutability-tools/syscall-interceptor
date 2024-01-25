obj-m	:= src/intercept.o
KERNELDIR ?= /usr/src/linux
PWD       := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
