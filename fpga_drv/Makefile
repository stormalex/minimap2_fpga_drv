obj-m += fpga_drv.o 
fpga_drv-objs:=fpga.o flash.o

KERNELDR := /home/ljb/rpmbuild/BUILD/kernel-3.10.0-693.21.1.el7/linux-3.10.0-693.21.1.el7.x86_64
PWD := $(shell pwd)

KBUILD_EXTRA_SYMBOLS += /home/ljb/minimap2_drv/mem_drv/Module.symvers
export KBUILD_EXTRA_SYMBOLS

modules:  
	$(MAKE) -C $(KERNELDR) M=$(PWD) modules  
moduels_install:  
	$(MAKE) -C $(KERNELDR) M=$(PWD) modules_install  
clean:  
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions *.order *.symvers  
