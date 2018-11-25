obj-m := mem_drv.o  
KERNELDR := /home/ljb/rpmbuild/BUILD/kernel-3.10.0-693.21.1.el7/linux-3.10.0-693.21.1.el7.x86_64
PWD := $(shell pwd)  
modules:  
	$(MAKE) -C $(KERNELDR) M=$(PWD) modules
	cp Module.symvers ../fpga_drv
moduels_install:  
	$(MAKE) -C $(KERNELDR) M=$(PWD) modules_install  
clean:  
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions *.order *.symvers  
