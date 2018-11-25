#!/bin/bash

rmmod fpga_drv
rmmod mem_drv

cd fpga_drv
make clean
cd -
cd mem_drv
make clean
make
insmod mem_drv.ko
cd -
cd fpga_drv
make
insmod fpga_drv.ko
cd -
cd fpga_lib
make clean
make
cd -
chmod 777 /dev/dma_mem_0
chmod 777 /dev/fpga_lyy
chmod 777 /dev/fpga_gsb
