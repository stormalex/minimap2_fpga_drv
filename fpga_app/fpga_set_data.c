#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>

#include "../fpga_lib/fpga.h"
#include "../common/common.h"

int main(int argc, char* argv[])
{
    unsigned int i =0;
    int ret;
    
    fpga_init(BLOCK);
    
    fpga_test();
    
    fpga_finalize();
    return 0;
}