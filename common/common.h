#ifndef __COMMON_H__
#define __COMMON_H__

enum {
    E_OK = 0,
    E_NOMEM,
    E_INVAL,
};

struct buf_info {
    unsigned int index;
    unsigned int size;
};

struct test_data {
    unsigned long long data;
    unsigned int offset;
};

struct data_info {
    unsigned int offset;
    unsigned int data_size;
    unsigned int type;
};

#define K_RET_TYPE_SW 0
#define K_RET_TYPE_CD 1
#define K_RET_TYPE_CS 3

#ifndef ALIGN
#define ALIGN(x, a)         (((x) + ((a) - 1)) & ~((a) - 1))
#endif

#define MAX_TASK_NUM        (512)

#define DMA_BUF_SIZE        (4 * 1024 * 1024)

//#define DMA_MEM_SIZE        (0x200000000)         //8G
#define DMA_MEM_SIZE        (0x80000000)         //2G
//#define DMA_MEM_SIZE          (0x100000000)         //4G

#define BLOCK_MEM_NUM        (512)
#define BLOCK_MEM_SIZE      (4 * 1024 * 1024)

#define FPGA_IOCTL_MAGIC 'F'

#define FPGA_INIT               _IO(FPGA_IOCTL_MAGIC, 0)     //init driver

#define FPGA_SET_BUFS_MAP       _IOW(FPGA_IOCTL_MAGIC, 1, unsigned int)     //set map result buf index

#define FPGA_SET_REG_MAP        _IO(FPGA_IOCTL_MAGIC, 3)
#define FPGA_APPLY_RESULT_BUF   _IOR(FPGA_IOCTL_MAGIC, 4, struct buf_info*)    //apply a valid result buf
#define FPGA_RETURN_RESULT_BUF  _IOW(FPGA_IOCTL_MAGIC, 5, unsigned int)     //return a invalid result buf
#define FPGA_APPLY_WRITE_BUF    _IOR(FPGA_IOCTL_MAGIC, 6, unsigned int*)    //get bar space size for map
#define FPGA_WRITE_BUF_SUBMIT   _IOW(FPGA_IOCTL_MAGIC, 7, struct buf_info*)
#define FPGA_EXIT_BLOCK         _IO(FPGA_IOCTL_MAGIC, 8)        //exit block

#define FPGA_SET_DATA           _IOW(FPGA_IOCTL_MAGIC, 10, unsigned int)     //set data to buf, for test
#define FPGA_IRQ                _IO(FPGA_IOCTL_MAGIC, 11)
#define FPGA_TEST_WRITE         _IOWR(FPGA_IOCTL_MAGIC, 12, struct test_data*)
#define FPGA_TEST_READ          _IOWR(FPGA_IOCTL_MAGIC, 13, struct test_data*)


#endif //__COMMON_H__