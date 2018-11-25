#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/time.h>

#include "user_common.h"
#include "common.h"
#include "mem.h"


static int g_fd = -1;
static void* g_addr = NULL;
static struct mem_pool* g_mem_pool;
static int g_block_flag = 0;

int block_init(int block_flag)
{
    unsigned int i = 0;
    int j = 0;
    int ret = 0;
    
    g_block_flag = block_flag;
    
    g_fd = open("/dev/dma_mem_0", O_RDWR);
    if(g_fd < 0) {
        ERROR("open /dev/dma_mem_0 failed, %s", strerror(errno));
        return -1;
    }
    DEBUG("mmap length=%lu", (size_t)DMA_MEM_SIZE);
    g_addr = mmap(NULL, DMA_MEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED , g_fd, 0);
    if(g_addr == MAP_FAILED) {
        ERROR("mmap failed, %s", strerror(errno));
        close(g_fd);
        return -1;
    }
    
    DEBUG("MEM pool:%p - %p", g_addr, g_addr + DMA_MEM_SIZE);
    
    g_mem_pool = mem_pool_init(g_addr, DMA_MEM_SIZE);
    if(g_mem_pool == NULL) {
        ERROR("mem_pool_init failed");
        return -1;
    }
    
    return 0;
}

void block_finalize()
{

    mem_pool_finalize(g_mem_pool);
    munmap(g_addr, DMA_MEM_SIZE);
    
    close(g_fd);
    g_fd = -1;
    
    g_block_flag = 0;
    
    return;
}

unsigned long addr_to_offset(void *addr)
{
    if(g_addr != NULL && addr >= g_addr && addr < (g_addr + DMA_MEM_SIZE)) {
        return (addr - g_addr);
    }
    return 0xffffffff;
}

void *offset_to_addr(unsigned long offset)
{
    if(offset <= DMA_MEM_SIZE) {
        return (g_addr + offset);
    }
    return NULL;
}

int block_alloc(void *addr[], int n, unsigned long size)
{
    int i = 0;
    int j = 0;
    int ret = E_OK;
    unsigned long real_size = size;
    
    for(i = 0; i < n; i++) {
        ret = mem_pool_alloc(g_mem_pool, &addr[i], &real_size, g_block_flag);
        if(ret != E_OK) {
            for(j = i - 1; i > 0; j--) {
                mem_pool_free(g_mem_pool, addr[j], size);
            }
            return -1;
        }
        if(real_size != size) {
            ERROR("block alloc, size=%d, real_size=%d", size, real_size);
        }
        //DEBUG("[%d]alloc %lu", i, real_size);
    }
    return 0;
}

void block_free(void *addr[], int n, unsigned int size)
{
    int i = 0;
    
    for(i = 0; i < n; i++) {
        mem_pool_free(g_mem_pool, addr[i], size);
    }
}

void* mem_alloc(unsigned long *size)
{
    void* addr;
    int ret;
    ret = mem_pool_alloc(g_mem_pool, &addr, size, g_block_flag);
    if(ret == ENOMEM) {
        return NULL;
    }

    return addr;
}

void mem_free(void *addr, unsigned int size)
{
    if(mem_pool_free(g_mem_pool, addr, size) != 0) {
        ERROR("mem_pool_free failed");
    }
}
