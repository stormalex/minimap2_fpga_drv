#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "mem.h"

#define MEM_SIZE    20 * 1024 *1024
#define ALLOC_NUM   20

int main(int argc, char* argv[])
{
    int i = 0;
    int ret = 0;
    unsigned int size[ALLOC_NUM];
    void *addr[ALLOC_NUM] = {NULL};
    void *p = malloc(MEM_SIZE);
    if(p == NULL) {
        printf("malloc failed\n");
        exit(1);
    }
    struct mem_pool* pool = mem_pool_init(p, MEM_SIZE);
    if(pool == NULL) {
        printf("mem_pool_init failed\n");
        free(p);
        exit(1);
    }
    
    for(i = 0; i < ALLOC_NUM; i++) {
        size[i] = 256;
        addr[i] = mem_pool_alloc(pool, &(size[i]));
        printf("[%d]0x%016llx - 0x%016llx\n", i, addr[i] ,addr[i] + size[i]);
    }
    
    mem_pool_print_blocks(pool);
    
    printf("free addr[1]=0x%016llx\n", addr[1]);
    ret = mem_pool_free(pool, addr[1], size[1]);
    if(ret != 0) {
        printf("mem_pool_free failed\n");
    }
    printf("free addr[3]=0x%016llx\n", addr[3]);
    ret = mem_pool_free(pool, addr[3], size[3]);
    if(ret != 0) {
        printf("mem_pool_free failed\n");
    }
    printf("free addr[4]=0x%016llx\n", addr[4]);
    ret = mem_pool_free(pool, addr[4], size[4]);
    if(ret != 0) {
        printf("mem_pool_free failed\n");
    }
    printf("free addr[0]=0x%016llx\n", addr[0]);
    ret = mem_pool_free(pool, addr[0], size[0]);
    if(ret != 0) {
        printf("mem_pool_free failed\n");
    }
    printf("free addr[2]=0x%016llx\n", addr[2]);
    ret = mem_pool_free(pool, addr[2], size[2]);
    if(ret != 0) {
        printf("mem_pool_free failed\n");
    }
    
    printf("free addr[6]=0x%016llx\n", addr[6]);
    ret = mem_pool_free(pool, addr[6], size[6]);
    if(ret != 0) {
        printf("mem_pool_free failed\n");
    }
    
    printf("free addr[8]=0x%016llx\n", addr[8]);
    ret = mem_pool_free(pool, addr[8], size[8]);
    if(ret != 0) {
        printf("mem_pool_free failed\n");
    }
    
    printf("free addr[10]=0x%016llx\n", addr[10]);
    ret = mem_pool_free(pool, addr[10], size[10]);
    if(ret != 0) {
        printf("mem_pool_free failed\n");
    }
    
    mem_pool_print_blocks(pool);
    
    mem_pool_finalize(pool);
}