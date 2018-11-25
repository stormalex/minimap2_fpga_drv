#ifndef __BLOCK_H__
#define __BLOCK_H__

struct block_handle {
    void* addr;
    int size;
};

int block_init(int block_flag);
void block_finalize();
int block_alloc(void *addr[], int n, unsigned long size);
void block_free(void *addr[], int n, unsigned long size);
unsigned long addr_to_offset(void *addr);
void *offset_to_addr(unsigned long offset);

void* mem_alloc(unsigned long *size);
void mem_free(void *addr, unsigned long size);

#endif //__BLOCK_H__