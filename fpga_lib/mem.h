#ifndef __MEM_H__
#define __MEM_H__

struct mem_pool;

struct mem_pool* mem_pool_init(void* addr, unsigned long size);
void mem_pool_finalize(struct mem_pool* pool);
int mem_pool_alloc(struct mem_pool* pool, void **addr, unsigned long *size, int block_flag);
int mem_pool_free(struct mem_pool* pool, void* addr, unsigned long size);
void mem_pool_print_blocks(struct mem_pool* pool);

#endif  //__MEM_H__