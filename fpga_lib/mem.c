#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "common.h"
#include "mem.h"
#include "user_common.h"
#include "fpga.h"

struct slot {
    struct slot* next;
    unsigned long size;
};

struct mem_pool {
    size_t addr;
    size_t addr_end;
    unsigned long size;
    unsigned long max_block_size;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    struct slot *next;
};

struct mem_pool* mem_pool_init(void* addr, unsigned long size)
{
    struct slot* slot = NULL;
    
    if(size < sizeof(struct slot)) {
        return NULL;
    }
    
    struct mem_pool* pool = malloc(sizeof(struct mem_pool));
    if(pool == NULL) {
        return NULL;
    }
    DEBUG("mem pool range:%p - %p, size:%lu %p", addr, (char *)addr + size, size, size);
    pool->addr = (size_t)addr;
    pool->addr_end = (size_t)addr + size;
    pool->size = size;
    
    slot = (struct slot*)addr;
    slot->next = NULL;
    slot->size = size;
    
    
    if(pthread_mutex_init(&pool->mutex, NULL)) {
        free(pool);
        return NULL;
    }
    
    if(pthread_cond_init(&pool->cond, NULL)) {
        free(pool);
        return NULL;
    }
    
    pool->next = (struct slot*)addr;
    
    return pool;
}

void mem_pool_finalize(struct mem_pool* pool)
{
    if(pool) {
        pthread_cond_destroy(&pool->cond);
        pthread_mutex_destroy(&pool->mutex);
        free(pool);
    }
    return;
}

int mem_pool_alloc(struct mem_pool* pool, void **_addr, unsigned long *size, int block_flag)
{
    struct slot *cur;
    struct slot **prve;
    char *addr = NULL;
    unsigned int real_size = *size;

    *_addr = NULL;
    WARNING("alloc 1 size:%u, pool reserve size:%u  %p", real_size, pool->size, pool->size);
retry:
    pthread_mutex_lock(&pool->mutex);
    if(real_size > pool->size) {
        if(block_flag == BLOCK) {
            pthread_cond_wait(&pool->cond, &pool->mutex);
            goto retry;
        }
        else {
            pthread_mutex_unlock(&pool->mutex);
            return E_NOMEM;
        }
    }
    
    cur = pool->next;
    prve = &(pool->next);
    while(*prve) {
        if(cur->size > (real_size + sizeof(struct slot))) {
            //printf("1.cur->size=%d\n", cur->size);
            cur->size -= real_size;
            addr = (char *)cur;
            addr = addr + cur->size;
            
            pool->size -= real_size;
            goto out;
        }
        else if(cur->size >= real_size && cur->size <= (real_size + sizeof(struct slot))) {
            unsigned int cur_size = cur->size;
            //printf("2.cur->size=%d\n", cur->size);
            
            if(cur->next == NULL) {     //last block
                addr = (char *)cur;
                *prve = NULL;
                //printf("!!!pool->next=0x%016llx\n", pool->next);
            }
            else {                      //not last block
                addr = (char *)cur;
                *prve = cur->next;
            }
            pool->size -= cur_size;
            *size = cur_size;
            goto out;
        }
        else {
            //printf("3.cur->size=%d\n", cur->size);
        }
        prve = &(cur->next);
        cur = *prve;
    }
    
out:
    pthread_mutex_unlock(&pool->mutex);

    if(block_flag == BLOCK && addr == NULL) {
        goto retry;
    }
    
    if(addr == NULL) {
        WARNING("NOMEM:alloc (%u), pool reserve size(%u)", real_size, pool->size);
        return E_NOMEM;
    }
    WARNING("alloc 2 pool reserve size:%u  %p", real_size, pool->size, pool->size);
    *_addr = addr;
    return E_OK;
}

int mem_pool_free(struct mem_pool* pool, void * const addr, unsigned long size)
{
    int ret = 0;
    struct slot *new_slot = addr;
    struct slot *cur = NULL;
    struct slot **prve = &pool->next;
    
    if(((unsigned long)addr >= pool->addr_end) && ((unsigned long)addr < pool->addr))
        return;
    
    new_slot->size = size;
    
    WARNING("free 1 addr(%p) size(%u)", addr, size);
    
    pthread_mutex_lock(&pool->mutex);
    
    if(pool->next == NULL) {
        pool->next = (struct slot*)addr;
        new_slot->next = NULL;
        pool->size += size;
    }
    else {
        if((size_t)addr < (size_t)(pool->next)) {
            if((size_t)((char *)addr + size) == (size_t)(pool->next)) {
                struct slot *tmp = pool->next;
                pool->next = (struct slot*)addr;
                pool->next->size = size + tmp->size;
                pool->next->next = tmp->next;
                
                pool->size += size;
                
            }
            else if((size_t)((char *)addr + size) < (size_t)(pool->next)) {
                struct slot* tmp = pool->next;
                pool->next = (struct slot*)addr;
                new_slot->next = tmp;
                
                pool->size += size;
                
            }
            else if((size_t)((char *)addr + size) > (size_t)(pool->next)) {
                ERROR("addr=0x%016llx, size=%d, pool->next=0x%016llx\n", addr, size, pool->next);
                ret = -1;
                goto out;
            }
        }
        else if((size_t)addr == (size_t)(pool->next)) {
            ERROR("addr=0x%016llx, pool->next=0x%016llx", addr, pool->next);
            ret = -1;
            goto out;
        }
        else if((size_t)addr > (size_t)(pool->next)) {
            while(*prve) {
                cur = *prve;
                
                if(cur->next == NULL) {
                    if((size_t)((char *)cur + cur->size) > (size_t)addr) {
                        ERROR("cur=0x%016llx - 0x%016llx, addr=0x%016llx", cur, (char *)cur + cur->size,addr);
                        ret = -1;
                        goto out;
                    }
                    else if((size_t)((char *)cur + cur->size) == (size_t)addr) {
                        cur->size += size;
                        
                        pool->size += size;
                        goto out;
                    }
                    else {
                        cur->next = addr;
                        ((struct slot *)addr)->next = NULL;
                        ((struct slot *)addr)->size = size;
                        
                        pool->size += size;
                        goto out;
                    }
                }
                else {
                    if((size_t)((char *)cur + cur->size) <= (size_t)addr && (size_t)((char *)addr + size) <= (size_t)(cur->next)) {
                        struct slot* tmp = cur->next;
                        cur->next = (struct slot*)addr;
                        cur->next->next = tmp;
                        
                        if((size_t)((char *)addr + size) == (size_t)(((struct slot*)addr)->next)) {
                            struct slot* tmp = ((struct slot*)addr)->next->next;
                            ((struct slot*)addr)->size += ((struct slot*)addr)->next->size;
                            ((struct slot*)addr)->next = tmp;
                            
                        }
                        
                        if((size_t)((char *)cur + cur->size) == (size_t)addr) {
                            cur->next = ((struct slot*)addr)->next;
                            cur->size += ((struct slot*)addr)->size;
                        }
                        pool->size += size;
                        
                        goto out;
                    }
                }
                
                prve = &cur->next;
            }
        }
    }
    
out:
    pthread_cond_signal(&pool->cond);
    pthread_mutex_unlock(&pool->mutex);
    
    WARNING("free 2 pool reserve size(%u)", pool->size);
    
    return ret;
}

void mem_pool_print_blocks(struct mem_pool* pool)
{
    int i = 0;
    struct slot *cur = NULL;
    struct slot **prve = &(pool->next);
    char *addr = 0;
    
    pthread_mutex_lock(&pool->mutex);
    
    DEBUG("***********************memory***********************");
    DEBUG("     0x%016llx - 0x%016llx\n", pool->addr, pool->addr_end);
    DEBUG("********************free blocks*********************");
    while(*prve) {
        i++;
        cur = *prve;
        addr = (char *)cur;
        DEBUG("\n[%02d] 0x%016llx - 0x%016llx\n", i, addr, addr + cur->size);
        prve = &(cur->next);
    }
    DEBUG("****************************************************");
    
    pthread_mutex_unlock(&pool->mutex);
    
    return;
}
