#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <pthread.h>
#include <signal.h>

#include "../common/common.h"
#include "fpga.h"
#include "block.h"
#include "rbtree_api.h"
#include "user_common.h"

#define ALIGN_SIZE  0x100000

static int g_fd_lyy = -1;
static int g_fd_gsb = -1;

static void* g_block_addr[BLOCK_MEM_NUM];
static int g_block_flag[BLOCK_MEM_NUM];
static pthread_mutex_t block_mutex;
static pthread_cond_t  block_cond;  

static void* g_block_addr_start = NULL;
static void* g_block_addr_end = NULL;

static struct rb_root rb_root = RB_ROOT;
static pthread_mutex_t rb_mutex;

static int block_flag = 0;

int fpga_init(int noblock)
{
    unsigned int i = 0;
    int j = 0;
    int ret = 0;
    
    if(block_init(noblock) != 0) {
        ERROR("block init failed\n");
        return -1;
    }
    DEBUG("block_init ok");

    if(noblock == NOBLOCK)
        g_fd_lyy = open("/dev/fpga_lyy", O_RDWR | O_NONBLOCK);     //非阻塞
    else
        g_fd_lyy = open("/dev/fpga_lyy", O_RDWR);
    if(g_fd_lyy < 0) {
        ERROR("open /dev/fpga_lyy failed, %s", strerror(errno));
    }

    if(noblock == NOBLOCK)
        g_fd_gsb = open("/dev/fpga_gsb", O_RDWR | O_NONBLOCK);     //非阻塞
    else
        g_fd_gsb = open("/dev/fpga_gsb", O_RDWR);
    if(g_fd_gsb < 0) {
        ERROR("open /dev/fpga_gsb failed, %s", strerror(errno));
    }
    
    if(g_fd_lyy == -1 && g_fd_gsb == -1) {
        ERROR("/dev/fpga_lyy and /dev/fpga_gsb are not opened");
        return -1;
    }
    
    memset(g_block_flag, 0, sizeof(g_block_flag));
    block_alloc(g_block_addr, BLOCK_MEM_NUM, BLOCK_MEM_SIZE);
    
    g_block_addr_start = g_block_addr[BLOCK_MEM_NUM - 1];
    g_block_addr_end = g_block_addr[0] + BLOCK_MEM_SIZE - 1;
    
    pthread_mutex_init(&rb_mutex, NULL);
    pthread_mutex_init(&block_mutex, NULL);
    pthread_cond_init(&block_cond, NULL);
    
    block_flag = noblock;
    
    DEBUG("block range:%p - %p", g_block_addr_start, g_block_addr_end);
    
    return 0;
}

void fpga_finalize()
{
    pthread_mutex_destroy(&block_mutex);
    pthread_mutex_destroy(&rb_mutex);
    
    g_block_addr_start = NULL;
    g_block_addr_end = NULL;
    block_free(g_block_addr, BLOCK_MEM_NUM, BLOCK_MEM_SIZE);
    
    block_finalize();

    if(g_fd_lyy > 0) {
        close(g_fd_lyy);
        g_fd_lyy = -1;
    }

    if(g_fd_gsb > 0) {
        close(g_fd_gsb);
        g_fd_gsb = -1;
    }

    return;
}

static int is_block_range(void* addr)
{
    if(addr >= g_block_addr_start && addr < g_block_addr_end) {
        DEBUG("addr is %p, in block range:%p - %p", addr, g_block_addr_start, g_block_addr_end);
        return 1;
    }
    else
        DEBUG("addr is %p, in pool range", addr);
        return 0;
}

void* fpga_get_retbuf(int* len, RET_TYPE type)
{
    struct data_info data_info;
    int ret;
    
    data_info.type = type;
    if(type == RET_TYPE_SW) {
        data_info.type = K_RET_TYPE_SW;
        ret = ioctl(g_fd_lyy, FPGA_APPLY_RESULT_BUF, &data_info);
        if(ret) {
            //ERROR("FPGA_APPLY_RESULT_BUF type(%d) ret=%d, %s\n", type, ret, strerror(errno));
            return NULL;
        }
    }
    else if(type == RET_TYPE_CD || type == RET_TYPE_CS) {
        if(type == RET_TYPE_CD)
            data_info.type = K_RET_TYPE_CD;
        else
            data_info.type = K_RET_TYPE_CS;
        ret = ioctl(g_fd_gsb, FPGA_APPLY_RESULT_BUF, &data_info);
        if(ret) {
            //ERROR("FPGA_APPLY_RESULT_BUF type(%d) ret=%d, %s\n", type, ret, strerror(errno));
            return NULL;
        }
    }
    else {
        ERROR("Unknown type(%d)", type);
    }
    
    
    *len = data_info.data_size;
    
    return offset_to_addr(data_info.offset);
}

int fpga_release_retbuf(void* addr)
{
    int i = 0;
    unsigned long size;
    int ret = 0;
    
    if(is_block_range(addr)) {
        DEBUG("free in blcok range");
        pthread_mutex_lock(&block_mutex);
        for(i = 0; i < BLOCK_MEM_NUM; i++) {
            if(g_block_addr[i] == addr) {
                g_block_flag[i] = 0;
                pthread_cond_signal(&block_cond);
                pthread_mutex_unlock(&block_mutex);
                return 0;
            }
        }
        pthread_mutex_unlock(&block_mutex);

        ERROR("%p not used", addr);
        return -1;
    }
    else {
        DEBUG("free in poll range");
        pthread_mutex_lock(&rb_mutex);
        ret = rb_delete(&rb_root, addr, &size);
        pthread_mutex_unlock(&rb_mutex);
        
        if(ret == 0) {
            mem_free(addr, size);
        }
    }
    return 0;
}

void* fpga_get_writebuf(unsigned long size, BUF_TYPE type)
{
    int ret;
    void* addr = NULL;
    int i = 0;
    
    if(size <= 0) {
        return NULL;
    }
    
    if(type == BUF_TYPE_SW) {
        pthread_mutex_lock(&block_mutex);
try_again:
        for(i = 0; i < BLOCK_MEM_NUM; i++) {
            if(g_block_flag[i] == 0) {
                DEBUG("alloc mem form block");
                g_block_flag[i] = 1;
                pthread_mutex_unlock(&block_mutex);
                return g_block_addr[i];
            }
        }
        if(block_flag == BLOCK) {
            pthread_cond_wait(&block_cond, &block_mutex);
            goto try_again;
        }
        else {
            pthread_mutex_unlock(&block_mutex);
        }
    }
    else if(type == BUF_TYPE_CD || type == BUF_TYPE_CS) {
    
	    unsigned long real_size = ALIGN(size, ALIGN_SIZE);
	        DEBUG("alloc mem form pool, real_size=%d", real_size);
	    addr = mem_alloc(&real_size);
	    if(addr == NULL) {
	        ERROR("mem_alloc failed");
	        return NULL;
	    }
    
		if(is_block_range(addr)) {
	        ERROR("addr=%p in block range(%p-%p)", addr, g_block_addr_start, g_block_addr_end);
	        mem_free(addr, real_size);
	        return NULL;
	    }
    
        pthread_mutex_lock(&rb_mutex);
        ret = rb_insert(&rb_root, addr, real_size);
        if(ret != 0){
            pthread_mutex_unlock(&rb_mutex);
            ERROR("insert addr(%p) size(%d) failed", addr, real_size);
            mem_free(addr, real_size);
                if(ret == -1)
                    ERROR("rb malloc failed");
                if(ret == -2)
                    ERROR("addr(%p) node exist in rb_tree", addr);
            return NULL;
        }
    
        
        pthread_mutex_unlock(&rb_mutex);
    }
    else {
        ERROR("Unknown type(%d)", type);
    }
    
    return addr;
}

int fpga_writebuf_submit(void* addr, unsigned int size, unsigned int type)
{
    unsigned int i = 0;
    struct data_info data_info;
    int ret;
    
    data_info.offset = addr_to_offset(addr);
    data_info.data_size = size;
    data_info.type = type;
    if(type == TYPE_SW) {
        ret = ioctl(g_fd_lyy, FPGA_WRITE_BUF_SUBMIT, &data_info);
        if(ret) {
            ERROR("ERROR:FPGA_WRITE_BUF_SUBMIT type(%d) ret=%d, %s\n", type, ret, strerror(errno));
            return -1;
        }
    }
    else if(type == TYPE_CD || type == TYPE_CS) {
        ret = ioctl(g_fd_gsb, FPGA_WRITE_BUF_SUBMIT, &data_info);
        if(ret) {
            ERROR("ERROR:FPGA_WRITE_BUF_SUBMIT type(%d) ret=%d, %s\n", type, ret, strerror(errno));
            return -1;
        }
    }
    else {
        ERROR("Unknown type(%d)", type);
    }

    return 0;
}

void fpga_exit_block()
{
    int ret;
    if(g_fd_lyy > 0) {
        ret = ioctl(g_fd_lyy, FPGA_EXIT_BLOCK);
        if(ret) {
            ERROR("ERROR:FPGA_EXIT_BLOCK ret=%d, %s\n", ret, strerror(errno));
            return;
        }
    }
    if(g_fd_gsb > 0) {
        ret = ioctl(g_fd_gsb, FPGA_EXIT_BLOCK);
        if(ret) {
            ERROR("ERROR:FPGA_EXIT_BLOCK ret=%d, %s\n", ret, strerror(errno));
            return;
        }
    }
    return;
}

void fpga_test(void)
{
    int ret = 0;
    char c = 0;
    char tmp_c;
    struct test_data data;
    while(1) {
        printf("w.write data\n");
        printf("r.read data\n");
        printf("l.loop test\n");
        printf(">");
        scanf("%c", &c);
        while ((tmp_c = getchar()) != EOF && tmp_c != '\n');
        
        switch(c) {
            case 'w':
                printf("test write, input data:");
                scanf("%llx", &data.data);
                while ((tmp_c = getchar()) != EOF && tmp_c != '\n');
                printf("test write, input offset:");
                scanf("%x", &data.offset);
                while ((tmp_c = getchar()) != EOF && tmp_c != '\n');
                ret = ioctl(g_fd_gsb, FPGA_TEST_WRITE, &data);
                if(ret) {
                    DEBUG("ERROR:FPGA_TEST_WRITE ret=%d, %s", ret, strerror(errno));
                }
                break;
            case 'r':
                printf("input offset:");
                scanf("%x", &data.offset);
                while ((tmp_c = getchar()) != EOF && tmp_c != '\n');
                printf("offset=%x\n", data.offset);
                
                ret = ioctl(g_fd_gsb, FPGA_TEST_READ, &data);
                if(ret) {
                    DEBUG("ERROR:FPGA_TEST_READ ret=%d, %s", ret, strerror(errno));
                }
                printf("offset:%x, data:0x%llx\n", data.offset, data.data);
                break;
            case 'l':
            {
                int64_t ts1;
                int64_t ts2;
                struct timeval tv_1;
                struct timeval tv_2;
                gettimeofday(&tv_1, NULL);
                data.offset = 0x500;
                data.data = 0;
                struct test_data tmp_data;
                tmp_data.offset = 0x500;
                int i = 0;
                for(i = 0; i < 10000000; i++) {
                    ret = ioctl(g_fd_gsb, FPGA_TEST_WRITE, &data);
                    if(ret) {
                        DEBUG("ERROR:FPGA_TEST_WRITE ret=%d, %s", ret, strerror(errno));
                    }
                    
                    ret = ioctl(g_fd_gsb, FPGA_TEST_READ, &tmp_data);
                    if(ret) {
                        DEBUG("ERROR:FPGA_TEST_READ ret=%d, %s", ret, strerror(errno));
                    }
                    if(data.data != tmp_data.data) {
                        DEBUG("ERROR:offset 0x%x value wrong, write data:0x%llx, read data:0x%llx", data.offset, data.data, tmp_data.data);
                    }
                    data.data++;
                }
                gettimeofday(&tv_2, NULL);
                ts1 = (int64_t)tv_1.tv_sec*1000 + tv_1.tv_usec/1000;
                ts2 = (int64_t)tv_2.tv_sec*1000 + tv_2.tv_usec/1000;
                printf("interval=%lld ms\n", ts2 - ts1);
                break;
            }
            case 'f':
            {
                struct test_data tmp_data;
                tmp_data.offset = 0x00;
                int i = 0;
                for(i = 0; i < 10000000; i++) {
                    ret = ioctl(g_fd_gsb, FPGA_TEST_READ, &tmp_data);
                    if(ret) {
                        DEBUG("ERROR:FPGA_TEST_READ ret=%d, %s", ret, strerror(errno));
                    }
                    if(tmp_data.data == 0xffffffffffffffff) {
                        DEBUG("data == -1");
                        break;
                    }
                }
                break;
            }
            case 'q':
                return;
            default:
                break;
        }
    }
    return;
}
