#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>
#include <sys/time.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>

#include "../fpga_lib/fpga.h"

#define DP_BATCHSIZE        (127)

#define ALIGN_BYTE_N(n, v) ((v+n-1)&(~(n-1)))


typedef struct {
  int n_cigar;
  uint32_t max:31, zdropped:1;
  int max_q, max_t;      // max extension coordinate
  int mqe, mqe_t;        // max score when reaching the end of query
  int mte, mte_q;        // max score when reaching the end of target
  int score;             // max score reaching both ends; may be KSW_NEG_INF
  int reach_end;
  int m_cigar;
  int revcigar;
  int pad8B[2];
  uint32_t *cigar;
} ksw_extz_t;


typedef struct
{
  uint32_t offset;//first sw segment, from head always
  uint32_t size;//total ez size of this reg
  uint32_t midnum;//middle cnt in x86
  uint32_t regpos;
  //uint8_t  hasleft;//0 not has, non 0 has
  //uint8_t  hasright;
} sw_reghdr_t;


typedef struct
{
  uint64_t head;//node list's head
  uint32_t ctxpos;//curr read's ctx position
  uint16_t regnum;//regnum for curr read'sw
  uint16_t longsw;
  sw_reghdr_t reg;
} sw_readhdr_t;


typedef struct {
  void *   km;
  uint32_t magic;//from swring magic
  uint32_t size;
  uint16_t tid;//threadid
  uint16_t num;
  uint8_t  type;
  uint8_t  lat;
  uint16_t freecigar;
  uint8_t pad8B[8];
  sw_readhdr_t data[DP_BATCHSIZE];
} swtest_rcvhdr_t;

typedef struct
{
    uint32_t magic;
    uint32_t size;
    uint16_t tid;//thread id
    uint16_t num;//fact readnum
    uint8_t  type;
    uint8_t  lat;//last or not
    uint16_t pad2B;
    uint32_t pad16B[4];
    sw_readhdr_t data[DP_BATCHSIZE];
} sw_sndhdr_t;

typedef struct 
{
    int16_t qlen;
    int16_t tlen;
    //int32_t qoff;
    //int32_t toff;
    int16_t flag;
    int16_t zdrop;
    int16_t bw;
    int8_t  end_bonus;
    int8_t  pad1B;
    int16_t qlen_align;
    int16_t tlen_align;
    //uint8_t swpos;//one of left,mid,right
} sw_to_fpga_t;

static uint32_t merge_to_midnum(uint32_t midnum, int hasleft, int hasright)
{
    uint32_t ret = 0;
    if (hasleft)  ret |= midnum|0x80000000UL;//set bit 31 to left
    if (hasright) ret |= midnum|0x40000000UL;//set bit 30 to right
    return ret;
}

static int get_left(uint32_t midnum)
{
    return midnum&0x80000000UL;//get bit 31
}

static int get_right(uint32_t midnum)
{
    return midnum&0x40000000UL;//get bit 30
}

static uint32_t clear_midnum(uint32_t midnum)
{
    return midnum&0x3FFFFFFFUL;//clear bit 31-30
}
unsigned long err_count = 0;



void printf_64(unsigned char* p, int n)
{
    int i = 63;
    if(n != 64)
        return;
    for(i = 63; i >=0; i--)
        printf("%02x", p[i]);
    
    return;
}

void printsigset(sigset_t* set)//打印pending表
{
    int i = 0;
    for(i=1; i<=32; ++i)
    {   
        if(sigismember(set,i))//当前信号在信号集中
            putchar('1');
        else//当前信号不在信号集中
            putchar('0');
    }   
    puts("");//printf("\n");
}

char in_file[256];

int main(int argc, char* argv[])
{
    int i = 0;
    int j = 0;
    int len = 0;
    void *addr = NULL;
    void *out_addr = NULL;
    int output_fpga_len;
    FILE* input = 0;
    FILE* output = 0;
    int ret = 0;
    int count = 0;
    int print_num = 0;
    unsigned char* p = NULL;
    sw_sndhdr_t* head = NULL;
    int err_cnt = 0;
    
    if(argc != 3) {
        printf("Usage:./fpga_test input_file num\n");
        return -1;
    }
    
    memset(in_file, 0, 256);
    memcpy(in_file, argv[1], strlen(argv[1]));
    strcat(in_file, "in.bin");
    print_num = atoi(argv[2]);
    
    input = fopen(in_file, "rb");
    if(input == NULL) {
        printf("open %s failed\n", in_file);
        fpga_finalize();
        return 1;
    }

    while(!feof(input) && fread(&len,4,1,input)>0){
        count++;
        
        //printf("start %d ###########################################\n", count);
        //printf("len=%d\n", len);
        char *input_data = (char *)malloc(len);
        int input_len = fread(input_data,1,len,input);
        if(input_len != len){
            fprintf(stderr,"ERROR:len,input_len:%d,%d\n",len,input_len);
            perror("ERROR:read input data file failed!\n");
            exit(1);
        }

        
        if(count == print_num) {
            printf("####count=%d\n", count);
            head = (sw_sndhdr_t*)input_data;
            printf("head->magic = 0x%x\n", head->magic);
            printf("head->size = %d\n", head->size);
            printf("head->type = 0x%x\n", head->type);
            printf("head->tid = 0x%x\n", head->tid);
            printf("head->num = %d\n", head->num);
            printf("head->lat = 0x%x\n", head->lat);
            printf("head->freecigar = 0x%x\n", head->freecigar);
            printf("head->km = 0x%x\n", head->km);
            
            sw_to_fpga_t *fpghdr = (sw_to_fpga_t *)(hdr->data + 127);
            
            for(int k = 0; k < head->num; k++) {
                sw_readhdr_t *read = &data[k];
                if(read->longsw == 0) {
                    
                }
            }
        }
        
        free(input_data);
    }
    
    fclose(input);
    return 0;
}
