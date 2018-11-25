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
uint32_t cigar_compare(ksw_extz_t *sim_ez, ksw_extz_t *fpg_ez, uint32_t *cigar_start, int mm, const char *pos, int nn)
{
    int i = 0;
    uint32_t err_flag = 0;
    int ncigar_flag = 0;
    err_count++;
    //printf("%d, %s, %d\n", mm, pos, nn);
    
    //printf("revcigar=%d\n", sim_ez->revcigar);
    if (sim_ez->n_cigar != fpg_ez->n_cigar) {printf("ez->ncigar err![fpga:%x sim:%x] %d %lu\n", fpg_ez->n_cigar, sim_ez->n_cigar, mm, err_count);err_flag=1;ncigar_flag=1;};
    if (sim_ez->max != fpg_ez->max) {printf("ez->max err! [fpga:%x sim:%x] %d %lu\n", fpg_ez->max, sim_ez->max, mm, err_count);err_flag=1;};
    //if (sim_ez-> != fpg_ez->) printf("ez->\n");
    if (sim_ez->zdropped != fpg_ez->zdropped) {printf("ez->zdropped err! [fpga:%x sim:%x] %d %lu\n", fpg_ez->zdropped, sim_ez->zdropped, mm, err_count);err_flag=1;};
    
    if (sim_ez->max_q != fpg_ez->max_q) {printf("ez->max_q err! [fpga:%x sim:%x] %d %lu\n", fpg_ez->max_q, sim_ez->max_q, mm, err_count);err_flag=1;};
    if (sim_ez->max_t != fpg_ez->max_t) {printf("ez->max_t err! [fpga:%x sim:%x] %d %lu\n", fpg_ez->max_t, sim_ez->max_t, mm, err_count);err_flag=1;};
    if (sim_ez->mqe   != fpg_ez->mqe)   {printf("ez->mqe   err! [fpga:%x sim:%x] %d %lu\n", fpg_ez->mqe, sim_ez->mqe, mm ,err_count);err_flag=1;};
    if (sim_ez->mqe_t != fpg_ez->mqe_t) {printf("ez->mqe_t err! [fpga:%x sim:%x] %d %lu\n", fpg_ez->mqe_t, sim_ez->mqe_t, mm, err_count);err_flag=1;};
    if (sim_ez->mte   != fpg_ez->mte)   {printf("ez->mte   err! [fpga:%x sim:%x] %d %lu\n", fpg_ez->mte, sim_ez->mte, mm ,err_count);err_flag=1;};
    if (sim_ez->mte_q != fpg_ez->mte_q) {printf("ez->mte_q err! [fpga:%x sim:%x] %d %lu\n", fpg_ez->mte_q, sim_ez->mte_q, mm, err_count);err_flag=1;};
    if (sim_ez->score != fpg_ez->score) {printf("ez->score err! [fpga:%x sim:%x] %d %lu\n", fpg_ez->score, sim_ez->score, mm, err_count);err_flag=1;};
    if (sim_ez->reach_end != fpg_ez->reach_end) {printf("ez->reach_end err! [fpga:%x sim:%x] %d %lu\n", fpg_ez->reach_end, sim_ez->reach_end, mm, err_count);err_flag=1;};
    fpg_ez->cigar = cigar_start;
    
    if(ncigar_flag == 0) {
        for(i = 0; i < fpg_ez->n_cigar; i++) {
            if(sim_ez->cigar[i] != fpg_ez->cigar[i]) {
                printf("[%d][%d][%s][%d][%d]sim cigar:%08x fpg cigar:%08x\n", err_count, mm, pos, nn, i, sim_ez->cigar[i], fpg_ez->cigar[i]);
                err_flag = 1;
            }
        }
    }
    
    if(err_flag) {
        printf("pad8B[1] = %x\n", sim_ez->pad8B[1]);
    }
    
    return err_flag;
}
int swresult_compare(swtest_rcvhdr_t *sim, swtest_rcvhdr_t *fpg)
{
    int k = 0;
    int x = 0;
    uint32_t ret = 0;
    int err_flag = 0;
    int total_extz=0;
  /*if (sim->magic != fpg->magic) printf("magic err! sim:%p, fpg:%p\n", sim->magic, fpg->magic);
  if (sim->tid   != fpg->tid  ) printf("tid   err! 1111111111\n");
  if (sim->num   != fpg->num  ) printf("num   err! 1111111111\n");
  if (sim->type  != fpg->type ) printf("type  err! 1111111111\n");
  if (sim->lat   != fpg->lat  ) printf("last  err! 1111111111\n");
  if (sim->freecigar != 0)       printf("freecigar err!1111111111\n");
*/
   
   for(k=0; k<sim->num; k++){
      sw_readhdr_t *fpg_read = fpg->data + k;
      sw_reghdr_t *fpg_reg = &fpg_read->reg;
      total_extz +=  (!!get_left(fpg_reg->midnum)+!!get_right(fpg_reg->midnum)+clear_midnum(fpg_reg->midnum));
   }
   
   ksw_extz_t *fpg_ez = (ksw_extz_t *)((uint8_t *)fpg+sizeof(swtest_rcvhdr_t));
   uint8_t *cigar_start = (uint8_t *)(fpg_ez + total_extz);

  for (k=0; k<sim->num; k++) {
    sw_readhdr_t *sim_read = sim->data + k;
    sw_readhdr_t *fpg_read = fpg->data + k;

    sw_reghdr_t *sim_reg = &sim_read->reg;
    sw_reghdr_t *fpg_reg = &fpg_read->reg;

    //if (sim_read->ctxpos != fpg_read->ctxpos) printf("read->ctxpos err!\n");
    //if (sim_read->regnum != fpg_read->regnum) printf("read->regnum err!\n");
    //if (sim_read->longsw != 0) printf("read->longsw err!\n");
    //if (sim_reg->midnum  != fpg_reg->midnum) printf("reg->midnum err!\n");
    //if (sim_reg->regpos  != fpg_reg->regpos) printf("reg->regpos err!\n");
    fpg_reg->size = (!!get_left(fpg_reg->midnum) + !!get_right(fpg_reg->midnum) + clear_midnum(fpg_reg->midnum)) * sizeof(ksw_extz_t);
    if (0 == k) fpg_reg->offset = sizeof(swtest_rcvhdr_t);
    else fpg_reg->offset = fpg->data[k-1].reg.offset + fpg->data[k-1].reg.size;

    ksw_extz_t *sim_ez = (ksw_extz_t *)((uint8_t *)sim+sim_reg->offset);
    //ksw_extz_t *fpg_ez = (ksw_extz_t *)((uint8_t *)fpg+fpg_reg->offset);
    //ksw_extz_t *fpg_ez = (ksw_extz_t *)((uint8_t *)fpg+sizeof(swtest_rcvhdr_t));

    //uint8_t *cigar_start = (uint8_t *)(fpg_ez + (!!get_left(fpg_reg->midnum) + !!get_right(fpg_reg->midnum) + clear_midnum(fpg_reg->midnum)));
    //uint8_t *cigar_start = (uint8_t *)(fpg_ez + total_extz);

    uint8_t *cigar_start_sim = (uint8_t *)((uint8_t *)sim + sim_ez->pad8B[0]);
    if (get_left(fpg_reg->midnum)) {
        sim_ez->cigar = (uint32_t*)cigar_start_sim;
        ret = cigar_compare(sim_ez, fpg_ez, (uint32_t *)cigar_start, k, "L", 0);
        if(ret == 1) {
            err_flag = 1;
        }
        cigar_start += ALIGN_BYTE_N(16, fpg_ez->n_cigar*4);
        cigar_start_sim += ALIGN_BYTE_N(16, sim_ez->n_cigar*4);
        fpg_ez++;
        sim_ez++;
    }

    int midnums = clear_midnum(fpg_reg->midnum);
    for (x=0; x<midnums; x++) {
        sim_ez->cigar = (uint32_t *)cigar_start_sim;
        ret = cigar_compare(sim_ez, fpg_ez, (uint32_t *)cigar_start, k, "M", x);
        if(ret == 1) {
            err_flag = 1;
        }
        cigar_start += ALIGN_BYTE_N(16, fpg_ez->n_cigar*4);
        cigar_start_sim += ALIGN_BYTE_N(16, sim_ez->n_cigar*4);//
        fpg_ez++;
        sim_ez++;
    }

    if (get_right(fpg_reg->midnum)) {
        sim_ez->cigar = (uint32_t *)cigar_start_sim;
        ret = cigar_compare(sim_ez, fpg_ez, (uint32_t *)cigar_start, k, "R", 0);
        if(ret == 1) {
            err_flag = 1;
        }
        cigar_start += ALIGN_BYTE_N(16, fpg_ez->n_cigar*4);
        cigar_start_sim += ALIGN_BYTE_N(16, sim_ez->n_cigar*4);//
        fpg_ez++;
        sim_ez++;
    }
  }
  return err_flag;
}


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
char out_file[256];
#define COMPARE_RESULT 1
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
    int exec_num = 0;
    unsigned char* p = NULL;
    sw_sndhdr_t* head = NULL;
    int err_cnt = 0;
    
    if(argc != 3) {
        printf("Usage:./fpga_test input_file num\n");
        return -1;
    }
    
    memset(in_file, 0, 256);
    memset(out_file, 0, 256);
    memcpy(in_file, argv[1], strlen(argv[1]));
    memcpy(out_file, argv[1], strlen(argv[1]));
    
    strcat(in_file, "in.bin");
    strcat(out_file, "out.bin");
    
    exec_num = atoi(argv[2]);
    
    ret = fpga_init(BLOCK);
    if(ret) {
        printf("fpga_init failed\n");
        return -1;
    }
    
    input = fopen(in_file, "rb");
    if(input == NULL) {
        printf("open %s failed\n", in_file);
        fpga_finalize();
        return 1;
    }
#if COMPARE_RESULT
    output = fopen(out_file, "rb");
    if(output == NULL) {
        printf("open %s failed\n", out_file);
        fpga_finalize();
        return 1;
    }
#endif
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
#if COMPARE_RESULT
        int out_len;
        fread(&out_len,4,1,output);
        
        char* out_d_addr = malloc(out_len);
        //printf("out_file_len=%d out_d_addr=%p\n", out_len, out_d_addr);
        fread(out_d_addr,1,out_len,output);
#endif
        
        if(count == exec_num || exec_num == 0) {
        //if(count > 182) {
            printf("####count=%d\n", count);
            head = (sw_sndhdr_t*)input_data;
            
            //printf("size:%d\n", head->size);
            //printf("tid:%d\n", head->tid);
            //printf("num:%d\n", head->num);
            //printf("type:%d\n", head->type);
            //printf("lat:%d\n", head->lat);
            
            addr = fpga_get_writebuf(len, BUF_TYPE_SW);
            if(addr == NULL) {
                printf("ERROR:fpga_get_writebuf failed\n");
                exit(1);
            }
            
            //printf("fpga write addr:%p\n", addr);
            memcpy(addr, input_data, len);
            
            
            
            /*p = ((unsigned char*)addr);
            for(i = 0; i < input_len - 4096; i++) {
                if(i % 16 == 0 && i != 0)
                    printf("\n");
                printf("%02x ", p[i]);
            }
            printf("\n\n");*/
            
            /*for(i = 0; i < input_len; i += 64) {
                printf_64(&p[i], 64);
                printf("\n");
            }
            printf("\n\n");*/
            
            fpga_writebuf_submit(addr, len, TYPE_SW);
            
            out_addr = fpga_get_retbuf(&output_fpga_len, RET_TYPE_SW);
            if(out_addr == NULL) {
                fprintf(stderr,"ERROR:output_fpga_len:%d,%d\n",output_fpga_len);
                exit(1);
            }
            //printf("fpga get addr:%p\n", out_addr);
            //printf("output_fpga_len=%d\n", output_fpga_len);
            
            p = ((unsigned char*)out_addr) + 4096;
            /*for(i = 0; i < output_fpga_len - 4096; i += 64) {
                printf_64(&p[i], 64);
                printf("\n");
            }*/
#if COMPARE_RESULT
            /*printf("\n\n");
            p = ((unsigned char*)out_d_addr) + 4096;
            for(i = 0; i < out_len - 4096; i += 64) {
                printf_64(&p[i], 64);
                printf("\n");
            }*/
            
            /*p = ((unsigned char*)out_d_addr) + 4096;
            for(i = 0; i < out_len - 4096; i++) {
                if(i % 16 == 0 && i != 0)
                    printf("\n");
                printf("%02x ", p[i]);
            }
            printf("\n");*/
            
            err_count = 0;
            //printf("out_file=%p\n", out_d_addr);
            ret = swresult_compare((swtest_rcvhdr_t *)out_d_addr, (swtest_rcvhdr_t *)out_addr);
            if(ret) {
                printf("result error\n");
                err_cnt++;
            }
            else {
                printf("data OK!!\n");
            }
#endif
            fpga_release_retbuf(out_addr);
            if(exec_num != 0) {
                break;
            }
        }
        //printf("end ###########################################\n\n\n");
        free(input_data);
#if COMPARE_RESULT
        free(out_d_addr);
#endif
    }
    
    fclose(input);
#if COMPARE_RESULT
    fclose(output);
#endif
    fpga_finalize();
    
    printf("err_cnt=%d\n", err_cnt);
    
    return 0;
}
