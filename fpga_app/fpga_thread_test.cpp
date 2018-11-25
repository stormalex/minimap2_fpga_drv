//Usage: ./gtest
//Usage: ./gtest sw3
//Usage: ./gtest sw4
//Usage: ./gtest ph
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <math.h>
#include <map>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <stdint.h>

#include "../fpga_lib/fpga.h"



typedef struct data_info {
    long offset;
    int len;
}data_info_t;

std::map<unsigned int, data_info_t> offset_table;
FILE *input,*output;
char in_file[256];
char out_file[256];

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
    if (sim_ez->max_q != fpg_ez->max_q) {printf("ez->max_q err! [fpga:%x sim:%x] %d %lu %p %p\n", fpg_ez->max_q, sim_ez->max_q, mm, err_count, &(sim_ez->max_q), &(fpg_ez->max_q));err_flag=1;};
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
int send_count = 0;
void* send_thread(void *)
{
    int ret;
    void* addr;
    int len;
    
    while(!feof(input) && fread(&len,4,1,input)>0){
        //sw((char*)&len,4);
        char *data = (char *)malloc(len);
        int rlen = fread(data,1,len,input);
	    if(rlen != len){
            fprintf(stderr,"ERROR:len,rlen:%d,%d\n",len,rlen);
            perror("ERROR:read input data file failed!\n");
            exit(1);
        }

        //send data to fpga
        addr = fpga_get_writebuf(len, BUF_TYPE_SW);
        if(addr == NULL) {
            printf("ERROR:fpga_get_writebuf failed\n");
            exit(1);
        }
    
        memcpy(addr, data, len);
        
        if(fpga_writebuf_submit(addr, len, TYPE_SW)) {
            printf("ERROR:fpga_writebuf_submit failed\n");
            exit(1);
        }
        free(data);
        send_count++;
    }
    //printf("send thread exit, send_count=%d\n", send_count);
    return NULL;
}

#define COMPARE_RESULT 0

int main(int argc, char* argv[])
{
    pthread_t p_send;
    int i = 0;
    int j = 0;
    int len = 0;
    void *addr = NULL;
    void *out_addr = NULL;
    int output_fpga_len;
    int ret = 0;
    int count = 0;
    int exec_num = 0;
    unsigned char* p = NULL;
    swtest_rcvhdr_t* data = NULL;
    unsigned int total_num = 0;
    unsigned int ret_num = 0;
    int olen = 0;
    long offset = 0;
    int rlen = 0;
    int err = 0;
    
    if(argc != 2) {
        printf("Usage:./fpga_test input_file\n");
        return -1;
    }
    
    memset(in_file, 0, 256);
    memset(out_file, 0, 256);
    memcpy(in_file, argv[1], strlen(argv[1]));
    memcpy(out_file, argv[1], strlen(argv[1]));
    
    strcat(in_file, "in.bin");
    strcat(out_file, "out.bin");
    
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
    int cnt = 0;
    while(!feof(output) && fread(&olen,4,1,output)>0) {
        cnt++;
        char *odata = (char *)malloc(olen);
        offset = ftell(output);
        rlen = fread(odata,1,olen,output);
        if(rlen != olen){
            fprintf(stderr,"ERROR:olen,rlen:%d,%d, cnt=%d\n",olen,rlen, cnt);
            perror("ERROR:read output data file failed!\n");
            exit(1);
        }
        
        data = (swtest_rcvhdr_t*)odata;
        unsigned int magic = data->magic;
        
        data_info_t info;
        info.offset = offset;
        info.len = olen;
        
        //printf("insert magic=0x%016llx\n", magic);
        std::map<unsigned int, data_info_t>::iterator it = offset_table.find(magic);
        if(it != offset_table.end()) {
            printf("already have 0x%016llx\n", magic);
        }
        total_num++;
        offset_table.insert(std::pair<unsigned int, data_info_t>(magic, info));
        free(odata);
    }
    fseek(output, 0, SEEK_SET);
#endif
    ret = fpga_init(BLOCK);
    if(ret) {
        printf("fpga_init failed\n");
        return -1;
    }
    
    pthread_create(&p_send, NULL, send_thread, NULL);
    
    
    struct timeval tv1;
    struct timeval tv2;
    gettimeofday(&tv1, NULL);
    while(1) {
        int i = 0;
        int outputlen;
        unsigned char *outputdata = NULL;

        outputdata = (unsigned char*)fpga_get_retbuf(&outputlen, RET_TYPE_SW);
        if(outputdata == NULL) {
            printf("ERROR:fpga_get_retbuf failed\n");
            exit(1);
        }
#if COMPARE_RESULT
        data = (swtest_rcvhdr_t*)outputdata;
        unsigned int magic = *((unsigned int*)data);
        
        
        std::map<unsigned int, data_info_t>::iterator it = offset_table.find(magic);
        
        if(it != offset_table.end()) {
            data_info_t info = it->second;
            char *odata = (char *)malloc(info.len);
            fseek(output, info.offset, SEEK_SET);
            int olen = fread(odata, 1, info.len, output);
            if(olen != info.len) {
                printf("ERROR:out put len (%d) not equal outfile len(%d)\n", olen, info.len);
                fpga_release_retbuf(outputdata);
                continue;
            }
            
            //printf("out_file=%p fpga_out=%p\n", odata, outputdata);
            err_count = 0;
            if(swresult_compare((swtest_rcvhdr_t *)odata, (swtest_rcvhdr_t *)outputdata) != 0) {
                err++;
                fprintf(stderr,"ERROR:wrong result on 0x%016llx\n",magic);
            }
            //printf("out_magic=0x%016llx\n", magic);
            
            free(odata);
        }
        else {
            printf("cannot find magic:0x%016llx\n", magic);
        }
#endif
        if(fpga_release_retbuf(outputdata)) {
            exit(1);
        }
        ret_num++;
#if COMPARE_RESULT
        printf("ret_num=%d total_num=%d, err_cnt=%d\n", ret_num, total_num, err);
        if(ret_num == total_num)
            break;
#else
        printf("ret_num=%d\n", ret_num);
        if(ret_num == send_count)
            break;
#endif
    }
    
    gettimeofday(&tv2, NULL);
    printf("time=%llu ms\n", ((tv2.tv_sec * 1000000 + tv2.tv_usec) - (tv1.tv_sec * 1000000 + tv1.tv_usec))/1000);
#if COMPARE_RESULT
    printf("ret_num=%d err_count=%d\n", ret_num, err);
#else
    printf("ret_num=%d send_count=%d err_count=%d\n", ret_num, send_count, err);
#endif
    pthread_join(p_send, NULL);
    return 0;
}
