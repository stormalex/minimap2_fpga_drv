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

#include "../fpga_lib/fpga.h"

typedef struct {
    int32_t p,v;
} pv_t ;


typedef struct {
    uint32_t n_a,rep_len,n_mini_pos;
    uint32_t moffset,aoffset;
    uint32_t subsize,ctxpos;
    uint32_t gap_ref,gap_qry;
    uint16_t n_segs;
    uint8_t  err_flag;
    uint8_t  pad25B[25];
    uint8_t  pvf[0];
} dptest_rcvsubhdr_t ;


typedef struct {
    void *   km;
    uint32_t magic;//from dpring magic
    uint32_t size;
    uint16_t tid;
    uint16_t num;
    uint8_t  type;
    uint8_t  lat;
    uint16_t pad2B;
    uint32_t pad48B[12];
    dptest_rcvsubhdr_t subhdr[0];
} dptest_rcvhdr_t ;


typedef struct {
    //void *   km;
    uint32_t magic;//from dpring magic
    uint32_t size;
    uint16_t tid;
    uint16_t num;
    uint8_t  type;
    uint8_t  lat;
    uint16_t pad2B;
    uint32_t pad48B[12];
    dptest_rcvsubhdr_t subhdr[0];
} dptest_rcvhdr_fpga_t ;


#define ALIGN_BYTE_N(n, v) ((v+n-1)&(~(n-1)))

int dpcomp(dptest_rcvhdr_fpga_t *x86, dptest_rcvhdr_fpga_t *fpg)
{
    int err_flag = 0;
    int x = 0;
    int y = 0;
    if (x86->magic != fpg->magic) {
        printf("magic error!\n");
        err_flag = 1;
    }
    //if (x86-> != fpg->) printf("error!\n");
    if (x86->num != fpg->num) {
        printf("hdr num error!\n");
        err_flag = 1;
    }
    if (x86->type != fpg->type) {
        printf("hdr type error!\n");
        err_flag = 1;
    }
    /*if (x86->lat != fpg->lat) {
        printf("hdr lat error!\n");
        err_flag = 1;
    }*/

    int preoff = 0;
    for (x=0; x<x86->num; x++) {
        dptest_rcvsubhdr_t *x86sub = (dptest_rcvsubhdr_t *)((uint8_t *)x86->subhdr + preoff);
        uint32_t n_a = x86sub->n_a;
        uint32_t aln64B_pv = ALIGN_BYTE_N(64, ((n_a+1)<<3));
        uint32_t aln64B_f  = ALIGN_BYTE_N(64, (n_a<<2));
        uint32_t aln64B_a  = ALIGN_BYTE_N(64, (n_a<<4));
        uint32_t aln64B_nm = ALIGN_BYTE_N(64, 0);
        //uint32_t subsize = sizeof(dptest_rcvsubhdr_t) + aln64B_pv + aln64B_f + aln64B_a + aln64B_nm;
        //uint32_t subsize2 = sizeof(dptest_rcvsubhdr_t) + aln64B_pv;
        uint32_t subsize = 0;
        
        pv_t *x86pv = (pv_t *)x86sub->pvf;
        int *x86f = (int *)((uint8_t *)x86pv + aln64B_pv);
        uint8_t *x86a = (uint8_t *)(x86sub->pvf + x86sub->aoffset);

        dptest_rcvsubhdr_t *fpgsub = (dptest_rcvsubhdr_t *)((uint8_t *)fpg->subhdr + preoff);
        pv_t *fpgpv = (pv_t *)fpgsub->pvf;
        int *fpgf = (int *)((uint8_t *)fpgpv + aln64B_pv);
        uint8_t *fpga = (uint8_t *)(fpgsub->pvf + fpgsub->aoffset);

        uint32_t fpgna = fpgsub->n_a;

        if ((x86pv[n_a].p != fpgpv[n_a].p)) {       //判断n_u是否正确
            printf("readseq %d, n_u error! %x %x\n", x, x86pv[n_a].p, fpgpv[n_a].p);
            err_flag = 1;
            return 1;
        }
        else { 
            if(fpgpv[n_a].p != 0) {
                subsize = sizeof(dptest_rcvsubhdr_t) + aln64B_pv + aln64B_f + aln64B_a + aln64B_nm;
            }
            else {
                
                subsize = sizeof(dptest_rcvsubhdr_t) + aln64B_pv;
                printf("n_u == 0, x=%d, subsize=%d\n", x, subsize);
            }
        }
        {
            if(fpgsub->err_flag == 1 && x86sub->err_flag == 0)
                printf("err_flag error!\n");
            
            if(fpgsub->err_flag == 0) {
                if (n_a != fpgna) printf("readseq %d, n_a error! %x %x\n",x, n_a, fpgna);
                //if (x86sub-> != fpgsub->) printf("readseq %d, error!\n",x);
                if (x86sub->rep_len != fpgsub->rep_len) {
                    printf("readseq %d, replen error! %x %x\n", x, x86sub->rep_len, fpgsub->rep_len);
                    err_flag = 1;
                }
                if (x86sub->moffset != fpgsub->moffset) {
                    printf("readseq %d, moffset error! %x %x\n",x, x86sub->moffset, fpgsub->moffset);
                    err_flag = 1;
                }
                if (x86sub->aoffset != fpgsub->aoffset) {
                    printf("readseq %d, aoffset error! %x %x\n",x, x86sub->aoffset, fpgsub->aoffset);
                    err_flag = 1;
                }
                if (x86sub->subsize != fpgsub->subsize) {
                    printf("readseq %d, subsize error! %x %x\n",x, x86sub->subsize, fpgsub->subsize);
                    err_flag = 1;
                }
                if (x86sub->ctxpos  != fpgsub->ctxpos ) {
                    printf("readseq %d, ctxpos  error! %x %x\n",x, x86sub->ctxpos, fpgsub->ctxpos);
                    err_flag = 1;
                }
                
                for (y=0; y<n_a; y++) {
                    if ((x86pv[y].p != fpgpv[y].p) || (x86pv[y].v != fpgpv[y].v)) {
                        printf("readseq %d, pv[%d] error \n",x,y);
                        err_flag = 1;
                    }
                    if(x86pv[n_a].p != 0) {
                        if (x86f[y] != fpgf[y]) {
                            printf("readseq %d, f[%d] error!\n", x,y);
                            err_flag = 1;
                        }
                    }
                }

                
            }

            //int c = memcmp(x86a, fpga, n_a*16);
            //if (c != 0) {printf("readseq %d, seed error!\n",x);err_flag = 1;}
        }
        preoff += subsize;
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

char in_file[256];
char out_file[256];

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

    output = fopen(out_file, "rb");
    if(output == NULL) {
        printf("open %s failed\n", out_file);
        fpga_finalize();
        return 1;
    }

    while(!feof(input) && fread(&len,4,1,input)>0) {
        count++;

        //printf("start %d ###########################################\n", count);
        //printf("len=%d\n", len);
        char *input_data = (char *)malloc(len);
        int input_len = fread(input_data,1,len,input);
        if(input_len != len) {
            fprintf(stderr,"ERROR:len,input_len:%d,%d\n",len,input_len);
            perror("ERROR:read input data file failed!\n");
            exit(1);
        }

        int out_len;
        fread(&out_len,4,1,output);

        char* out_d_addr = malloc(out_len);
        printf("out_file_len=%d out_d_addr=%p\n", out_len, out_d_addr);
        fread(out_d_addr,1,out_len,output);


        if(count == exec_num || exec_num == 0) {
            printf("####count=%d\n", count);
            addr = fpga_get_writebuf(len * 2, BUF_TYPE_CD);
            if(addr == NULL) {
                printf("ERROR:fpga_get_writebuf failed\n");
                exit(1);
            }

            //printf("fpga write addr:%p\n", addr);
            memcpy(addr, input_data, len);

            p = ((unsigned char*)addr) + 4096;
            /*for(i = 0; i < input_len - 4096; i++) {
                if(i % 16 == 0 && i != 0)
                    printf("\n");
                printf("%02x ", p[i]);
            }
            printf("\n");*/

            /*for(i = 0; i < input_len - 4096; i += 64) {
                printf_64(&p[i], 64);
                printf("\n");
            }*/

            //printf("\n\n");


            fpga_writebuf_submit(addr, len, TYPE_CD);

            out_addr = fpga_get_retbuf(&output_fpga_len, RET_TYPE_CD);
            if(out_addr == NULL) {
                fprintf(stderr,"ERROR:output_fpga_len:%d,%d\n",output_fpga_len);
                perror("ERROR:fpga_get_retbuf failed!\n");
                exit(1);
            }


            printf("fpga get addr:%p\n", out_addr);
            printf("fpga out len=%d\n", output_fpga_len);

            /*p = ((unsigned char*)out_addr);
            for(i = 0; i < output_fpga_len; i += 64) {
                printf_64(&p[i], 64);
                printf("\n");
            }
            printf("\n\n");*/

            /*p = ((unsigned char*)out_d_addr);
            for(i = 0; i < out_len; i += 64) {
                printf_64(&p[i], 64);
                printf("\n");
            }
            printf("\n\n");*/

            ret = dpcomp((dptest_rcvhdr_fpga_t *)(out_d_addr), (dptest_rcvhdr_fpga_t *)out_addr);
            if(ret) {
                printf("result error\n");
                fpga_release_retbuf(out_addr);
                return 1;
            } else {
                printf("data OK!!\n");
            }

            fpga_release_retbuf(out_addr);
        }
        //printf("end ###########################################\n\n\n");
        free(input_data);
        free(out_d_addr);
    }

    fclose(input);
    fclose(output);
    fpga_finalize();

    return 0;
}
