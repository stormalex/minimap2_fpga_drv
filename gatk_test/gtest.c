//Usage: ./gtest
//Usage: ./gtest sw3
//Usage: ./gtest sw4
//Usage: ./gtest ph
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#include <math.h>
#include <unistd.h>
#include "../fpga_lib/fpga.h"

void verify(void *param)
{
}
void sw(char *p, int size)
{
    char tmp;
    int i;
    for(i=0;i<size>>1;i++){
        tmp=p[i];
        p[i]=p[size-1-i];
        p[size-1-i]=tmp;
    }
}

#define CHKCMP(p,q,pos,size) do{\
int r = memcmp(p+pos,q+pos,size);\
if(r!=0){fprintf(stderr,"failed on pos %d\n",pos);return r;}\
}while(0)
    
int gtmemcmp(const char *p, const char *q, int size)
{
    int i;
    int j;
    const unsigned char* p_d = p;
    int pos = 0;
    CHKCMP(p,q,0,4);
    CHKCMP(p,q,4,1);
    CHKCMP(p,q,8,8);
    int type = p[4];
    int n = p[13]|p[14]<<8|p[15]<<16;
    pos = 16;
    if(type==2){
        //CHKCMP(p,q,pos,4*n);
        float *p_a = (float *)(p + pos);
        float *q_a = (float *)(q + pos);
        
        
        for(i = 0; i < n; i++) {
            //sw((char *)&p_a[i], sizeof(float));
            //sw((char *)&q_a[i], sizeof(float));
            if(fabsf(p_a[i]) < 0.00001 && fabsf(p_a[i]) > -0.00001) {
                if(fabsf(p_a[i] - q_a[i]) > 0.00001) {
                    fprintf(stderr,"failed on array %d, p =%f, q = %f, fabsf(p_a - q_a)=%f, p_a-q_a=%f\n",i, p_a[i], q_a[i], fabsf(p_a[i] - q_a[i]), p_a[i]-q_a[i]);
                    
                    for(j=0; j<8;j++) {
                        printf("%02x ", p_d[j]);
                    }
                    printf(" \n");
                    for(j=8; j<16;j++) {
                        printf("%02x ", p_d[j]);
                    }
                    printf(" \np=");
                    
                        printf("%08x ", *((unsigned int*)&p_a[i]));
                    
                    printf(" \nq=");
                    
                        printf("%08x ", *((unsigned int*)&q_a[i]));
                    
                    printf(" \n");
                    
                    return 1;
                }
                else {
                    //printf("[%d]p=%f q=%f\n", i, p_a[i], q_a[i]);
                }
            }
            else {
                if(fabsf(p_a[i] - q_a[i])/fabsf(p_a[i]) > 0.00001) {
                    fprintf(stderr,"failed on array %d, p =%f, q = %f, fabsf(p_a - q_a)=%f, p_a-q_a=%f\n",i, p_a[i], q_a[i], fabsf(p_a[i] - q_a[i]), p_a[i]-q_a[i]);
                    
                    for(j=0; j<8;j++) {
                        printf("%02x ", p_d[j]);
                    }
                    printf(" \n");
                    for(j=8; j<16;j++) {
                        printf("%02x ", p_d[j]);
                    }
                    printf(" \np=");
                    
                        printf("%08x ", *((unsigned int*)&p_a[i]));
                    
                    printf(" \nq=");
                    
                        printf("%08x ", *((unsigned int*)&q_a[i]));
                    
                    printf(" \n");
                    
                    return 1;
                }
                else {
                    //printf("[%d]p=%f q=%f\n", i, p_a[i], q_a[i]);
                }
            }
        }
        
    }else if(type==1||type==0){
        int i;
        for(i=0;i<n;i++){
            CHKCMP(p,q,pos,4);
            int ncigar = p[pos+2]|p[pos+3]<<8;
            CHKCMP(p,q,pos,4*ncigar);
            pos += 16+4*ncigar;
            pos = (pos+15)>>4<<4;
        }
    }
    return 0;
}

union test_data{
    float a;
    char b[4];
};

int main(int argc, char **argv)
{
    int ret;
    void* addr;
    int i;
    char infile[256]={0};
    char outfile[256]={0};
    char buff[512];
    FILE *input,*output;
    struct timeval tv_1;
    struct timeval tv_2;
    int64_t ts1;
    int64_t ts2;
    unsigned long long *id1;
    unsigned long long *id2;
    unsigned char* p_data;
    
    /*union test_data data;
    data.a = 1.567;
    printf("%02x %02x %02x %02x\n", data.b[0], data.b[1], data.b[2], data.b[3]);
    
    char a[4];
    a[0] = 1;
    a[1] = 2;
    a[2] = 3;
    a[3] = 4;
    sw(a, 4);
    printf("%d %d %d %d\n", a[0], a[1], a[2], a[3]);
    
    exit(0);*/
    
    if(argc > 1) strcpy(infile,argv[1]);
    if(argc > 1) strcpy(outfile,argv[1]);
    input = fopen(strcat(infile,"inputdata.dat"),"rb");
#if 1
    output = fopen(strcat(outfile,"outputdata.dat"),"rb");
    if(input==NULL || output == NULL) {
        perror("ERROR open data file failed!\n");
        exit(1);
    }
#endif
    
    //init fpga
    ret = fpga_init(BLOCK);
    if(ret) {
        printf("fpga_init failed\n");
        return -1;
    }

    int max_size;
    long nin=0,nout=0;
    int len,olen;
    int err_counter = 0;
    //gettimeofday(&tv_1, NULL);
    while(!feof(input) && fread(&len,4,1,input)>0){
        nout++;
        //sw((char*)&len,4);
        char *data = (char *)malloc(len);
        int rlen = fread(data,1,len,input);
	    if(rlen != len){
            fprintf(stderr,"ERROR:len,rlen:%d,%d\n",len,rlen);
            perror("ERROR:read input data file failed!\n");
            exit(1);
        }

#if 1
        fread(&olen,4,1,output);
        //sw((char*)&olen,4);
        char *odata = (char *)malloc(olen);
        rlen = fread(odata,1,olen,output);
        if(rlen != olen){
            fprintf(stderr,"ERROR:olen,rlen:%d,%d\n",olen,rlen);
            perror("ERROR:read output data file failed!\n");
            exit(1);
        }

        if(argc == 3 && nout != atoi(argv[2])) {
            free(data);
            free(odata);
            continue;
        }
#endif
        //send data to fpga
        addr = NULL;
        

        addr = fpga_get_writebuf(len);
        if(addr == NULL) {
            printf("ERROR:fpga_get_writebuf failed\n");
            exit(1);
        }
        
        memcpy(addr, data, len);
        /*char* tmp_addr = (char *)addr;
        char* tmp_data = (char *)data;
        for(i = 0; i < len; i++) {
            tmp_addr[i] = tmp_data[i];
        }*/
        
        
        id1 = (unsigned long long*)addr;
        id2 = id1 + 1;
        p_data = addr;
        printf("ID:0x%llx\n", *id2);
        printf("len=%d\n", len);
        for(i=0; i<8;i++) {
            printf("%02x ", p_data[i]);
        }
        printf(" \n");
        for(i=8; i<16;i++) {
            printf("%02x ", p_data[i]);
        }
        printf(" \n");
        //sleep(1);
        fpga_writebuf_submit(addr, len);
        
        nin++;
        free(data);
#if 1
        //recv result from fpga
        int outputlen;
        unsigned char *outputdata = NULL;

        outputdata = (char*)fpga_get_retbuf(&outputlen);
        if(outputdata == NULL) {
            printf("ERROR:fpga_get_retbuf failed\n");
            exit(1);
        }
    
        /*printf("outputlen=%d\n", outputlen);
        for(i=0; i<outputlen;i++) {
            if(i%16 == 0)
                printf("\n");
            printf("%02x ", outputdata[i]);
        }
        printf(" \n");*/
        
        if(olen != outputlen || gtmemcmp(odata,outputdata,olen) != 0){
            fprintf(stderr,"ERROR:wrong result on %ld\n",nout);
            //fpga_release_retbuf(outputdata);
            //fpga_finalize();
            //exit(1);
            err_counter++;
        }
    
        fpga_release_retbuf(outputdata);

        
        free(odata);
        printf("data %ld ok!\n", nout);
#endif
        //fpga_finalize();
        //exit(0);
    }
    printf("max_size=%d\n", max_size);
    //gettimeofday(&tv_2, NULL);
    //ts1 = (int64_t)tv_1.tv_sec * 1000000 + tv_1.tv_usec;
    //ts2 = (int64_t)tv_2.tv_sec * 1000000 + tv_2.tv_usec;
    //printf("%lld usec\n", ts2 - ts1);
    printf("all ok! err:%d\n", err_counter);
    fpga_finalize();
    return 0;
}
