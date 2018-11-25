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
#include <unistd.h>
#include <math.h>
#include <map>
#include "../fpga_lib/fpga.h"


#define ID_MASK 0x000000FFFFFFFFFF

typedef struct data_info {
    long offset;
    int len;
}data_info_t;

std::map<unsigned long long, data_info_t> offset_table;

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
    
int gtmemcmp(char *p, char *q, int size)
{
    int i;
    int j;
    unsigned char* p_d = (unsigned char*)p;
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

FILE *input,*output;

void* send_thread(void *)
{
    int ret;
    void* addr;
    int len;
    int send_count = 0;
    
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
        addr = fpga_get_writebuf(len);
        if(addr == NULL) {
            exit(1);
        }
    
        memcpy(addr, data, len);
        
        /*id1 = (unsigned long long*)addr;
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
        printf(" \n");*/
        
        if(fpga_writebuf_submit(addr, len)) {
            exit(1);
        }
        free(data);
        send_count++;
    }
    //printf("send thread exit, send_count=%d\n", send_count);
    return NULL;
}

int main(int argc, char* argv[])
{
    int ret;
    pthread_t p_send;
    char infile[256]={0};
    char outfile[256]={0};
    int rlen;
    int olen;
    int ret_num = 0;
    
    if(argc > 1) strcpy(infile,argv[1]);
    if(argc > 1) strcpy(outfile,argv[1]);
    input = fopen(strcat(infile,"inputdata.dat"),"rb");
    output = fopen(strcat(outfile,"outputdata.dat"),"rb");
    if(input==NULL || output == NULL) {
        perror("ERROR open data file failed!\n");
        exit(1);
    }
    
    ret = fpga_init(BLOCK);
    if(ret) {
        printf("fpga_init failed\n");
        return -1;
    }
    
    int max_size = 0;
    long offset;
    while(!feof(output) && fread(&olen,4,1,output)>0) {
        //sw((char*)&olen,4);
        char *odata = (char *)malloc(olen);
        unsigned long long* p = (unsigned long long*)odata;
        offset = ftell(output);
        rlen = fread(odata,1,olen,output);
        if(rlen != olen){
            fprintf(stderr,"ERROR:olen,rlen:%d,%d\n",olen,rlen);
            perror("ERROR:read output data file failed!\n");
            exit(1);
        }

        unsigned long long type = odata[4];
        unsigned long long tmp_type = type;
        
        
        
        type = type << 56;
        
        unsigned long long id = p[1];
        //sw((char*)&id, 8);
        id = id & ID_MASK;
        id = id | type;
        
        data_info_t info;
        info.offset = offset;
        info.len = olen;
        
        //printf("file_id=0x%016llx\n", id);
        std::map<unsigned long long, data_info_t>::iterator it = offset_table.find(id);
        if(it != offset_table.end()) {
            printf("already have 0x%016llx\n", id);
        }
        ret_num++;
        offset_table.insert(std::pair<unsigned long long, data_info_t>(id, info));
        free(odata);
    }
    fseek(output, 0, SEEK_SET);
    pthread_create(&p_send, NULL, send_thread, NULL);
    
    int err_count = 0;
    //sleep(1);
    while(1) {
        int i = 0;
        int outputlen;
        unsigned char *outputdata = NULL;

        outputdata = (unsigned char*)fpga_get_retbuf(&outputlen);
        if(outputdata == NULL) {
            printf("ERROR:fpga_get_retbuf failed\n");
            exit(1);
        }
        
        unsigned long long* p = (unsigned long long*)outputdata;
        unsigned long long type = outputdata[4];
        type = type << 56;
        
        unsigned long long id = p[1];
        //sw((char*)&id, 8);
        id = id & ID_MASK;
        id = id | type;
        
        std::map<unsigned long long, data_info_t>::iterator it = offset_table.find(id);
        
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
            if(gtmemcmp(odata, (char *)outputdata, olen) != 0) {
                
                /*printf(" \n");
                for(i=0; i<outputlen;i++) {
                    if(i%16 == 0)
                        printf("\n");
                    printf("%02x ", outputdata[i]);
                    
                }
                printf(" \n");*/
                
                err_count++;
                fprintf(stderr,"ERROR:wrong result on 0x%016llx\n",id);
            }
            //printf("out_id=0x%016llx\n", id);
        }
        
        if(fpga_release_retbuf(outputdata)) {
            exit(1);
        }
        ret_num--;
        //printf("ret_num=%d\n", ret_num);
        if(ret_num == 0)
            break;
    }
    printf("ret_num=%d err_count=%d\n", ret_num, err_count);
    pthread_join(p_send, NULL);
    return 0;
}
