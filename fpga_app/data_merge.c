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


void merge_file(char* file_list, char* out_file_name)
{
    char* file_name = NULL;
    size_t file_name_len = 0;
    FILE* out_file = NULL;
    FILE* in_file = NULL;
    struct stat statbuf;
    char* buf = NULL;
    int ret = 0;
    
    FILE* file_l = fopen(file_list, "r");
    if(file_l == NULL) {
        printf("open %s failed\n", file_list);
        return;
    }
    
    out_file = fopen(out_file_name, "w+");
    if(out_file == NULL) {
        printf("open %s failed\n", out_file_name);
        return;
    }
    file_name = malloc(1024);
    while(!feof(file_l)) {
        memset(file_name, 0, 1024);
        fgets(file_name, 1023, file_l);
        int n = strlen(file_name) - 1;
        if(file_name[n] == '\n')file_name[n] = 0;
        printf("file_name=%s\n", file_name);
        
        in_file = fopen(file_name, "r");
        if(in_file == NULL) {
            printf("open %s failed\n", file_name);
            break;
        }
        
        ret = stat(file_name,&statbuf);
        if(ret) {
            printf("stat failed\n");
            exit(0);
        }
        buf = malloc(statbuf.st_size);
        if(buf == NULL) {
            printf("malloc failed\n");
            break;
        }
        
        int read_len = fread(buf, 1, statbuf.st_size, in_file);
        if(read_len != statbuf.st_size) {
            printf("fread failed\n");
            break;
        }
        
        unsigned int *data_size = (unsigned int*)buf;
        if(*data_size != statbuf.st_size - 4) {
            printf("ERROR: data_size=%u, file_size=%d\n", *data_size, statbuf.st_size);
            //exit(0);
            *data_size = statbuf.st_size - 4;
        }
        
        int write_len = fwrite(buf, 1, statbuf.st_size, out_file);
        if(write_len != statbuf.st_size) {
            printf("fwrite failed\n");
            break;
        }
        
        fclose(in_file);
        free(buf);
        buf = NULL;
    }
    fclose(out_file);
    free(file_name);
    return;
}

int main(int argc, char* argv[])
{
    int cnt = 0;
    FILE* out_file = NULL;
    FILE* in_file = NULL;
    struct stat statbuf;
    char *buf = NULL;
    int tid = 0;
    
    system("ls swdriv*in.bin > file_list_in.txt");
    system("ls swdriv*out.bin > file_list_out.txt");
    
    sleep(3);
    
    merge_file("file_list_in.txt", "sw_in.bin");
    merge_file("file_list_out.txt", "sw_out.bin");
    
    return 0;
}