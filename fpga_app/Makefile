all:
	gcc -g -o fpga_test fpga_test.c ../fpga_lib/libfpgadrv.a -lpthread
	gcc -g -o cd_test cd_test.c ../fpga_lib/libfpgadrv.a -lpthread
	g++ -g -o fpga_thread_test fpga_thread_test.cpp ../fpga_lib/libfpgadrv.a -lpthread
	gcc -g -o fpga_set_data fpga_set_data.c ../fpga_lib/libfpgadrv.a
	gcc -g -o data_merge data_merge.c ../fpga_lib/libfpgadrv.a

clean:
	rm -f fpga_test fpga_set_data fpga_thread_test cd_test