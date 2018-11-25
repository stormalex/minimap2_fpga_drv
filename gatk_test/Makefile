all:
	gcc -g -o gtest gtest.c ../fpga_lib/libfpgadrv.a -lpthread
	g++ -g -o gtest_a gtest_a.cpp ../fpga_lib/libfpgadrv.a -lpthread

clean:
	-rm -f gtest gtest_a
