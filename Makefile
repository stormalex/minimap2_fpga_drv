SUB_DIR := fpga_drv fpga_lib fpga_app gatk_test

all:$(SUB_DIR)

$(SUB_DIR):ECHO
	make -C $@

ECHO:
	@echo $(SUB_DIR)
	@echo begin compile

clean:
	$(foreach N, $(SUB_DIR),make clean -C $(N);)
