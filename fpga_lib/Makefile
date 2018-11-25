TARGET=libfpgadrv.a
CC = gcc
AR = ar

CFLAGS := $(CFLAGS)

INCDIR += -I../common
CFLAGS += $(INCDIR)

SRCS := $(wildcard *.c)
OBJS := $(patsubst %.c, %.o, $(SRCS))

$(TARGET):$(OBJS)
	$(AR) rv $(TARGET) $(OBJS)

%.o:%.c
	$(CC) -g -c $< $(CFLAGS) -o $@

%.d:%.c
	@set -e; rm -f $@; \
	$(CC) -MM $(CFLAGS) $< > $@; \
	sed 's,\($*\)\.o[ :]*,\1.o $@ : ,g' < $@ > $@; \
	rm -f $@
-include $(SRCS:.c=.d)

.PHONY: clean

clean:
	rm -f $(OBJS) $(TARGET) *.d