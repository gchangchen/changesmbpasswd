

OBJ = changesmbpasswd.o qs_parse.o picohttpparser.o

DEBUG ?= 0
ifeq ($(DEBUG), 0)
	LDFLAGS += -s
	CFLAGS += -O2 -DNDEBUG
else
	CFLAGS += -g
endif

CC = $(CROSS_COMPILE)gcc
#CC = $(CROSS_COMPILE)clang
LD = $(CROSS_COMPILE)ld
AS = $(CROSS_COMPILE)as
CPP = $(CC) -E
AR = $(CROSS_COMPILE)ar
NM = $(CROSS_COMPILE)nm
STRIP = $(CROSS_COMPILE)strip
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump

export CC LD AS CPP AR NM STRIP OBJCOPY OBJDUMP CFLAGS LDFLAGS

changesmbpasswd:$(OBJ)
	$(CC) $^ -o $@ $(LDFLAGS) -ldl

.PHONY:clean
clean:
	rm -rf *.o changesmbpasswd



