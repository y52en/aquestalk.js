CC = clang
LD = ld.lld
CFLAGS = -target i386-pc-none-elf -march=i386 -ffreestanding -nostdlib -Os -fno-asynchronous-unwind-tables -fno-stack-protector -ffunction-sections
LDFLAGS = --oformat=binary -static -Ttext 0

SRCS = strncmp.c strncpy.c strchr.c stricmp.c strtok.c initterm.c cxx_handler.c disable_thread_lib.c
OBJS = $(SRCS:.c=.o)

all: clib.bin

clib.bin: $(OBJS)
	$(LD) $(LDFLAGS) -T linker.ld -o $@ $(OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o *.bin
