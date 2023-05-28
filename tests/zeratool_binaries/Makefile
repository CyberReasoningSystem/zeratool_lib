# Adapted from Zeratool's tests/Makefile

build_flags := -fno-stack-protector -z execstack \
	-Wno-implicit-function-declaration -no-pie \
	-Wno-format-security -fcf-protection=none -mno-shstk
build_NX_flags := -fno-stack-protector \
	-Wno-implicit-function-declaration -no-pie \
	-Wno-format-security -z relro -fcf-protection=none -mno-shstk

CC := gcc

all: build_bof build_format

build_bof:
	$(CC) -m32 buffer_overflow.c -o bin/bof_32.elf $(build_flags)
	$(CC) -m32 buffer_overflow.c -o bin/bof_nx_32.elf $(build_NX_flags)
	$(CC) -m32 buffer_overflow.c -o bin/bof_win_32.elf -Dwin_func $(build_flags)

build_format:
	$(CC) -O0 -m32 -fno-stack-protector -o bin/read_stack_32.elf \
		format_string.c -DEASY $(build_flags)
	$(CC) -O0 -m32 -fno-stack-protector -o bin/format_pc_write_32.elf \
		format_string.c -DMEDIUM $(build_flags) -z relro
	$(CC) -O0 -m32 -fno-stack-protector -o bin/format_write_and_constrain_32.elf \
		format_string.c -DHARD $(build_flags)

clean:
	rm -rf bin/*