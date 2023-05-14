GCC_ARGS=main.c -o gvisor-init -static -Wall -Os -s
UID=$(shell id -u)

# For the nolibc build to work, the nolibc directory must point to https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/include/nolibc
all:
	test -f nolibc/nolibc.h && gcc -fno-asynchronous-unwind-tables -fno-stack-protector -fno-ident -nostdlib -include nolibc/nolibc.h -lgcc $(GCC_ARGS)
# glibc does not work for gVisor because of `linkval[0] == '/'` assertion.
#	|| musl-gcc $(GCC_ARGS) || gcc $(GCC_ARGS)
install:
	test "$(UID)" = "0" && mkdir -p /usr/local/lib/pallium && install -m 755 gvisor-init /usr/local/lib/pallium || mkdir -p ~/.local/lib/pallium && install -m 755 gvisor-init ~/.local/lib/pallium
