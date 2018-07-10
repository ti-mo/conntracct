uname=$(shell uname -r)
LINUX_HEADERS=/lib/modules/$(uname)/build

BPF_OBJ=bpf/acct.o
SOURCES := $(shell find $(SOURCEDIR) -name '*.go')

conntracct: ${SOURCES} ${BPF_OBJ}
	go build

${BPF_OBJ}: bpf/*.c bpf/*.h
	clang -D__KERNEL__ -D __BPF_TRACING__ \
		-fno-stack-protector \
		-Wno-address-of-packed-member \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
		-O2 -emit-llvm -ferror-limit=1 -c bpf/acct.c \
		$(foreach path,$(LINUX_HEADERS), -I $(path)/arch/x86/include -I $(path)/arch/x86/include/generated -I $(path)/include -I $(path)/include/generated/uapi -I $(path)/arch/x86/include/uapi -I $(path)/include/uapi) \
		-o - | llc -march=bpf -filetype=obj -o ${BPF_OBJ}
