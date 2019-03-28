LLC ?= llc
CLANG ?= clang

PLATFORM_INCLUDE := /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include
#PLATFORM_INCLUDE := /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk/usr/include

NOSTDINC_FLAGS := -nostdinc -isystem $(shell $(CC) -print-file-name=include) -isystem $(PLATFORM_INCLUDE)

BPF_OBJECTS = p1.o p2.o p3.o p4.o p5.o p6.o

all: $(BPF_OBJECTS)

$(BPF_OBJECTS): %.o: %.c Makefile
	$(CLANG) -S $(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(EXTRA_CFLAGS) \
	    -D__KERNEL__ -D__ASM_SYSREG_H \
	    -D__BPF_TRACING__ \
	    -Wall \
	    -Wno-unused-value -Wno-pointer-sign \
	    -D__TARGET_ARCH_$(ARCH) \
	    -Wno-compare-distinct-pointer-types \
	    -Wno-gnu-variable-sized-type-not-at-end \
	    -Wno-tautological-compare \
	    -Wno-unknown-warning-option \
	    -Wno-address-of-packed-member \
	    -O2 -emit-llvm -c $< -o ${@:.o=.ll}
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}
