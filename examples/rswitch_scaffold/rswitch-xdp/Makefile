# Simple libbpf CO-RE build
# Dependencies: clang llc pkg-config libbpf-dev zlib

BPF_CLANG ?= clang
BPF_LLC   ?= llc
CFLAGS    ?= -O2 -g -Wall -Werror
BPF_CFLAGS ?= -O2 -g -target bpf -D__TARGET_ARCH_x86

BPF_OBJ = xdp_voq_kern.o
USER_OBJ = xdp_voq_user

INCLUDE_DIR = include
SRC_DIR = src

all: $(BPF_OBJ) $(USER_OBJ)

$(BPF_OBJ): $(SRC_DIR)/xdp_voq_kern.c $(INCLUDE_DIR)/vmlinux.h $(INCLUDE_DIR)/rswitch_common.h
	$(BPF_CLANG) $(BPF_CFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

$(USER_OBJ): $(SRC_DIR)/xdp_voq_user.c
	$(CC) $(CFLAGS) -o $@ $< $(shell pkg-config --cflags --libs libbpf) -lelf -lz

clean:
	rm -f $(BPF_OBJ) $(USER_OBJ)

.PHONY: all clean
