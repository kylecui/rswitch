# S1 复现套件 v0.1 —— 在目标 guest 上执行（工具链见 ENV_PROBE.sh G4）
CLANG  ?= clang
GCC    ?= gcc
ARCH   := $(shell uname -m)
INC    := -I/usr/include/$(ARCH)-linux-gnu
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 $(INC) -I.

all: min_slice.bpf.o trace_export.bpf.o min_slice.skel.h trace_export.skel.h min_ctl

%.bpf.o: bpf/%.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

trace_export.bpf.o: bpf/trace_export.bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

min_slice.skel.h: min_slice.bpf.o
	bpftool gen skeleton min_slice.bpf.o > $@

trace_export.skel.h: trace_export.bpf.o
	bpftool gen skeleton trace_export.bpf.o > $@

min_ctl: user/min_ctl.c min_slice.skel.h trace_export.skel.h
	$(GCC) -O2 -Wall -I. -o $@ $< -lbpf

clean:
	rm -f *.bpf.o *.skel.h min_ctl trace_events.jsonl

.PHONY: all clean
