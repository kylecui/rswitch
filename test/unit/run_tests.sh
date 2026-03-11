#!/bin/bash
set -e

if [ $(id -u) -ne 0 ]; then
    echo "Must run as root for BPF"
    exit 1
fi

BPF_DIR=./build/bpf
TEST_DIR=./build

echo "Running dispatcher tests"
$TEST_DIR/test_dispatcher $BPF_DIR/dispatcher.bpf.o

echo "Running ACL tests"
$TEST_DIR/test_acl $BPF_DIR/acl.bpf.o

echo "Running VLAN tests"
$TEST_DIR/test_vlan $BPF_DIR/vlan.bpf.o

if [ -x "$TEST_DIR/test_acl_bpf" ]; then
    echo "Running ACL BPF_PROG_RUN harness"
    $TEST_DIR/test_acl_bpf $BPF_DIR/acl.bpf.o $TEST_DIR/test_acl_bpf.junit.xml
fi

echo "All BPF unit tests completed"
