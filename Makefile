all:
	clang -o cproxycli -lelf -lbpf -I/kernel-src/samples/bpf -I/kernel-src/tools/lib -I/kernel-src/tools/perf -I/kernel-src/tools/include  -L/usr/local/lib64 /kernel-src/samples/bpf/bpf_load.c *.c -DHAVE_ATTR_TEST=0
clean:
	rm viewer
