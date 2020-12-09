all:
	clang -o cproxycli -lelf -lbpf -I ./include ./src/*.c
clean:
	rm cproxycli
