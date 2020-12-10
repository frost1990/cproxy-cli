#include <unistd.h>
#include <stdlib.h>

#include "screen.h"
#include "datapath.h"

int main(int argc, char **argv) 
{
	if (argc == 2 && strcasecmp(argv[1], "stat") == 0) {
		show_stat();
		exit(EXIT_SUCCESS);
	}

	if (argc != 4) {
		SCREEN(SCREEN_YELLOW, stderr, "usage: %s tcp/udp frontend/backend frontend_ip/backend_ip:port\n", argv[0]);
		SCREEN(SCREEN_YELLOW, stderr, "example: %s frontend udp 172.17.0.2:53\n", argv[0]);
		SCREEN(SCREEN_YELLOW, stderr, "example: %s backend tcp 10.8.164.116:8080\n", argv[0]);
		exit(EXIT_FAILURE);
	} 
	char *type = argv[1];
	char *proto = argv[2];
	char *l4addr = argv[3];
	
	if (strcasecmp(type, "frontend") == 0) {
		show_datapath(proto, l4addr);
	} else if (strcasecmp(type, "backend") == 0) {
		show_backends(proto, l4addr);
	} else {
		SCREEN(SCREEN_RED, stderr, "incorrect type: %s\n", type);
		exit(EXIT_FAILURE);
	}
	return 0;
}
