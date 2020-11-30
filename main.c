#include <unistd.h>
#include <stdlib.h>

#include "screen.h"
#include "datapath.h"

int main(int argc, char **argv) 
{
	if (argc != 4) {
		SCREEN(SCREEN_YELLOW, stderr, "usage: %s frontend/backend/all frontend_ip/backend_ip\n", argv[0]);
		exit(EXIT_FAILURE);
	} 
	char *type = argv[1];
	char *ip = argv[2];
	int port = atoi(argv[3]);
	
	if (strcasecmp(type, "frontend") == 0) {
		show_datapath(ip, port);
	} else if (strcasecmp(type, "backend") == 0) {

	}

	return 0;
}
