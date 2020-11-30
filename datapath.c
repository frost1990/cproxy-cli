#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <asm/byteorder.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "bpf_load.h"

#include "datapath.h"
#include "screen.h"
#include "sk.h"

static const char *service_map		= "/sys/fs/bpf/tc/globals/cilium_lb4_services_v2";
static const char *backend_map		= "/sys/fs/bpf/tc/globals/cilium_lb4_backends";

void print_lb4_backend(struct lb4_backend *p) {
    char ipstr[64] = {0};
    sk_ipv4_tostr(ntohl(p->address), ipstr, strlen(ipstr));
	SCREEN(SCREEN_BLUE, stdout, "--> backend address: %s:%d, proto:%d\n", ipstr, __be16_to_cpu(p->port), p->proto);
}

void show_datapath(char *ip, int port)
{
	int fd = bpf_obj_get(service_map);
	if (fd < 0) {
		printf("failed to fetch the map: %d (%s), file path: %s\n", fd, strerror(errno), service_map);
		return;
	}	
	struct lb4_key key;
	struct lb4_service  val;

	key.address = inet_addr(ip);
	key.dport = htons(port);
	key.backend_slot = 0;

	bpf_map_lookup_elem(fd, &key, &val);
	uint16_t count = val.count;
	if (count > 0) {
		SCREEN(SCREEN_YELLOW, stdout, "L4 frontend addr %s:%d\n", ip, port);
	}
	for (uint16_t i = 1; i <= count; i++) {
		key.backend_slot =  i;
		struct lb4_service val;
		bpf_map_lookup_elem(fd, &key, &val);
		show_backend_by_id(val.backend_id);
	}

	close(fd);
}

void show_backend_by_id(uint32_t id)
{
	int fd = bpf_obj_get(backend_map);
	if (fd < 0) {
		printf("failed to fetch the map: %d (%s), file path: %s\n", fd, strerror(errno), backend_map);
		return;
	}
	struct lb4_backend backend;
	bpf_map_lookup_elem(fd, &id, &backend);
	print_lb4_backend(&backend);
	close(fd);
}

void show_backends(char *ip, int port)
{


}