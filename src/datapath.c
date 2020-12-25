#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <asm/byteorder.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>

#include "datapath.h"
#include "screen.h"
#include "sk.h"

static const char *service_map	= "/sys/fs/bpf/tc/globals/cproxy_lb4_services_v2";
static const char *backend_map	= "/sys/fs/bpf/tc/globals/cproxy_lb4_backends";

void print_lb4_backend(struct lb4_backend *p) 
{
    char ipstr[64] = {0};
    sk_ipv4_tostr(ntohl(p->address), ipstr, strlen(ipstr));
	if (p->proto == 17) {
		SCREEN(SCREEN_BLUE, stdout, "--> backend address: udp %s:%d\n", ipstr, __be16_to_cpu(p->port));
	} else {
		SCREEN(SCREEN_BLUE, stdout, "--> backend address: tcp %s:%d\n", ipstr, __be16_to_cpu(p->port));
	}
}

void search_backend_reference(uint32_t backend_id) 
{
	int fd = bpf_obj_get(service_map);
	if (fd < 0) {
		SCREEN(SCREEN_RED, stderr, "failed to fetch the map: %d (%s), file path: %s\n", 
			fd, strerror(errno), backend_map);
		return;
	}

	struct lb4_key lookup_key, next_key;
	lookup_key.address = 0;
	next_key.address = 0;
	struct lb4_service svc;

	while (bpf_map_get_next_key(fd, &lookup_key, &next_key) == 0) {
		bpf_map_lookup_elem(fd, &next_key, &svc);
		if (svc.backend_id == backend_id) {
    		char ipstr[64] = {0};
    		sk_ipv4_tostr(ntohl(next_key.address), ipstr, strlen(ipstr));
			SCREEN(SCREEN_BLUE, stdout, "<-- backend id %d is redirected from frontend %s:%d\n", 
				backend_id, ipstr, ntohs(next_key.dport));	
		}
		lookup_key = next_key;
	}
	close(fd);
}

void show_datapath(char *proto, char *l4addr)
{
	int fd = bpf_obj_get(service_map);
	if (fd < 0) {
		printf("failed to fetch the map: %d (%s), file path: %s\n", fd, strerror(errno), service_map);
		return;
	}	
	struct lb4_key key;
	struct lb4_service  val;

	char *r = malloc(30);
	strcpy(r, l4addr);
    char *ip = strsep(&r, ":");
	if (r == NULL) {
		SCREEN(SCREEN_RED, stderr, "Invalid l4 address %s\n", l4addr);
		exit(EXIT_FAILURE);
	} 
   	int port = atoi(r);

	key.address = inet_addr(ip);
	key.dport = htons(port);
	key.backend_slot = 0;
	if (strcasecmp(proto, "udp") == 0) {
		key.proto = 17;
	} else {
		key.proto = 6;
	}

	if (bpf_map_lookup_elem(fd, &key, &val) != 0) {
		SCREEN(SCREEN_RED, stdout, "L4 frontend address %s %s:%d not found in proxy map: %m\n", proto, ip, port);
		exit(EXIT_FAILURE);
	}
	uint16_t count = val.count;
	if (count > 0) {
		SCREEN(SCREEN_YELLOW, stdout, "L4 frontend address %s %s:%d\n", proto, ip, port);
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
		SCREEN(SCREEN_RED, stderr, "failed to fetch the map: %d (%s), file path: %s\n", 
			fd, strerror(errno), backend_map);
		return;
	}
	struct lb4_backend backend;
	if (bpf_map_lookup_elem(fd, &id, &backend) != 0) {;
		SCREEN(SCREEN_RED, stdout, "Backend ID %d not found in proxy map: %m\n", id);
		exit(EXIT_FAILURE);
	}
	print_lb4_backend(&backend);
	close(fd);
}

bool protoeq(int pn, char *proto) 
{
	return ((pn == 6 && strcasecmp("tcp", proto) == 0) || (pn == 17 && strcasecmp("udp", proto) == 0));
}

void show_backends(char *proto, char *l4addr)
{
	int fd = bpf_obj_get(backend_map);
	if (fd < 0) {
		SCREEN(SCREEN_RED, stderr, 
			"failed to fetch the map: %d (%s), file path: %s\n", fd, strerror(errno), backend_map);
		return;
	}

	char *r = malloc(32 * sizeof(char));
	char *freepos = r;
	strcpy(r, l4addr);
    char *ip = strsep(&r, ":");
	if (r == NULL) {
		SCREEN(SCREEN_RED, stderr, "Invalid l4 address %s\n", l4addr);
		exit(EXIT_FAILURE);
	} 
   	int port = atoi(r);

	struct lb4_backend val;
	uint16_t lookup_key, next_key;

	bool found = false;
	while (bpf_map_get_next_key(fd, &lookup_key, &next_key) == 0) {
		if (bpf_map_lookup_elem(fd, &next_key, &val) != 0){
			SCREEN(SCREEN_RED, stderr, "bpf_map_lookup_elem %d %m", __LINE__);
		}
		lookup_key = next_key;
    	char ipstr[64] = {0};
    	sk_ipv4_tostr(ntohl(val.address), ipstr, strlen(ipstr));
		if (protoeq(val.proto, proto) && strcasecmp(ipstr, ip) == 0 && (uint16_t)port == ntohs(val.port)) {
			found = true;
			SCREEN(SCREEN_YELLOW, stdout, "L4 address %s %s:%d has backend id %d\n", proto, ip, port, next_key);
			uint32_t backend_id = next_key;
			search_backend_reference(backend_id);	
		} 
	}
	if (!found) {
		SCREEN(SCREEN_RED, stdout, "L4 backend address %s %s:%d not found in proxy map.\n", proto, ip, port);
	}
	close(fd);
	free(freepos);
}

void show_stat() 
{
	int fd = bpf_obj_get(service_map);
	if (fd < 0) {
		SCREEN(SCREEN_RED, stderr, "failed to fetch the map: %d (%s), file path: %s\n", 
			fd, strerror(errno), service_map);
		return;
	}

	struct lb4_key lookup_key, next_key;
	lookup_key.address = 0;
	next_key.address = 0;
	struct lb4_service svc;
	int frondend_cnt = 0;
	while (bpf_map_get_next_key(fd, &lookup_key, &next_key) == 0) {
		bpf_map_lookup_elem(fd, &next_key, &svc);
		if (next_key.backend_slot == 0 && svc.count > 0) {
    		char ipstr[64] = {0};
    		sk_ipv4_tostr(ntohl(next_key.address), ipstr, strlen(ipstr));
			char *proto = "tcp";
			if (next_key.proto == 17) {
				proto = "udp";
			}
			SCREEN(SCREEN_BLUE, stderr, "Frontend %s %s:%d with %d backends\n", 
					proto,ipstr, ntohs(next_key.dport), svc.count);
				frondend_cnt++;
		}
		lookup_key = next_key;
	}

	close(fd);
	fd = bpf_obj_get(backend_map);

	int backend_cnt = 0;
	if (fd < 0) {
		SCREEN(SCREEN_RED, stderr, "failed to fetch the map: %d (%s), file path: %s\n", 
			fd, strerror(errno), backend_map);
		return;
	}

	struct lb4_backend bk;
	uint16_t lookup_int, next_int;
	while (bpf_map_get_next_key(fd, &lookup_int, &next_int) == 0) {
		bpf_map_lookup_elem(fd, &next_key, &bk);
		lookup_int = next_int;
		backend_cnt++;
	}

	SCREEN(SCREEN_YELLOW, stderr, "Total:\n");
	SCREEN(SCREEN_YELLOW, stderr, "Frontends number: %d\n", frondend_cnt);
	SCREEN(SCREEN_YELLOW, stderr, "Backends number: %d\n", backend_cnt);
	close(fd);
}
