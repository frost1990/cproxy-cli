#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

void sk_ipv4_tostr(uint32_t ip, char *ipstr, size_t ipstr_len) 
{
    ip = ntohl(ip);
    memset(ipstr, 0, ipstr_len);
    size_t offset = 0;
    for (int i = 0; i < 4; i++) {
        char store[128];
        uint8_t segement = ip >> (8 * i); 
        snprintf(store, sizeof(store) - 1, "%u", segement);
        size_t step = strlen(store);
        if (offset + step > ipstr_len - 1 ) { 
            return;
        }   
        offset += step;
        strncat(ipstr, store, step);
        if (i != 3) {
            size_t step_dot = strlen(".");
            if (offset + step_dot > ipstr_len - 1 ) { 
                return;
            }   
            strncat(ipstr, ".", step_dot);
            offset += strlen(".");
        }   
    }   
    return;
}
