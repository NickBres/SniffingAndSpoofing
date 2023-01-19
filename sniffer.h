#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h> // for inet_ntoa()
#include <netinet/ip_icmp.h>
#include <ctype.h> // for isprint()

#define FILTER_A "tcp and host 127.0.0.1 and dst port 9999"
#define FILTER_C "icmp"

struct myHeader
{
  u_int32_t timestamp;        // unix time 4 bytes (32 bit)
  u_int16_t total_lenght;     // header lenght 2 bytes (16 bit)
  u_char saved : 3;           // 3 bits for the future use must be zero
  u_char cache_flag : 1;      // 1 bit
  u_char steps_flag : 1;      // 1 bit
  u_char type_flag : 1;       // 1 bit
  u_int16_t status_code : 10; // 10 bits. 2xx, 3xx, 4xx, 5xx
  u_int16_t cache_control;    // 2 bytes (16 bit)
  u_int16_t padding;          // 2 bytes (16 bit)
};

char *getDevice(char *errbuf, pcap_t *handle);
void printDataHex(FILE *fp, char *data, int size);
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void partA(const u_char *packet,int sizeEth, int length);
void partC(const u_char *packet, int sizeEth, int length);
void print_hex_ascii_line(const u_char *payload, int len, int offset);
void print_payload(const u_char *payload, int len);
