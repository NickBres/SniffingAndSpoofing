#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h> // for inet_ntoa()
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <stdlib.h>


char* create_reply_packet(const u_char *packet, int sizeEth, int length);
int send_reply(char *reply,int length, struct sockaddr_in dest);
unsigned short calculate_checksum(unsigned short *paddress, int len);