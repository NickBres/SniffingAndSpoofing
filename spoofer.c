#include "spoofer.h"
#include "sniffer.h"

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;

    char *devname = getDevice(errbuf, handle);

    // Open the device for sniffing
    printf("Opening device %s for sniffing ...\n", devname);
    handle = pcap_open_live(devname, 65536, 1, 1, errbuf);

    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", devname, errbuf);
        return (2);
    }

    char *filter_exp = FILTER_C;

    printf("filter: %s\n", filter_exp);
    bpf_u_int32 net;
    // Step 2: Compile filter_exp into BPF psuedo-code
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return (2);
    }
    printf("start sniffing...\n");
    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); // Close the handle
    return 0;
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    int len = header->len;
    if (len >= sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr))
    {
        int ethLen = sizeof(struct ethhdr) + 2;
        struct iphdr *ip_header = (struct iphdr *)(packet + ethLen);
        struct icmphdr *icmp_header = (struct icmphdr *)(packet + ethLen + sizeof(struct iphdr));
        if(icmp_header->type == 8)
        {
            struct sockaddr_in dest;
            dest.sin_addr.s_addr = ip_header->daddr;
            
            printf("Catched ICMP echo request to %s\n", inet_ntoa(dest.sin_addr));
            char *reply = create_reply_packet(packet, ethLen, len);
            dest.sin_family = AF_INET;
            int i = send_reply(reply, len - ethLen, dest );
            if(i == -1)
            {
                printf("Error sending reply\n");
            }
            else
            {
                printf("Reply sent: %d bytes\n",i);
            }
        }
    }
};

int send_reply(char *reply,int length, struct sockaddr_in dest){
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0)
    {
        perror("socket");
        return -1;
    }
    int enable = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable)); 
    int i = sendto(sock, reply, length, 0, (struct sockaddr *)&dest, sizeof(dest));
    if (i < 0)
    {
        perror("sendto");
        return -1;
    }
    close(sock);

    return i;
};

char* create_reply_packet(const u_char *packet, int sizeEth, int length)
{
    char *reply = malloc(length - sizeEth);
    struct iphdr *ip_header = (struct iphdr *)(packet + sizeEth);
    struct icmphdr *icmp_header = (struct icmphdr *)(packet + sizeEth + sizeof(struct iphdr));
    char *data = (char *)(packet + sizeEth + sizeof(struct iphdr) + sizeof(struct icmphdr));
    int dataLen = length - sizeEth - sizeof(struct iphdr) - sizeof(struct icmphdr);

    struct iphdr *ip_header_reply = (struct iphdr *)(reply);
    struct icmphdr *icmp_header_reply = (struct icmphdr *)(reply + sizeof(struct iphdr));
    char *data_reply = (char *)(reply + sizeof(struct iphdr) + sizeof(struct icmphdr));

    // ip header
    ip_header_reply->ihl = ip_header->ihl;
    ip_header_reply->version = ip_header->version;
    ip_header_reply->tos = ip_header->tos;
    ip_header_reply->tot_len = ip_header->tot_len;
    ip_header_reply->id = ip_header->id;
    ip_header_reply->frag_off = ip_header->frag_off;
    ip_header_reply->ttl = ip_header->ttl;
    ip_header_reply->protocol = ip_header->protocol;
    ip_header_reply->check = ip_header->check;
    ip_header_reply->saddr = ip_header->daddr;
    ip_header_reply->daddr = ip_header->saddr;

    // icmp header
    icmp_header_reply->type = 0;
    icmp_header_reply->code = 0;
    icmp_header_reply->checksum = 0;
    icmp_header_reply->un.echo.id = icmp_header->un.echo.id;
    icmp_header_reply->un.echo.sequence = icmp_header->un.echo.sequence;

    memcpy(data_reply, data, dataLen);

    icmp_header_reply->checksum = calculate_checksum((unsigned short *)icmp_header_reply, sizeof(struct icmphdr) + dataLen);

    return reply;
};

char *getDevice(char *errbuf, pcap_t *handle)
{

  int count = 1, n;
  pcap_if_t *alldevsp, *device;
  char *devs[100][100];
  // First get the list of available devices
  printf("Finding available devices ... ");
  if (pcap_findalldevs(&alldevsp, errbuf))
  {
    printf("Error finding devices : %s", errbuf);
    return 1;
  }
  printf("Done");

  // Print the available devices
  printf("\nAvailable Devices are :\n");
  for (device = alldevsp; device != NULL; device = device->next)
  {
    printf("%d. %s - %s\n", count, device->name, device->description);
    if (device->name != NULL)
    {
      strcpy(devs[count], device->name);
    }
    count++;
  }

  // Ask user which device to sniff
  printf("Enter the number of the device you want to sniff : ");
  scanf("%d", &n);
  if (handle == NULL)
  {
    fprintf(stderr, "Couldn't open device %s : %s\n", devs[n], errbuf);
    return 1;
  }
  printf("Done\n");
  char *devName = devs[n];
  return devName;
};
// Compute checksum (RFC 1071).
unsigned short calculate_checksum(unsigned short *paddress, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = paddress;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1)
    {
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }

    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits

    return answer;
};