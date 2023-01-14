
#include "sniffer.h"

int count = 1;
FILE *log;

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;

  char *devname = getDevice(errbuf, handle);

  // Open the device for sniffing
  printf("Opening device %s for sniffing ...\n", devname);
  handle = pcap_open_live(devname, 65536, 1, 0, errbuf);

  if(handle == NULL)
  {
    fprintf(stderr, "Couldn't open device %s: %s\n", devname, errbuf);
    return (2);
  }

  char *filter_exp;
  char c;
  printf("Enter A to catch Matala2 or C to catch Matala4 \n");
  scanf(" %c", &c);

  if (c == 'A')
  {
    filter_exp = FILTER_A;
  }
  else if (c == 'C')
  {
    filter_exp = FILTER_C;
  }
  else
  {
    printf("Wrong input\n");
    return 0;
  }

  printf("filter: %s\n", filter_exp);
  bpf_u_int32 net;
printf("1\n ");
  // Step 2: Compile filter_exp into BPF psuedo-code
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
  {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
  }
printf("2\n ");
  if (pcap_setfilter(handle, &fp) == -1)
  {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    return (2);
  }
printf("3\n ");

  log = fopen("log.txt", "w");
  if (log == NULL)
  {
    printf("Error opening file!\n");
    return 0;
  }

  printf("start sniffing...\n");
  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle); // Close the handle
  return 0;
};

void printDataHex(FILE *fp, char *data, int size)
{
  int i = 0;
  for (i = 0; i < size; i++)
  {
    fprintf(fp, "%x ", data[i]);
  }
  fprintf(fp, "\n");
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  int length = header->len;

  struct ethhdr *eth = (struct ethhdr *)packet;
  int sizeEth = sizeof(struct ethhdr) + 2;

  printf("--------------Packet No.%d Size: %d--------------\n", count, length);
  fprintf(log, "--------------Packet No.%d Size: %d--------------\n", count++, length);
  printf("size of eth: %d + 2?\n", sizeof(struct ethhdr));

  struct iphdr *iph = (struct iphdr *)(packet + sizeEth);

  fprintf(log, "_____________________IP_____________________\n");

  struct sockaddr_in source, dest;
  memset(&source, 0, sizeof(source));
  source.sin_addr.s_addr = iph->saddr;
  memset(&dest, 0, sizeof(dest));
  dest.sin_addr.s_addr = iph->daddr;

  fprintf(log, "| source ip: %s | dest ip: %s |\n", inet_ntoa(source.sin_addr), inet_ntoa(dest.sin_addr));
  printf("size of ip: %d\n", sizeof(struct iphdr));

  if (iph->protocol == 6)
  {
    partA(packet, sizeEth, length);
  }
  else if (iph->protocol == 1)
  {
    partC(packet, sizeEth, length);
  }
  else
  {
    printf("not tcp or icmp\n");
  }
};

void partA(const u_char *packet, int sizeEth, int length)
{
  fprintf(log, "_____________________TCP_____________________\n");
  struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr) + sizeEth);
  fprintf(log, "| source port: %u | dest port: %u |\n", ntohs(tcph->source), ntohs(tcph->dest));
  printf("size of tcp: %d\n", sizeof(struct tcphdr));

  fprintf(log, "_____________________PROTOCOL_____________________\n");
  struct myHeader *my = (struct myHeader *)(packet + sizeEth + sizeof(struct iphdr) + sizeof(struct tcphdr));
  fprintf(log, "| timestamp: %u |", ntohl(my->timestamp));
  fprintf(log, " total_lenght: %u |", ntohs(my->total_lenght));
  fprintf(log, " cache_flag: %d |", my->cache_flag);
  fprintf(log, " steps_flag: %d |", my->steps_flag);
  fprintf(log, " type_flag: %d |", my->type_flag);
  fprintf(log, " status_code: %u |", ntohs(my->status_code));
  fprintf(log, " cache_control: %u |\n", ntohs(my->cache_control));
  printf("size of protocol: %d\n", sizeof(struct myHeader));

  int dataSize = length - sizeEth - sizeof(struct iphdr) - sizeof(struct tcphdr) - sizeof(struct myHeader);
  if (dataSize > 0)
  {
    fprintf(log, "_____________________data_____________________\n");
    char *data = (char *)(packet + sizeEth + sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(struct myHeader));
    printDataHex(log, data, length - sizeEth - sizeof(struct iphdr) - sizeof(struct tcphdr) - sizeof(struct myHeader));
    printf("size of data: %d\n", dataSize);
  }
  fprintf(log, "\n\n");
}

void partC(const u_char *packet, int sizeEth, int length)
{
  fprintf(log, "_____________________ICMP_____________________\n");
  struct icmphdr *icmph = (struct icmphdr *)(packet + sizeof(struct iphdr) + sizeEth);
  fprintf(log, "   |-Type : %d", (unsigned int)(icmph->type));
  if ((unsigned int)(icmph->type) == 11)
  {
    fprintf(log, "  (TTL Expired)\n");
  }
  else if ((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
  {
    fprintf(log, "  (ICMP Echo Reply)\n");
  }
  fprintf(log, "   |-Code : %d\n", (unsigned int)(icmph->code));
  fprintf(log, "   |-Checksum : %d\n", ntohs(icmph->checksum));
  printf("size of icmp: %d\n", sizeof(struct icmphdr));

  int dataSize = length - sizeEth - sizeof(struct iphdr) - sizeof(struct icmphdr);
  if (dataSize > 0)
  {
    fprintf(log, "_____________________DATA_____________________\n");
    char *data = (char *)(packet + sizeEth + sizeof(struct iphdr) + sizeof(struct icmphdr));
    printDataHex(log, data, length - sizeEth - sizeof(struct iphdr) - sizeof(struct icmphdr));
    printf("size of data: %d\n", dataSize);
    fprintf(log, "\n\n");
  }
}

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
}