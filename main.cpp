# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <unistd.h>
# include <sys/socket.h>
# include <sys/ioctl.h>
# include <net/if.h>
# include <net/ethernet.h>
# include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/tcp.h>
# include <pcap.h>

# pragma pack(push, 1)
struct pkthdr {
	struct ether_header _ethhdr;
        struct iphdr _iphdr;
        struct tcphdr _tcphdr;
};
# pragma pack(pop)

void usage(void) {
	printf("syntax : tcp-block <interface>< pattern>\n");
	printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

// Reference: https://github.com/lattera/freebsd/blob/master/lib/libc/string/strnstr.c
char* strnstr(const char* s, const char* find, size_t slen) {
	char c, sc;
	size_t len;

	if ((c = *find++) != '\0') {
		len = strlen(find);
		do {
			do {
				if (slen-- < 1)
					return nullptr;
				sc = *s++;
			} while (sc != c);
			if (len > slen)
				return nullptr;
		} while (strncmp(s, find, len) != 0);
		s--;
	}
	return ((char*)s);
}

void getMyMac(u_int8_t* myMac, const char* dev) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		fprintf(stderr, "getMyMac failded\n");
		exit(1);
	}
	struct ifreq ifr;

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		fprintf(stderr, "getMayMac failed\n");
		exit(1);
	}
	memcpy(myMac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	close(fd);
}
char* parseOrgPkt(struct pkthdr* orgpkt, const u_char* packet) {
	char* ptr = (char*) packet;
	
	memcpy(&(orgpkt->_ethhdr), ptr, sizeof(ether_header));
	ptr += sizeof(ether_header);

	memcpy(&(orgpkt->_iphdr), ptr, sizeof(iphdr));
	ptr += (orgpkt->_iphdr.ihl << 2);

	memcpy(&(orgpkt->_tcphdr), ptr, sizeof(tcphdr));
	ptr += (orgpkt->_tcphdr.doff << 2);

	return ptr;
}

void printMac(u_int8_t* mac) {
	for (int i = 0; i < ETH_ALEN; i++)
		printf("%02x ", *(mac + i));
	putchar('\n');
}
/*
void printInfo(struct pkthdr orgpkt) {
		struct in_addr addr;

                printf("smac: "); printMac(orgpkt._ethhdr.ether_shost);
                printf("dmac: "); printMac(orgpkt._ethhdr.ether_dhost);
                
		addr.s_addr = orgpkt._iphdr.saddr;
                printf("sip: %s\n", inet_ntoa(addr));
                addr.s_addr = orgpkt._iphdr.daddr;
                printf("dip: %s\n", inet_ntoa(addr));

                printf("sport: %d\n", ntohs(orgpkt._tcphdr.source));
                printf("dport: %d\n", ntohs(orgpkt._tcphdr.dest));
                
		printf("msg: ");
                for (int i = 0; i < 4; i++)
                        printf("%c ", *(msg + i));
                putchar('\n');
}
*/
int main(int argc, char* argv[])
{
	if (argc != 3) {
		usage();
		exit(1);
	}
	const char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	
	if (handle == nullptr) {
		fprintf(stderr, "pcap_open_live failed\n");
		exit(1);
	}
	u_int8_t myMac[ETH_ALEN];
	const char* finMsg = "blocked!!!";
	getMyMac(myMac, dev);

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);

		if (res == -1 || res == 2) {
			fprintf(stderr, "pcap_next_ex failed\n");
			continue;
		}
		if (res == 0 || strnstr((char*)packet, argv[2], header->caplen) == nullptr)
			continue;
	
		struct pkthdr orgpkt;
		parseOrgPkt(&orgpkt, packet);

		struct pkthdr fpkt;
		struct pkthdr bpkt;

		memcpy(&fpkt, &orgpkt, sizeof(pkthdr));
		memcpy(&bpkt, &orgpkt, sizeof(pkthdr));
		
		/* Ethernet Header */
		memcpy(&(bpkt._ethhdr.ether_dhost), &(orgpkt._ethhdr.ether_shost), sizeof(ETH_ALEN));
		memcpy(&(fpkt._ethhdr.ether_shost), &(myMac), sizeof(ETH_ALEN));
		memcpy(&(bpkt._ethhdr.ether_shost), &(myMac), sizeof(ETH_ALEN));
			
		/* Ipv4 Header */
		fpkt._iphdr.ihl = bpkt._iphdr.ihl = 5;
		fpkt._iphdr.tot_len = htons(((u_int16_t)sizeof(iphdr) + (u_int16_t)sizeof(tcphdr)) >> 2);
		bpkt._iphdr.tot_len = htons(((u_int16_t)sizeof(iphdr) + (u_int16_t)sizeof(tcphdr) + (u_int16_t)strlen(finMsg)) >> 2);
		bpkt._iphdr.ttl = (u_int8_t)0x80;
		
		/* TCP Header */
		bpkt._tcphdr.source = orgpkt._tcphdr.dest;
		bpkt._tcphdr.dest = orgpkt._tcphdr.source;

		u_int16_t tot_orglen = ntohs(orgpkt._iphdr.tot_len) - ((u_int16_t)orgpkt._iphdr.ihl << 2) - ((u_int16_t)orgpkt._tcphdr.doff << 2);
		fpkt._tcphdr.seq = htonl(ntohl(orgpkt._tcphdr.seq) + (u_int32_t)tot_orglen);
		bpkt._tcphdr.seq = orgpkt._tcphdr.ack_seq;
		fpkt._tcphdr.ack_seq = orgpkt._tcphdr.ack_seq;
		bpkt._tcphdr.ack_seq = orgpkt._tcphdr.seq; // why not + tot_orglen?
		
		fpkt._tcphdr.doff = bpkt._tcphdr.doff = (sizeof(tcphdr) >> 6);
		fpkt._tcphdr.ack = fpkt._tcphdr.fin = 1;
		bpkt._tcphdr.rst = 1;
	
		u_char* sendbpkt = (u_char*)malloc(sizeof(bpkt) + strlen(finMsg));
		memcpy(sendbpkt, &bpkt, sizeof(bpkt));
		memcpy(sendbpkt + sizeof(bpkt), finMsg, strlen(finMsg));

		// printf("bpkt rst: %u\n",bpkt._tcphdr.rst); 

		int resf = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&fpkt), sizeof(fpkt));
		int resb = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(sendbpkt), sizeof(bpkt) + strlen(finMsg));
		if (resf != 0 || resb != 0) {
			fprintf(stderr, "pcap_sendpacket failed, return %d %d error %s\n", resf, resb, pcap_geterr(handle));
			exit(1);
		}
		free(sendbpkt);
	}
	pcap_close(handle);
	return 0;
}

