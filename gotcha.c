#include<pcap.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<ctype.h>
#include<errno.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<time.h>

#define SNAP_LEN 1518 //設定一個封包最多捕獲1518 bytes
#define SIZE_ETHERNET 14 //header 必定14 bytes
#define ETHER_ADDR_LEN 6 //address 必定6 bytes
#define MACADDR_STRLEN 18

static const char *mac_ntoa(u_int8_t *d){

    #define STR_BUF 16
    static char mac[STR_BUF][MACADDR_STRLEN];
    static int which = -1;

    which = (which + 1 == STR_BUF ? 0 : which + 1);

    memset(mac[which], 0, MACADDR_STRLEN);
    snprintf(mac[which], sizeof(mac[which]), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);

    return mac[which];
}

//UDP header
typedef struct uheader {
	uint16_t uh_sport;					//source port
	uint16_t uh_dport;					//destination port
	uint16_t uh_length;
	uint16_t uh_sum;				//checksum
}UDP;

//Ethernet header
typedef struct eheader {
	u_char ether_dhost[ETHER_ADDR_LEN];	//destination host address
	u_char ether_shost[ETHER_ADDR_LEN];	//source host address
	u_short ether_type;					//IP? ARP? RARP? etc
}Ethernet;

//IP header
typedef struct iheader {
	u_char  ip_vhl;					//version << 4 | header length >> 2
	u_char  ip_tos;					//type of service
	u_short ip_len;					//total length
	u_short ip_id;					//identification
	u_short ip_off;					//fragment offset field
#define IP_RF 0x8000				//reserved fragment flag
#define IP_DF 0x4000				//dont fragment flag
#define IP_MF 0x2000				//more fragments flag
#define IP_OFFMASK 0x1fff			//mask for fragmenting bits
	u_char  ip_ttl;					//time to live
	u_char  ip_p;					//protocol
	u_short ip_sum;					//checksum
	struct  in_addr ip_src, ip_dst;	//source and dest address
}IP;
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)  (((ip)->ip_vhl) >> 4)

//TCP header
typedef u_int tcp_seq;

typedef struct theader {
	u_short th_sport;				//source port
	u_short th_dport;				//destination port
	tcp_seq th_seq;					//sequence number
	tcp_seq th_ack;					//acknowledgement number
	u_char  th_offx2;				//data offset, rsvd
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
	u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;					//window
	u_short th_sum;					//checksum
	u_short th_urp;					//urgent pointer
}TCP;

void print_hex_ascii_line(const u_char *payload, int len, int offset);
void print_payload(const u_char *payload, int len);

void callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static int count = 1;		//封包計數
	
//declare pointers to packet headers
	const Ethernet *ethernet;	//The Ethernet header
	const IP *ip;				//The IP header
	const TCP *tcp;				//The TCP header
	const UDP *udp;				//The UDP header
	const char *payload;		//Packet payload
//時間函式
	struct tm *lt;
	char timestr[80];
	time_t local_tv_sec;

	int size_ip;
	int size_tcp;
	int size_udp;
	int size_payload;

	local_tv_sec = header->ts.tv_sec;
	lt = localtime(&local_tv_sec);
	strftime(timestr, sizeof(timestr), "%b %d %Y, %X", lt);

//定義Ethernet header
	ethernet = (Ethernet*)(packet);
//計算IP header offset
	ip = (IP*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;	//IP header長度
	if (size_ip < 20) {
		return;
	}
	else {
		printf("\nPacket number %d:  ", count);
		count++;
		switch(ip->ip_p) {
			case IPPROTO_TCP:
//計算TCP header offset
				printf("   Protocol: TCP  ");
				tcp = (TCP*)(packet + SIZE_ETHERNET + size_ip);
				size_tcp = TH_OFF(tcp)*4;
				if(size_tcp < 20) {
					printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
					return;
				}
				printf("  Src MAC: %s  ",mac_ntoa(ethernet->ether_shost));
       			printf("  Dst MAC: %s  ",mac_ntoa(ethernet->ether_dhost));
				printf("  Src port: %d  ", ntohs(tcp->th_sport));
				printf("  Dst port: %d  ", ntohs(tcp->th_dport));
				printf("  Length: %d bytes  ", header->len);
				printf("  Time: %s\n", timestr);
				break;
			case IPPROTO_UDP:
//計算UDP header offset
				printf("  Protocol: UDP  ");
				udp = (UDP*)(packet + SIZE_ETHERNET + size_ip);
				printf("  Src MAC: %s  ",mac_ntoa(ethernet->ether_shost));
       			printf("  Dst MAC: %s  ",mac_ntoa(ethernet->ether_dhost));
				printf("  Src port: %d  ", ntohs (udp->uh_sport));
				printf("  Dst port: %d  ", ntohs (udp->uh_dport));
				printf("  Length: %d bytes  ", ntohs(udp->uh_length));
				printf("  Time: %s\n", timestr);
				break;
			/*case IPPROTO_ICMP:
				printf("  Protocol: ICMP  ");
				printf("  Src MAC: %s  ",mac_ntoa(ethernet->ether_shost));
       			printf("  Dst MAC: %s  ",mac_ntoa(ethernet->ether_dhost));
				printf("  Src IP: %s    ", inet_ntoa(ip->ip_src));
				printf("  Dst IP: %s  ", inet_ntoa(ip->ip_dst));
				printf("  Length: %d bytes  ",header->len);
				printf("  Time: %s\n", timestr);
				break;*/
			case IPPROTO_IP:
				printf("  Protocol: IP  ");
				printf("  Src MAC: %s  ",mac_ntoa(ethernet->ether_shost));
       			printf("  Dst MAC: %s  ",mac_ntoa(ethernet->ether_dhost));
				printf("  Src IP: %s    ", inet_ntoa(ip->ip_src));
				printf("  Dst IP: %s  ", inet_ntoa(ip->ip_dst));
				printf("  Length: %d bytes  ",header->len);
				printf("  Time: %s\n", timestr);
				break;
			default:
				printf("  Protocol: unknown  ");
				printf("  Src MAC: %s  ",mac_ntoa(ethernet->ether_shost));
       			printf("  Dst MAC: %s  ",mac_ntoa(ethernet->ether_dhost));
				printf("  Src IP: %s    ", inet_ntoa(ip->ip_src));
				printf("  Dst IP: %s  ", inet_ntoa(ip->ip_dst));
				printf("  Length: %d bytes  ",header->len);
				printf("  Time: %s\n", timestr);
		}
	}
}

int main(int argc, char *argv[])
{

	char *dev = NULL;				//網路設備名稱
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	const char *filter= " ";		//過濾
	struct bpf_program fp;			//compiled filter program (expression)
	bpf_u_int32 mask;				//子網路遮罩
	bpf_u_int32 net;				//ip

	int num_packets = -1;			//獲取封包數量


	dev = pcap_lookupdev(errbuf);
	if(!dev) {
		printf("Couldn't find default device: %s\n", errbuf);
		exit(1);
	}

//command line 輸入過濾條件
	if(argc == 2) {
		filter = argv[1]; 
	}
	else if(argc > 2) {
		printf("error: unrecognized command-line options\n");
		exit(1);
	}

//獲取設備ip與網路遮罩
	if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		printf("Couldn't get netmask for device: %s\n", errbuf);
		net = mask = 0;
	}

//Print
	printf("Device: %s\n", dev);
//printf("Number of packets: %d\n", num_packets);
	if(!strcmp(filter ," ")) {
		printf("Filter expression: N/A\n");
	}else {
		printf("Filter expression: %s\n", filter);
	}
//打開網絡接口
//(接口名稱, 捕獲封包長度<max 65535>, 混雜模式, 可等待ms數
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if(!handle) {
		printf("Couldn't open device: %s\n", errbuf);
		exit(1);
	}

//返回數據鏈路層類型 (Ex:DLT_EN10MB
//確保對以太網設備的捕獲
	if(pcap_datalink(handle) != DLT_EN10MB) {
		printf("%s is not an Ethernet\n", dev);
		exit(1);
	}

//編譯過濾條件
	if(pcap_compile(handle, &fp, filter, 0, net) == -1) {
		printf("Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
		exit(1);
	}

//設定過濾
	if (pcap_setfilter(handle, &fp) == -1) {
		printf("Couldn't install filter: %s\n", pcap_geterr(handle));
		exit(1);
	}

//捕獲多個封包pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user);
//每捕獲一個就調用callback指定的函式，可在函式中處理封包
//cnt 捕獲封包個數(設為-1將一直捕獲）
	pcap_loop(handle, num_packets, callback, NULL);

//Clean
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}

/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}
