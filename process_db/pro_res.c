#include <pcap.h>
#include <mysql.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 55

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
	u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
	u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
	u_char  ip_vhl;                 /* version << 4 | header length >> 2 （8bits）*/
	u_char  ip_tos;                 /* type of service（8bits） */
	u_short ip_len;                 /* total length（16bits） */
	u_short ip_id;                  /* identification（16bits） */
	u_short ip_off;                 /* fragment offset field（16bits） */
	#define IP_RF 0x8000            /* reserved fragment flag（1bits） */
	#define IP_DF 0x4000            /* dont fragment flag（1bits） */
	#define IP_MF 0x2000            /* more fragments flag（1bits） */
	#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits（13bits） */
	u_char  ip_ttl;                 /* time to live */
	u_char  ip_p;                   /* protocol */
	u_short ip_sum;                 /* checksum */
	struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f) /* Header Length (4bits)*/ 
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)	/* Version (4bits)*/

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;               /* source port */
	u_short th_dport;               /* destination port */
	tcp_seq th_seq;                 /* sequence number */
	tcp_seq th_ack;                 /* acknowledgement number */
	u_char  th_offx2;               /* data offset, rsvd */
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
	#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;                 /* window */
	u_short th_sum;                 /* checksum */
	u_short th_urp;                 /* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void print_payload(const u_char *payload, int len);

void print_hex_ascii_line(const u_char *payload, int len, int offset);

void print_app_usage(void);

/* * print help text */
void
print_app_usage(void)
{
	printf("\n");
	printf("Options:\n");
	printf("    interface    Listen on <interface> for packets.\n");
	printf("\n");

	return;
}

/* * print data in rows of 16 bytes: offset   hex   ascii
  * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1.. */
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{
	int i;
	int gap;
	const u_char *ch;

	printf("%05d   ", offset);
	
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		if (i == 7)
			printf(" ");
	}
	if (len < 8)
		printf(" ");
	
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
			printf("..");
		ch++;
	}

	printf("\n");
	return;
}

/* * print packet payload data (avoid printing binary data) */
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

char *deal(char *keyword, char *payload) {	
	if(!isprint(*payload)) return NULL;
	char *ptr = strstr(payload,keyword);
	if(ptr == NULL) {
		printf("Do not contain '%s'\n ",keyword);
		return NULL;
	}
	ptr = ptr+strlen(keyword);
	if (strcspn(ptr,"\r")+1 == strcspn(ptr,"\n")) {
		int pos = strcspn(ptr,"\r");
		char *res = (char *)malloc(sizeof(char)*(pos+1));
		snprintf(res,pos+1,"%s",ptr);
		return res;
	}
	return NULL;
}

/* * dissect/print packet */
/* pcap_loop(handle, num_packets, got_packet, NULL); NULL的部分可以用来传参数，可以传文件描述符吗？*/ 
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	MYSQL *conn = (MYSQL *)args;

	static int count = 1;                   /* packet counter */
	// if(count > 10) {
	// 	return ;
	// }
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;
	
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
	
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	int size_frame = size_payload+SIZE_ETHERNET + size_ip + size_tcp;
	
	char cont[1024] = { 0 };
	if (size_payload > 0) {
		/* print source and destination IP addresses */
		printf("(1)Packet number %d:\n", count);
		printf("(2)Src Ip Address: %s\n", inet_ntoa(ip->ip_src));
		printf("(3)Dst Ip Address: %s\n", inet_ntoa(ip->ip_dst));
		printf("(4)Src port: %d\n", ntohs(tcp->th_sport));
		printf("(5)Dst port: %d\n", ntohs(tcp->th_dport));
		printf("   Payload (%d bytes):\n", size_payload);

		char *ct = deal("Content-Type:",payload);
		char path[100] = { 0 };
		if(ct != NULL){
			printf("(6)Content-Type: %s\n",ct);
			char *ptr = strstr(payload,"\r\n\r\n");
			if(strcmp(ct," text/html") == 0) {
				sprintf(path,"save/response/%d_content.html",count);
			} else if(strcmp(ct," application/json") == 0) {
				sprintf(path,"save/response/%d_content.json",count);
			} else {
				
			}
			FILE *fp = fopen(path, "w");
			if(ptr!=NULL) {
				fputs(ptr,fp);
			}
			fprintf(stdout,"path:%s\n",path);
		}

		sprintf(cont, "insert into response values(%d,'%s','%s',%d,%d,'%s',%d,'%s')",count, inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst), ntohs(tcp->th_sport), ntohs(tcp->th_dport), ct, size_frame, path);
		count++;
		printf("SQL:\n%s\n",cont);
	
		if(mysql_query(conn,cont)){
			fprintf(stderr,"%s\n",mysql_error(conn));
		}
		printf("----------------------------------\n");
	}
	return;
}

int main(int argc, char **argv)
{
	MYSQL* conn;
	char *server = "localhost";
	char *user = "root";
	char *password = "123456";
	char *database = "packet";

	conn = mysql_init(NULL);

	if(!mysql_real_connect(conn,server,user,password,database,0,NULL,0)) {
		fprintf(stderr,"%s\n",mysql_error(conn));
		exit(1);
	}

	mysql_query(conn,"use packet");
	mysql_query(conn,"truncate response");

	//char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "ip";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 300;			/* number of packets to capture */
	const char *fname = "data/response_new_1000.pcap"; 

	/* check for capture device name on command-line */
	if (argc > 1) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		//print_app_usage();
		exit(EXIT_FAILURE);
	}
	
	handle =  pcap_open_offline(fname, errbuf);
	if(handle == NULL){
		fprintf(stderr, "Couldn't open file %s\n", fname);
		exit(0);
	}
	/* print capture info */
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);


	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n",filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, (u_char *)conn);

	/* cleanup */
	mysql_close(conn);
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

	return 0;
}

