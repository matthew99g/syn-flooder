#ifndef __NETWORK_H___
#define __NETWORK_H___

#define __USE_MISC 1

#include <features.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <linux/if_addr.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <getopt.h>
#include <pthread.h>
/*
	Syn Flood DOS with LINUX sockets
*/

#define ETH_ADDRLEN    6       // octets in one address
#define ETH_HDRHLEN    14      // octets in entire header

#define bool uint8_t

#define TRUE 0x1
#define FALSE 0x0

struct eth_hdr {
    unsigned char   h_dest[ETH_ADDRLEN];       // Destination address
    unsigned char   h_source[ETH_ADDRLEN];     // Source address
    __be16          h_proto;                // Packet type ID field
};

//
//// This function sends a string of text to a socket descriptor
bool SendStringServer(int sockfd, char *buffer) {
    int iSentBytes, iBytesToSend;
    iBytesToSend = strlen(buffer);

    // Continue to send information as long
    // as there are remaining bytes to send
    while(iBytesToSend > 0) {
            iSentBytes = send(sockfd, buffer, iBytesToSend, 0);
            if(iSentBytes == -1)
                return FALSE;

        // Calculate new ptr and sub iBytesToSend
        iBytesToSend -= iSentBytes;
        buffer += iSentBytes;
    }

    return TRUE;
}

#define EOL "\r\n"  // End of line sequence
#define EOL_SIZE 2

//
//// Recieves string of data from from server
int RecvStringServer(int sockfd, char *szDestinationBuffer) {
    char *ptr;
    int iEolMatched = 0;

    ptr = szDestinationBuffer;

    // Loop as long as data is recieved
    while(recv(sockfd, ptr, 1, 0) == 1) {
        // Check if EOL is found
        if(*ptr == EOL[iEolMatched]) {
            iEolMatched++;
            if(iEolMatched == EOL_SIZE) {
                *(ptr + 1 - EOL_SIZE) = '\0';
                return strlen(szDestinationBuffer);
            }

        } else {
            iEolMatched = 0;
        }
        
        ptr++;
    }
    return 0;
}

void dump(char *buffer, unsigned int size) {
    for(int i = 0; i < size; i++) {
        printf("0x%02x ", (uint8_t)buffer[i]);
    }

    memset(buffer, '\0', size);

    printf("\n");
}

void DecodeEthr(const char *szBuffer) {
    struct eth_hdr *eth;
    eth = (struct eth_hdr *)szBuffer;

    printf("\nSource: %02x", eth->h_source[0]);
    for(int i = 1; i < ETH_ADDRLEN; i++)
        printf(":%02x", eth->h_source[i]);

    printf("\n");

    printf("Destination: %02x", eth->h_dest[0]);
    for(int i = 1; i < ETH_ADDRLEN; i++)
        printf(":%02x", eth->h_dest[i]);

    printf("\n\n");
}

void DecodeIp(const char *szBuffer) {
    struct iphdr *ip;
    struct in_addr *addr;
    ip = (struct iphdr *)szBuffer;
    addr = (struct in_addr *)&ip->saddr;

    printf("Source: 0x%02x | %s\n", ip->saddr, inet_ntoa(*addr));

    addr = (struct iphdr *)&ip->daddr;

    printf("Destination: 0x%02x | %s\n\n", ip->daddr, inet_ntoa(*addr));
}

__u_int DecodeTcp(const char *szBuffer) {
    struct tcphdr *tcp;
    __u_int uHeaderSize;

    tcp = (struct tcphdr *)szBuffer;
    uHeaderSize = 4 * tcp->th_off;

    printf("Source PORT: %hu\n", ntohs(tcp->th_sport));
    printf("Destination PORT: %hu\n", ntohs(tcp->th_dport));
    printf("Seq #: %u\n", ntohl(tcp->th_seq));
    printf("Ack #: %u\n", ntohl(tcp->th_ack));
    printf("Header Size: %u\nFlags: ", uHeaderSize);
    if(tcp->th_flags & TH_FIN)
        printf("FIN ");
    if(tcp->th_flags & TH_ACK)
        printf("ACK ");
    if(tcp->th_flags & TH_RST)
        printf("RST ");
    if(tcp->th_flags & TH_PUSH)
        printf("PUSH ");
    if(tcp->th_flags & TH_SYN)
        printf("SYN ");
    if(tcp->th_flags & TH_URG)
        printf("URG ");

    printf("\n\n");
    
}

struct pseudo_header    //needed for checksum calculation
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	
	struct tcphdr tcp;
};

unsigned short csum(unsigned short *ptr,int nbytes) {
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum>>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	
	return(answer);
}

void CreateSockaddr(struct sockaddr_in *sin, int port_num,
        uint16_t family, const char *ip_address) {
    memset(sin, '\0', sizeof(struct sockaddr_in));

    sin->sin_family = family;
    sin->sin_port = htons(port_num);
    inet_pton(family, ip_address, &sin->sin_addr);
}

void CreateArpHeader(struct iphdr *ip, unsigned int protocol,
        in_addr_t destination) {
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    ip->id = htons(12345);
    ip->frag_off = 0;
    ip->ttl = 255;
    ip->protocol = protocol;
    ip->check = 0;
    ip->saddr = inet_addr("10.15.46.123");
    ip->daddr = destination;
}

void CreateTcpHeader(struct tcphdr *tcph, int port) {
    tcph->source = htons (1234);
	tcph->dest = htons (port);
	tcph->seq = 0;
	tcph->ack_seq = 0;
	tcph->doff = 5;		/* first and only tcp segment */
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons (5840);	/* maximum allowed window size */
	tcph->check = 0;/* if you set a checksum to zero, your kernel's IP stack
				should fill in the correct checksum during transmission */
	tcph->urg_ptr = 0;
}

#endif