/*
** Envia pacotes com o ip falso (ip spoofing)
*/
#include <stdlib.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
//#include <net/if_arp.h>
#include <sys/uio.h>

#include <arpa/inet.h>
#include <sys/types.h>
//#include <netpacket/packet.h>
#include <net/ethernet.h> /* the L2 protocols */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <linux/ip.h>
#include <linux/udp.h>

int main(void){
	int sockfd;
	struct sockaddr_ll param;
	int n, ifindex;
	char device[10];
	uint8_t frame[200]; //sizeof(struct arphdr)
	struct ifreq ifr;
	int tam=0;
	struct iphdr *iph;
	struct udphdr *uh;
	uint8_t *p;

	strcpy(device, "lo");

	sockfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP) );
	//sockfd = socket(PF_PACKET, SOCK_DGRAM, 0 );
	 
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, device);
	if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
		fprintf(stderr, "eero: unknown iface %s\n", device);
		exit(2);
	}
	ifindex = ifr.ifr_ifindex;

	printf("ifindex=%d\n", ifindex); 

	param.sll_family = PF_PACKET;   /* Always AF_PACKET */
	param.sll_protocol = htons(ETH_P_IP); /* Physical layer protocol */
	param.sll_ifindex = ifindex;  /* Interface number */
	param.sll_hatype = 0;   /* Header type */
	param.sll_pkttype = 0;  /* Packet type */
	param.sll_halen = 6;    /* Length of address */
	memcpy(param.sll_addr, "\xaa\xaa\xaa\x00\x00\x02", 6);  /* Physical layer address(8) */


	int TAMANHO_DA_MENS = 16;

	iph = (struct iphdr *) frame;
	iph->ihl = 0x5;
	iph->version=0x4;
	iph->tos=0;
	iph->tot_len= htons(20+8+TAMANHO_DA_MENS);
	iph->id=0;
	iph->frag_off=0;
	iph->ttl=0x40;
	iph->protocol=0x11; // 17 em Decimal
	iph->check=0x0;
	memcpy(&iph->saddr,"\x7f\x00\x00\x01",4); //10.1.1.8 - Pode forcar o Ip de origem
	memcpy(&iph->daddr,"\x7f\x00\x00\x01",4); //127.0.0.1

	uh = (struct udphdr *)((uint8_t *)iph + 20);
	uh->source = htons(1972);
	uh->dest = htons(1234);

	

	uh->len = htons(8+TAMANHO_DA_MENS);
	uh->check = 0x0;

	p = (uint8_t *)uh + 8;

	char type[] = {1,2,3,4,5,6,7,8,9,0,5,'t','e','s','t','e'};
	memcpy(p, type, TAMANHO_DA_MENS);

	tam = 20 + 8 + TAMANHO_DA_MENS;

	n = sendto(sockfd, (char *)frame, tam, 0, (struct sockaddr *)&param, sizeof(param) );
	printf("n=%d\n", n);

	return(0);
}
