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
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <linux/ip.h>
#include <linux/udp.h>

char *device;
int mens_type;
int port;
char *mens_name;
uint16_t name_length;
uint8_t ip_src[4];
uint8_t ip_address[4];
uint8_t mac_address[6]; 
char *mens_matr;


int init(int argc, char **argv){ 

	printf("----------------\n");
	device = argv[1];
	printf("Device: %s\n", device);

	char *mac_s = argv[2];
	printf("MAC Address: %s\n", mac_s);

	char *ip = argv[3];
	printf("IP: %s\n", ip);
	port = atoi(argv[4]);
	printf("Port: %d\n", port);

	mens_type = 2;
	if(argc > 6){
		mens_type = 1;
	}
	printf("Mens Type: %d\n", mens_type);

	mens_matr = argv[5];
	printf("Mens Matr: %s\n", mens_matr);

	//GET NAME AND LENGHT NAME
	name_length = 0;
	if(mens_type == 1){
		mens_name = argv[6];
		name_length = 0;
		for( ; mens_name[name_length] != '\0'; ++name_length);
		printf("Name Lenght: %d\n", name_length);
		printf("Mens Name: %s\n", mens_name);
	}
	printf("----------------\n");

	
	//GET IP
	int i = 0;
	uint8_t temp = 0;
	int index = 0;
	int count_decimal = 1;
	while(ip[i] != 0x00 ){
		if(ip[i] != '.'){
			temp =  (temp * count_decimal) + (ip[i] - 48);
			count_decimal = 10;
		}else{
			ip_address[index] = temp;
			index++;
			temp = 0;
			count_decimal = 1;
		}
		i++;
	}
	ip_address[3] = temp;


	//GET MAC
	i = 0;
	char temp_ [2];
	index = 0;
	int count_hex = 0;
	while(mac_s[i] != 0x00 ){
		if(mac_s[i] != ':'){
			temp_[count_hex] =  mac_s[i] ;
			count_hex = 1;
		}else{
			mac_address[index] = (uint8_t) strtol(temp_, NULL, 16);
			index++;
			temp_[0] = 0;
			temp_[1] = 0;
			count_hex = 0;
		}
		i++;
	}
	mac_address[5] = (uint8_t) strtol(temp_, NULL, 16);

}

int main(int argc, char **argv){

	init(argc, argv);

	int sockfd;
	struct sockaddr_ll param;
	int n, ifindex;
	uint8_t frame[65579]; //sizeof(struct arphdr)
	struct ifreq ifr;
	int tam=0;
	struct iphdr *iph;
	struct udphdr *uh;
	uint8_t *p;

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

	strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);
	ioctl(sockfd, SIOCGIFADDR, &ifr);

	char *ip_interface = inet_ntoa(((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr);
	// printf("%u\n", strlen(ip_interface));

	// printf("%s\n", inet_ntoa(((struct sockaddr_in *) &ifr.ifr_addr)->sin_addr));

	int counter = 0;
	int order = 1;
	uint8_t temp = 0;
	for(int i = 0; i < strlen(ip_interface); i++){
		if(ip_interface[i] != '.'){
			temp = (temp * order) + ip_interface[i] - 48;
			order = 10;
		}else{
			ip_src[counter] = temp;
			counter++;
			temp = 0;
			order = 1;
		}
	}

	ip_src[3] = temp;

	param.sll_family = PF_PACKET;   /* Always AF_PACKET */
	param.sll_protocol = htons(ETH_P_IP); /* Physical layer protocol */
	param.sll_ifindex = ifindex;  /* Interface number */
	param.sll_hatype = 0;   /* Header type */
	param.sll_pkttype = 0;  /* Packet type */
	param.sll_halen = 6;    /* Length of address */

	memcpy(param.sll_addr, mac_address, 6);  /* Physical layer address(8) */

	int TAMANHO_DA_MENS = 1 + 8 + 2 + name_length;

	iph = (struct iphdr *) frame;
	iph->ihl = 0x5;
	iph->version = 0x4;
	iph->tos = 0;
	iph->tot_len = htons(20+8+TAMANHO_DA_MENS);
	iph->id = 0;
	iph->frag_off = 0;
	iph->ttl = 0x40;
	iph->protocol = 0x11; // 17 em Decimal
	iph->check = 0x0;   //10.1.1.1
	memcpy(&iph->saddr, ip_src, 4); //127.1.1.1 - Pode forcar o Ip de origem
	memcpy(&iph->daddr, ip_address, 4); //127.0.0.1

	uh = (struct udphdr *)((uint8_t *)iph + 20);
	uh->source = htons(5000);
	uh->dest = htons(port);
	uh->len = htons(8+TAMANHO_DA_MENS);
	uh->check = 0x0;
	p = (uint8_t *)uh + 8;
	char mens[TAMANHO_DA_MENS];
	mens[0] = mens_type;
	memcpy(&mens[1], mens_matr, 8);
	mens[9] = (name_length >> 8);
	mens[10] = (name_length & 0x00ff);
	memcpy(&mens[11], mens_name, name_length);
	memcpy(p, mens, TAMANHO_DA_MENS);
	tam = 20 + 8 + TAMANHO_DA_MENS;
	n = sendto(sockfd, (char *)frame, tam, 0, (struct sockaddr *)&param, sizeof(param) );
	printf("n=%d\n", n);

	return(0);
}
