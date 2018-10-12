#include <stdio.h>
#include <sys/socket.h>
#include <stdint.h>
#include <string.h>


#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define WHT   "\x1B[37m"
#define RESET "\x1B[0m"

#define UDP_SIZE_HEADER 8

#define IPV4_ETHERNET_TYPE_CODE 0x0800
#define UDP_PROTOCOL_CODE 0x11

typedef struct {
    uint16_t source;
    uint16_t destination;
    uint16_t lenght;
    uint16_t checksum; 
    char data [1000];   
}UDP;

typedef struct {
    uint8_t version_header_lenght;
    uint8_t differentiated_dervices;
    uint16_t total_lenght;
    uint16_t identification;
    uint16_t flags; //flags de fragmentos
    uint8_t time_to_live;
    uint8_t protocol;
    uint16_t header_checksum;
    uint32_t source;
    uint32_t destination;
}IPv4;


typedef struct {
    uint8_t destinadion[6];
    uint8_t source[6];
    uint16_t type;
}Ethernet;


uint8_t buffer[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x08, 0x00, 0x45, 0x00, 0x00, 0x22, 0x6c, 0xcd, 0x40, 0x00, 0x40, 0x11, 0xcf, 0xfb, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x84, 0x5c, 0x0b, 0xb8, 0x00, 0x0e, 0xfe, 0x21, 0x74, 0x65, 0x73, 0x74, 0x65, 0x0a};


uint16_t swapping(uint16_t value){
	uint16_t byte1 = (value & 0xff00) >> 8;
	uint16_t byte2 = (value & 0x00ff) << 8;
	uint16_t result = byte1 + byte2;
	return result;
}

int main(){

	printf("Size Ethernet: %lu\n", sizeof(Ethernet));
	printf("Size IPv4: %lu\n", sizeof(IPv4));
	printf("Size UDP: %lu\n", sizeof(UDP));
	printf("-------------------------------\n");

	Ethernet *eth;
	IPv4 *ipv4;
	UDP *udp;

	eth = (Ethernet*) buffer;

	/*Está pegando invertido*/
	if(swapping(eth->type) == IPV4_ETHERNET_TYPE_CODE){

		printf("Ethernet Type: "GRN"%04X (IPv4)"RESET"\n", swapping(eth->type));
		
		ipv4 = (IPv4*) (eth + 1);

		if(ipv4->protocol == UDP_PROTOCOL_CODE){
			
			printf("IPv4 Protocol: "GRN"%x (UDP)"RESET"\n", ipv4->protocol);

			udp = (UDP*) (ipv4 + 1);

			int size_udp_payload = swapping(udp->lenght) - UDP_SIZE_HEADER;

			
			printf("UDP Size data: "GRN"%d bytes"RESET"\n", size_udp_payload);

			printf("Data: " GRN "%s" RESET "\n", udp->data);
		}
	}
}