/*
    Packet sniffer using libpcap library
*/
#include "pcap/pcap.h"
#include <stdio.h>
#include <stdlib.h> // for exit()
#include <string.h> //for memset
#include <sys/socket.h>
#include <stdint.h>
 
#include <sys/socket.h>
// #include <arpa/inet.h> // for inet_ntoa()
// #include <net/ethernet.h>
// #include <netinet/ip_icmp.h>   //Provides declarations for icmp header
// #include <netinet/udp.h>   //Provides declarations for udp header
// #include <netinet/tcp.h>   //Provides declarations for tcp header
// #include <netinet/ip.h>    //Provides declarations for ip header

#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define WHT   "\x1B[37m"
#define RESET "\x1B[0m"

#define UDP_SIZE_HEADER 8

typedef struct {
    uint16_t source;
    uint16_t destination;
    uint16_t lenght;
    uint16_t checksum; 
    char data[10];   
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

uint16_t swapping(uint16_t value){
    uint16_t byte1 = (value & 0xff00) >> 8;
    uint16_t byte2 = (value & 0x00ff) << 8;
    uint16_t result = byte1 + byte2;
    return result;
}

// uint8_t *swappingEthernet(uint8_t *value){
//     uint16_t *result = {value[5],value[4],value[3],value[2],value[1],value[0]};
//     return result;
// }

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
// void process_ip_packet(const u_char * , int);
// void print_ip_packet(const u_char * , int);
// void print_tcp_packet(const u_char *  , int );
// void print_udp_packet(const u_char * , int);
// void print_icmp_packet(const u_char * , int );
// void PrintData (const u_char * , int);
 
// FILE *logfile;
// struct sockaddr_in source, dest;
// int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j; 
 
int main(int argc, char **argv){

    char *devname = "any";
    pcap_t *handle;
    char errbuf[100];

    if(argc > 1){
        devname = argv[1];
    }
     
    printf("------------- Sniffing in device %s ... " , devname);
    handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
     
    if (handle == NULL) {
        printf(RED"Error\n"RESET);
        printf(RED"%s\n"RESET, errbuf);
        exit(1);
    }
    printf(GRN"OK\n"RESET);
     
    // logfile=fopen("log.txt","w");
    // if(logfile==NULL) 
    // {
    //     printf("Unable to create file.");
    // }
     
    //Put the device in sniff loop
    printf(CYN"------------- Start -------------\n"RESET);
    pcap_loop(handle , -1 , process_packet , NULL);
     
    return 0;   
}


 
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer){

    printf("Size Ethernet: %lu\n", sizeof(Ethernet));
    printf("Size IPv4: %lu\n", sizeof(IPv4));
    printf("Size UDP: %lu\n", sizeof(UDP));
    printf("-------------------------------\n");
    int size = header->len;
    for(int i =0; i < size; i++){
        printf("%02x ", buffer[i]);

    }

    Ethernet *eth;
    IPv4 *ipv4;
    UDP *udp;

    eth = (Ethernet*) buffer;

    /*Está pegando invertido*/
    if(swapping(eth->type) == 0x0800){

        printf("-------------------------------\n");
        printf("Ethernet Type: "GRN"0x%04X (IPv4)"RESET"\n", swapping(eth->type));
        // printf("Ethernet Source: "GRN"0x%012X (IPv4)"RESET"\n", swappingEthernet(eth->source));
        
        ipv4 = (IPv4*) (eth + 1);

        if(ipv4->protocol == 0x11){
            printf("IPv4 Protocol: "GRN"0x%x (UDP)"RESET"\n", ipv4->protocol);

            udp = (UDP*) (ipv4 + 1);

            int udp_size_data = swapping(udp->lenght) - UDP_SIZE_HEADER;
            
            printf("UDP Size data: "GRN"%u bytes"RESET"\n", udp_size_data);
            printf("Data: " GRN "%s" RESET "\n", udp->data);
        }else{
            printf("IPv4 Protocol: "RED"0x%02x (UDP)"RESET"\n", ipv4->protocol);
        }
    }
    
}
 
