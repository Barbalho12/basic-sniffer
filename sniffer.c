#include "pcap/pcap.h"
#include <stdlib.h> 
#include <string.h> 
#include <time.h>

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
    char *data;   
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
    uint8_t destination[6];
    uint8_t source[6];
    uint16_t type;
}Ethernet;

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void print_ethernet_address(uint8_t *eth_add);
void print_ipv4_address(uint32_t ip_add);
void printTime ();
uint16_t swapping(uint16_t value);
void show_buffer(const u_char *buffer, int size);
 
int main(int argc, char **argv){

    char *devname = "lo";
    pcap_t *handle;
    char errbuf[100];

    if(argc > 1){
        devname = argv[1];
    }
     
    printf("---------------------------------\n");
    printf(" Sniffing in device %s ... " , devname);
    handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
     
    if (handle == NULL) {
        printf(RED"Error\n"RESET);
        printf(RED"%s\n"RESET, errbuf);
        exit(1);
    }
    printf(GRN"OK\n"RESET);
     
    //Put the device in sniff loop
    printf(CYN"------------- Start -------------\n"RESET);
    pcap_loop(handle , -1 , process_packet , NULL);
     
    return 0;   
}
 
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer){

    Ethernet *eth;
    IPv4 *ipv4;
    UDP *udp;

    eth = (Ethernet*) buffer;

    if(swapping(eth->type) == 0x0800){
        
        ipv4 = (IPv4*) (eth + 1);

        if(ipv4->protocol == 0x11){        

            udp = (UDP*) (ipv4 + 1);

            int udp_size_data = swapping(udp->lenght) - UDP_SIZE_HEADER;

            uint16_t udp_destination = swapping(udp->destination);

            if(udp_destination == 1234){

                char *data = (char*) &(udp->data);

                // show_buffer(buffer, header->len);

                printTime();
                // printf("Ethernet Type: "GRN"0x%04X (IPv4)"RESET"\n", swapping(eth->type));
                printf("Ethernet Source: ");
                print_ethernet_address(eth->source);
                printf("Ethernet Destination: ");
                print_ethernet_address(eth->destination);
                printf("IPv4 Source: ");
                print_ipv4_address(ipv4->source);
                printf("IPv4 Destination: ");
                print_ipv4_address(ipv4->destination);
                printf("IPv4 Protocol: "GRN"0x%x (UDP)"RESET"\n", ipv4->protocol);
                printf("UDP Source: "GRN"%u"RESET"\n", swapping(udp->source));
                printf("UDP Destination: "GRN"%u"RESET"\n", swapping(udp->destination));
                printf("UDP Size data: "GRN"%u bytes"RESET"\n", udp_size_data);
                printf("Menssage Type: "BLU"%02x\n"RESET, data[0]);
                printf("Menssage Enrollment: "BLU);
                for(int i = 0; i < 8; i++){
                    printf("%c", data[1+i]);
                    if(i==7) printf("\n"RESET);
                }

                if(data[0] == 1){
                    uint16_t nome_length = (((uint16_t) data[9])<<8) + (uint8_t) data[10];
                    printf("Menssage Name Lenght: "BLU"%u\n"RESET, nome_length);
                    printf("Menssage Name: "BLU);
                    for(int i = 0; i < nome_length; i++){
                        printf("%c", data[11+i]);
                        if(i==nome_length-1) printf("\n"RESET);
                    }
                }
                printf("---------------------------------\n");
            }
        }
    }
}
 
void show_buffer(const u_char *buffer, int size){
    printf("\n-------------------------\n");
    for(int i = 0; i < size; i++){
        printf("%02x ", buffer[i]);
    }
    printf("\n-------------------------\n");
}

// void print_ethernet_address(uint8_t *eth_add){
//     printf(GRN);
//     for(int i =5; i >=0; i--){
//         printf("%02x", eth_add[i]);
//         if(i!=0) printf(":");
//     }
//     printf(RESET"\n");
// }

void print_ethernet_address(uint8_t *eth_add){
    printf(GRN);
    for(int i = 0; i < 6; i++){
        printf("%02x", eth_add[i]);
        if(i!=5) printf(":");
    }
    printf(RESET"\n");
}

void print_ipv4_address(uint32_t ip_add){
    uint8_t ip_adrs_0 =  (ip_add & 0x000000ff);
    uint8_t ip_adrs_1 =  (ip_add & 0x0000ff00) >> 8;
    uint8_t ip_adrs_2 =  (ip_add & 0x00ff0000) >> 16;
    uint8_t ip_adrs_3 =  (ip_add & 0xff000000) >> 24;
    printf(GRN);
    printf("%d.%d.%d.%d", ip_adrs_0, ip_adrs_1, ip_adrs_2, ip_adrs_3 );
    printf(RESET"\n");
}

void printTime () {
    char buff[100];
    time_t now = time (0);
    strftime (buff, 100, "%H:%M:%S.000", localtime (&now));
    printf ("Time: "YEL"%s\n"RESET, buff);
}

uint16_t swapping(uint16_t value){
    uint16_t byte1 = (value & 0xff00) >> 8;
    uint16_t byte2 = (value & 0x00ff) << 8;
    uint16_t result = byte1 + byte2;
    return result;
}
