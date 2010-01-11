#include <stdio.h>
#include <stdlib.h>

#include "pcapreader.h"
#include "structs.h"
#define SESSION_KEY_LENGTH  40

static uint8_t SESSIONKEY[SESSION_KEY_LENGTH];

void readSessionkey(const char* file)
{
    FILE *fp = fopen(file, "r");
    if(!fp)
    {
        printf("Couldn't open keyfile %s\n", file);
        exit(1);
    }
    const int expectedBytes = sizeof(SESSIONKEY);
    int readCount = fread(SESSIONKEY, 1, expectedBytes, fp);
    if(readCount != expectedBytes)
    {
        printf("Couldn't read %u bytes from keyfile %s\n", expectedBytes, file);
        exit(1);
    }
    fclose(fp);
}

const char* addrToStr(int addr)
{
    static char buffer[3+1+3+1+3+1+3];
    sprintf(buffer, "%d.%d.%d.%d", 0xFF&(addr>>3*8), 0xFF&(addr>>2*8), 0xFF&(addr>>8), 0xFF&(addr));
    return buffer;
}

static struct tcp_connection **connections = NULL;
static uint32_t connection_count = 0;
void handleTcpPacket(uint32_t from, uint32_t to, struct sniff_tcp_t *tcppacket)
{
    struct tcp_connection *connection = NULL;
    for(uint8_t i=0; i< connection_count; ++i)
    {
        if((connections[i]->from == from && connections[i]->to == to &&
                    connections[i]->src_port == tcppacket->th_sport && connections[i]->dst_port == tcppacket->th_dport)
            ||
            (connections[i]->from == to && connections[i]->to == from &&
             connections[i]->src_port == tcppacket->th_dport && connections[i]->dst_port == tcppacket->th_sport))
        {
            connection = connections[i];
            break;
        }
    }
    // not found, create new?
    if(connection==NULL)
    {
        if(tcppacket->th_flags == TH_SYN)
        {
            connection = malloc(sizeof(struct tcp_connection));
            connection_count++;
            connections = realloc(connections, sizeof(struct tcp_connection*)*connection_count);
            connections[connection_count-1] = connection;

            connection->from = from;
            connection->to = to;
            connection->src_port= tcppacket->th_sport;
            connection->dst_port= tcppacket->th_dport;
            connection->state = SYNED;

            printf("New connection, now tracking %u\n", connection_count);
        }
        else
        {
            printf("got non-initial tcppacket and couldn't find any associated connection - ignored\n");
        }
        return;
    }
    switch(connection->state)
    {
        case SYNED:
            break;
        case SYNACKED:
            break;
        case ESTABLISHED:
            break;
        case ACTIVE:
            break;
    }
}

void parsePcapFile(const char* filename)
{
    FILE *fd = fopen(filename, "r");
    if(!fd)
    {
        printf("Couldn't open pcap file %s\n", filename);
        exit(1);
    }
    struct pcap_hdr_t *header = readPcapHeader(fd);
    if(!header)
        exit(1);

    if(header->network != DLT_EN10MB)
    {
        printf("network link layer %u is not supported, currently only ethernet is implemented\n", header->network);
        exit(1);
    }

    struct pcaprec_hdr_t packet;
    uint8_t *data;
    while(readNextPacket(fd, &packet, &data))
    {
        struct sniff_ethernet_t *etherframe = (struct sniff_ethernet_t*)data;
        if(etherframe->ether_type == ETHER_TYPE_IP)
        {
            struct sniff_ip_t *ipframe = (struct sniff_ip_t*)(data+sizeof(struct sniff_ethernet_t));
            if(IP_V(ipframe)!=4)
            {
                printf("skipped ip v%u frame\n", IP_V(ipframe));
            }
            else
            {
                printf("ip packet len=%u from %s", ntohs(ipframe->ip_len), addrToStr(ntohl(ipframe->ip_src.s_addr)));
                printf(" to %s\n", addrToStr(ntohl(ipframe->ip_dst.s_addr)));
                uint32_t size_ip = IP_HL(ipframe)*4;
                if(size_ip<20)
                {
                    printf("size_ip is %u, <20\n", size_ip);
                }
                else if(ipframe->ip_p != TRANSPORT_TYPE_TCP)
                {
                    printf("skipping non-tcp frame\n");
                }
                else
                {
                    struct sniff_tcp_t *tcppacket = (struct sniff_tcp_t*)(data+sizeof(struct sniff_ethernet_t)+size_ip);
                    printf("th_sport: %u\n", ntohs(tcppacket->th_sport));
                    printf("th_dport: %u\n", ntohs(tcppacket->th_dport));
                    handleTcpPacket(ipframe->ip_src.s_addr, ipframe->ip_dst.s_addr, tcppacket);
                }
            }
///            exit(0);
        }
        free(data);
    }

    free(header);
}

int main(int argc, char *argv[])
{
    if(argc != 3)
    {
        printf("Usage: %s $dumpfile.cap $keyfile.txt\n", argv[0]);
        return 1;
    }
    
    readSessionkey(argv[2]);
    parsePcapFile(argv[1]);
    return 0;
}