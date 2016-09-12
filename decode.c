//
//  decode.c
//  pcap_parse_packet
//
//  Created by 王宏志 on 16/8/26.
//  Copyright © 2016年 王宏志. All rights reserved.
//

#include "decode.h"

#define printf(var,...) printf("")

void decodeArp(const u_char *packet)
{
    const struct pcap_arp *arp = (struct pcap_arp *)(packet + ETHERNET_SIZE);
    switch (ntohs(arp->arp_type)) {
        case ARP_REQUEST:
            printf("ARP Request \n");
            printf("From:  %d.%d.%d.%d\n",arp->arp_spa[0],arp->arp_spa[1],arp->arp_spa[2],arp->arp_spa[3]);
            printf("To:    %d.%d.%d.%d\n",arp->arp_dpa[0],arp->arp_dpa[1],arp->arp_dpa[2],arp->arp_dpa[3]);
            break;
            
        case ARP_REPLY:
            printf("ARP Response\n");
            printf("From:  %02X:%02X:%02X:%02X:%02X:%02X\n",arp->arp_sha[0],arp->arp_sha[1],arp->arp_sha[2],arp->arp_sha[3],arp->arp_sha[4],arp->arp_sha[5]);
            printf("To:    %d.%d.%d.%d\n",arp->arp_dpa[0],arp->arp_dpa[1],arp->arp_dpa[2],arp->arp_dpa[3]);
            break;
            
        default:
            printf("ARP Type:  %d\n",arp->arp_type);
            break;
    }
}

void decodeIp(const u_char *packet)
{
    const struct pcap_ip *ip ;
    uint version ;
    char *from ;
    char *to;
    
    ip = (struct pcap_ip *)(packet + ETHERNET_SIZE);
    version = GET_IP_VERSION(ip);
    
    from = inet_ntoa(ip->ip_src);
    
    to = inet_ntoa(ip->ip_dst);
    switch (ip->ip_p) {
        case IPPROTO_TCP:
            printf("Found TCP packet from: %s  to:  %s\n",from,to);
            decodeTcp(packet);
            break;
        case IPPROTO_UDP:
            printf("Found UDP packet from: %s  to:  %s\n",from,to);
            decodeUdp(packet);
            break;
        case IPPROTO_ICMP:
            printf("Found ICMP packet from: %s  to:  %s\n",from,to);
            break;
        default:
            printf("Found Unknown packet from: %s  to:  %s\n",from,to);
            break;
    }
}
