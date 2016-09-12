//
//  tcp.c
//  pcap_parse_packet
//
//  Created by 王宏志 on 16/8/26.
//  Copyright © 2016年 王宏志. All rights reserved.
//

#include "tcp.h"


void decodeTcp(const u_char *packet)
{
    struct pcap_ip *ip = (struct pcap_ip *)(packet + ETHERNET_SIZE);
    int offset = GET_IP_HEADER_LENGTH(ip)*4;
    struct pcap_tcp *tcp = (struct pcap_tcp *)(packet + ETHERNET_SIZE + offset);
    
    int from = ntohs(tcp->tcp_sport);
    int to = ntohs(tcp->tcp_dport);
    
    if (from == 53 || to == 53)
    {
        //        printf("UDP packet from %s:%d -> to %s:%d \n",inet_ntoa(ip->ip_src), from,inet_ntoa(ip->ip_dst), to);
        print_tcp_dns_packet(packet, ip, tcp);
    }

}


void print_tcp_dns_packet(const u_char *packet,struct pcap_ip *ip,struct pcap_tcp *tcp)
{
//    struct pcap_dns *dns;
//    u_char *query;
//    dns = (struct pcap_dns *)(packet + sizeof(struct pcap_ethernet) + sizeof(struct pcap_ip) + sizeof(struct pcap_tcp));
//    
//    query = (u_char *)&(dns->dns_data);
//    u_short qr = dns->dns_flag >> 15;
//    if (qr == 0)
//    {
//        printf("*********************\n");
//    }
//    else  if (qr == 1)
//    {
//        printf("tcp_dns_query:%s \n",parse_dns_packet(query));
//    }
//    else
//    {
//        printf("---------------------\n");
//    }

}
