//
//  udp.c
//  pcap_parse_packet
//
//  Created by 王宏志 on 16/8/26.
//  Copyright © 2016年 王宏志. All rights reserved.
//

#include "udp.h"

void print_udp_dns_packet(const u_char *packet,struct pcap_ip *ip,struct pcap_udp *udp);
int sizeofUrl(char data[]);

void decodeUdp(const u_char *packet)
{
    struct pcap_ip *ip = (struct pcap_ip *)(packet + ETHERNET_SIZE);
    int offset = GET_IP_HEADER_LENGTH(ip)*4;
    struct pcap_udp *udp = (struct pcap_udp *)(packet + ETHERNET_SIZE + offset);
    
    int from = ntohs(udp->udp_sport);
    int to = ntohs(udp->udp_dport);
    if (from == 53 || to == 53)
    {
//        printf("UDP packet from %s:%d -> to %s:%d \n",inet_ntoa(ip->ip_src), from,inet_ntoa(ip->ip_dst), to);
        print_udp_dns_packet(packet, ip, udp);
    }
}


void print_udp_dns_packet(const u_char *packet,struct pcap_ip *ip,struct pcap_udp *udp)
{
    struct pcap_dns *dns;
    struct pacp_static_RR *RR;
    u_char *query;
    dns = (struct pcap_dns *)(packet + sizeof(struct pcap_ethernet) + sizeof(struct pcap_ip) + sizeof(struct pcap_udp));

    
    query = (u_char *)&(dns->dns_data);
    u_short qr = dns->dns_flag >> 15;
    if (qr == 0)
    {
        //查询
    }
    else  if (qr == 1)
    {
        //响应
        RR = (struct pacp_static_RR *)((&dns->dns_data) + sizeofUrl((char *)&(dns->dns_data)));
    //    int type = ntohs(RR->type);
    //    int clas = ntohs(RR->clas);
    //    int ttl = (uint32_t)ntohl(RR->ttl);
        int rdlength = ntohs(RR->rdlength);
        
        uint8_t* rd = (void*)(&RR->rdlength + sizeof(uint16_t));
        
        if( rdlength != 0 ){
//            printf("data:");
//            printf("%d.%d.%d.%d",rd[0], rd[1], rd[2], rd[3]  );
//            printf("\n");
        }

        void *pf = (void *)&dns->dns_data;
        char *ptr = (char *)&(dns->dns_data);
//        while (*ptr !='\0') {
//            printf("%c ",*ptr);
//            ptr ++;
//        }
//        pf = ptr + 1;
//        printf("\n");
//        char *newps = (char *)pf;
        char a[1024];
    
//        printf("size:%lu,%lu,%lu \n",sizeof(struct pcap_ethernet),sizeof(struct pcap_ip),sizeof(struct pcap_udp));
        printf("udp_dns_query:%s \n",parse_dns_packet(query));
        for (int i = 0; i < 1000; i ++) {
            a[i] = *ptr;
            ptr ++;
        }
    }
    else
    {
        printf("---------------------\n");
    }
    
}

int sizeofUrl(char data[])
{
    int i = 0;
    int toskip = data[0];
    
    // skip each set of chars until (0) at the end
    while(toskip!=0){
        i += toskip+1;
        toskip = data[i];
    }
    
    // return the length of the array including the (0) at the end
    return i+1;
}
