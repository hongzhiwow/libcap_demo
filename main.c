//
//  main.c
//  pcap_parse_packet
//
//  Created by 王宏志 on 16/8/26.
//  Copyright © 2016年 王宏志. All rights reserved.
//

#include <stdio.h>
#include "struct.h"
#include "decode.h"

#define printf(var,...) printf("")

/**
 *  抓包
 *
 */
void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet);



int main(int argc, const char * argv[]) {

    
    pcap_if_t *allDevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs(&allDevs, errbuf) == -1) {
        printf("Error:  %s", errbuf);
    }
    
#if 0 // This is for test
    for(pcap_if_t *dev=allDevs; dev; dev=dev->next)
    {
        NSLog(@"\n");
        NSLog(@"%s", dev->name);
        NSLog(@"-----------------------");
        char addr[INET6_ADDRSTRLEN];
        pcap_addr_t *adrs = dev->addresses;
        for(;adrs;adrs = adrs->next) {
            struct sockaddr *sa = adrs->addr;
            inet_ntop(sa->sa_family, &(((struct sockaddr_in *)sa)->sin_addr),
                      addr, sizeof(addr));
            NSLog(@"    %s", addr);
        }
    }
#endif
    
#define SNAPLEN 65535
#define PROMISC 1
#define TIMEOUT 500
    
    pcap_t *handle;
    bpf_u_int32 localNet, netMask;
    struct bpf_program filterCode;
    char filter[] = "arp or tcp or udp or icmp";
    
    
    char *dev = pcap_lookupdev(errbuf);
    if (dev==NULL) {
        printf("Error finding default device %s", errbuf);
        return -1;
    }
    handle = pcap_open_live(dev, SNAPLEN, PROMISC, TIMEOUT, errbuf);
    if (handle == NULL) {
        printf("Can not open device %s", errbuf);
        return -1;
    }
    
    if (pcap_lookupnet(dev, &localNet, &netMask, errbuf) == -1) {
        pcap_close(handle);
        printf("pcap_lookupnet failed");
        return -1;
    }
    
    //filter
    
    if (pcap_compile(handle, &filterCode, filter, 1, netMask) == -1) {
        pcap_close(handle);
        printf("pcap_compile failed");
        return -1;
    }
    if (pcap_setfilter(handle, &filterCode) == -1) {
        pcap_close(handle);
        printf("Can't install filter");
        return -1;
    }
    
    pcap_loop(handle, -1, got_packet,NULL);
    
    pcap_freecode(&filterCode);
    pcap_close(handle);
    
    return 0;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
    if (packet != NULL) {
        const struct pcap_ethernet *ethernet = (struct pcap_ethernet *)packet;
        
        switch (ntohs(ethernet->ether_type)) {
            case ETHERTYPE_IP:
                printf("IP:  %d \n", ethernet->ether_type);
                 decodeIp(packet);
                break;
            case ETHERTYPE_ARP:
                printf("ARP:  %d \n", ethernet->ether_type);
                 decodeArp(packet);
                break;
            default:
                break;
        }
    }
}




