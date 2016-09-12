//
//  udp.h
//  pcap_parse_packet
//
//  Created by 王宏志 on 16/8/26.
//  Copyright © 2016年 王宏志. All rights reserved.
//

#ifndef udp_h
#define udp_h

#include <stdio.h>
#include "struct.h"
#include "dns.h"


void decodeUdp(const u_char *packet) ;
void print_udp_dns_packet(const u_char *packet,struct pcap_ip *ip,struct pcap_udp *udp);

#endif /* udp_h */
