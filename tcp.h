//
//  tcp.h
//  pcap_parse_packet
//
//  Created by 王宏志 on 16/8/26.
//  Copyright © 2016年 王宏志. All rights reserved.
//

#ifndef tcp_h
#define tcp_h

#include <stdio.h>
#include "struct.h"
#include "dns.h"

void decodeTcp(const u_char *packet);
void print_tcp_dns_packet(const u_char *packet,struct pcap_ip *ip,struct pcap_tcp *tcp);


#endif /* tcp_h */
