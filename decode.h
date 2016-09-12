//
//  decode.h
//  pcap_parse_packet
//
//  Created by 王宏志 on 16/8/26.
//  Copyright © 2016年 王宏志. All rights reserved.
//

#ifndef decode_h
#define decode_h

#include <stdio.h>
#include "struct.h"
#include "udp.h"
#include "tcp.h"

/**
 *  解析ip
 */
void decodeIp(const u_char *packet);
/**
 *  解析arp
 */
void decodeArp(const u_char *packet);

#endif /* decode_h */
