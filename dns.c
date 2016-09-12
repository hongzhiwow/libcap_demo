//
//  dns.c
//  pcap_parse_packet
//
//  Created by 王宏志 on 16/8/26.
//  Copyright © 2016年 王宏志. All rights reserved.
//

#include "dns.h"


u_char* parse_dns_packet(u_char *dns_data)
{
    u_char domainname[100] = {0};
    u_int i = 0;
    dns_data ++;
    while (*dns_data)
    {
        if(*dns_data < 0x10)//48以后出现数字和英文字母
        {
            domainname[i] = '.';
        }
        else
        {
            domainname[i] = *dns_data;
        }
        dns_data ++;
        i ++;
    }
    return domainname;
}