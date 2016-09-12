//
//  struct.h
//  pcap_parse_packet
//
//  Created by 王宏志 on 16/8/26.
//  Copyright © 2016年 王宏志. All rights reserved.
//

#ifndef struct_h
#define struct_h

#include <arpa/inet.h>
#include <pcap.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

#define ETHERNET_SIZE 14
#define ETHERNET_ADDRESS_LENGTH 6
/* Ethernet header */
#pragma pack(push,1)
struct pcap_ethernet {
    u_char  ether_dhost[ETHERNET_ADDRESS_LENGTH];    /* destination host address */
    u_char  ether_shost[ETHERNET_ADDRESS_LENGTH];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};
#pragma pack(pop)


#define ETHERTYPE_IP      0x0800
#define ETHERTYPE_ARP     0x0806

#pragma pack(push,1)
struct pcap_ip {
    u_int8_t  ip_vhl;          // header length and version
    u_int8_t  ip_tos;          // type of service
    u_int16_t ip_len;          // total length
    u_int16_t ip_id;           // identification
    u_int16_t ip_off;          // fragment offset
#define IP_RF 0x8000           // reserved fragment flag
#define IP_DF 0x4000           // don't fragment flag
#define IP_MF 0x2000           // more fragments flag
#define IP_OFFMASK 0x1fff      // mask for fragmenting bits
    u_int8_t  ip_ttl;          // time to live
    u_int8_t  ip_p;            // protocol
    u_int16_t ip_sum;          // checksum
    struct  in_addr ip_src, ip_dst;  // source and dest address
};
#pragma pack(pop)


#define GET_IP_VERSION(ip)    (((ip)->ip_vhl & 0xf0) >> 4)  //get version
#define GET_IP_HEADER_LENGTH(ip)   ((ip)->ip_vhl & 0x0f)    //get header length

#pragma pack(push,1)
struct pcap_tcp {
    u_short tcp_sport;          // source port
    u_short tcp_dport;          // destination port
    u_int   tcp_seq;            // sequence number
    u_int   tcp_ack;            // acknowledgement number
    u_int tcp_x2:4,             // (unused)
tcp_off:4;            // offset
    u_char  tcp_flags;
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PUSH 0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20
#define TCP_ECE  0x40
#define TCP_CWR  0x80
#define TCP_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short tcp_win;           // window
    u_short tcp_sum;           // checksum
    u_short tcp_urp;           // urgent pointer
};
#pragma pack(pop)


#pragma pack(push,1)
struct pcap_udp {
    unsigned short int udp_sport;   // source port
    unsigned short int udp_dport;   // destination port
    unsigned short int udp_len;     // length
    unsigned short int udp_sum;   //checksum
};
#pragma pack(pop)


#define ARP_REQUEST 1   // ARP Request
#define ARP_REPLY 2     // ARP Reply

#pragma pack(push,1)
struct pcap_arp {
    u_int16_t arp_htype;    // Hardware Type
    u_int16_t arp_ptype;    // Protocol Type
    u_char    arp_hlen;        // Hardware Address Length
    u_char    arp_plen;        // Protocol Address Length
    u_int16_t arp_type;     // ARP type
    u_char    arp_sha[6];      // source hardware address
    u_char    arp_spa[4];      // source IP address
    u_char    arp_dha[6];      // destination hardware address
    u_char    arp_dpa[4];      // destination IP address
};
#pragma pack(pop)


#define ICMP_ECHO_REPLY_TYPE 0
#define ICMP_ECHO_REQUEST_TYPE 8
#define ICMP_REDIRECT_TYPE 5
#define ICMP_DESTINATION_UNREACHABLE_TYPE 3
#define ICMP_TRACEROUTE_TYPE 30
#define ICMP_TIME_EXCEEDED_TYPE 11

#pragma pack(push,1)
struct pcap_icmp {
    u_char icmp_type;  // ICMP Type
    u_char icmp_code;  // ICMP Code
    u_short icmp_sum;     // ICMP Checksum
    u_short icmp_id;  // ID
    u_short icmp_seq;  // Sequence #
};
#pragma pack(pop)


#pragma pack(push,1)
struct pcap_dns
{
    u_short dns_id;
    u_short dns_flag;
    u_short dns_ques;
    u_short dns_ans;
    u_short dns_auth;
    u_short dns_add;
    
    u_int8_t *dns_data;    
};
#pragma pack(pop)

#pragma pack(push,1)
struct pacp_static_RR
{
    uint16_t type;
    uint16_t clas;
    uint32_t ttl;
    uint16_t rdlength;
} ;
#pragma pack(pop)


#endif /* struct_h */
