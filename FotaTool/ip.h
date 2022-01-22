#ifndef __IP_H__
#define __IP_H__

#include "cdef.h"
#include "tcp.h"
#include "udp.h"


#define   IP_HLEN     20

typedef struct ip_header {
    uint8 u8Ihl : 4,
    u8Version : 4;
    uint8  u8Tos;
    uint16 u16TotLen;
    uint16 u16Id;
    uint16 u16FragOffset;
    uint8  u8Ttl;
    uint8  u8Protocol;
    uint16 u8Check;
    uint32 u32SrcAddr;
    uint32 u32DstAddr;
    //uint32 u32Pad;        
}Ip_tstHdr;

typedef struct Ip_stPcb
{
    pcap_t *pSock;
    uint32 u32LocalIp;
    uint32 u32RemoteIp;
    uint8 u8TtL;
    uint8 u8IpProto;
}Ip_tstPcb;

Ip_tstHdr *Ip_pstCreateHeader(uint8*, tstPbuf*);
void Ip_vOutputPkg(uint8*, tstPbuf*);
void Ip_vInputPkg(tstPbuf*);
#endif