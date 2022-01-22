#ifndef __UDP_H__
#define __UDP_H__

#include "cdef.h"
#include "common.h"

typedef void(*vFun)(uint8*, uint16);

typedef struct 
{
    uint16 u16Src;
    uint16 u16Dst;
    uint16 u16Len;
    uint16 u16Check;
}Udp_tstHdr;


typedef struct Udp_stPcb
{
    pcap_t *pSock;
    uint32 u32LocalIp;
    uint32 u32RemoteIp;
    uint8 u8TtL;
    uint8 u8IpProto;

    struct Udp_stPcb* next;
    uint16 u16LocalPort;
    uint16 u16RemotePort;

    vFun vRecvFun;
}Udp_tstPcb;

Udp_tstPcb* Udp_pstAllocPcb();
Udp_tstPcb* Udp_vNewUdp(uint16, uint16, uint8*, uint8*);
Udp_tstHdr* Udp_pstCreateHeader(Udp_tstPcb*, tstPbuf*, uint16);
void Udp_vInputSeg(tstPbuf*);
void Udp_vSend(Udp_tstPcb*, uint8*, uint16);

#endif