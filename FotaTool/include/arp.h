#ifndef __ARP_H__
#define __ARP_H__

#include "cdef.h"
#define ETH_ALEN 0x06


#pragma pack(push,1)
typedef struct
{
    uint16    u16ArpHrd;           
    uint16    u16ArpPro;           
    uint8     u8ArpHln;
    uint8     u8ArpPln;           
    uint16    u16ArpOpt;  
    uint8     u8ArpSha[ETH_ALEN];//alignment
    uint32    u32ArpSpa;
    uint8     u8ArpTha[ETH_ALEN];//alignment
    uint32    u32ArpTpa;           
}Arp_tstHdr;
#pragma pack(pop)

void Arp_vReply();

#endif

