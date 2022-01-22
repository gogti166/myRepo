#ifndef __ETHERNET_H__
#define __ETHERNET_H__

#include "cdef.h"
#include "tcp.h"

#define ETHNET_HLEN       14

/* Multicast OUI 01-00-5e */
#define   MULTICAST_MAC_ADDR0  0x01
#define   MULTICAST_MAC_ADDR1  0x00
#define   MULTICAST_MAC_ADDR2  0x5e

#define ETH_ALEN          0x06
typedef struct
{
    uint8 u8DstMac[ETH_ALEN];
    uint8 u8SrcMac[ETH_ALEN];
    uint16 u16Type;
}Eth_tstHdr;

Eth_tstHdr* Eth_pstCreateHeader(uint8*, tstPbuf*);
void Eth_vInputFrm(tstPbuf*);
void Eth_vOutputFrm(uint8*, tstPbuf*);

#endif