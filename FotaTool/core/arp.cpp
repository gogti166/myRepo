#include "arp.h"
#include "ethernet.h"

/* Temporary code for debug */
void Arp_vReply()
{
    Arp_tstHdr *pstArpHdr = (Arp_tstHdr*)malloc(sizeof(Arp_tstHdr));
    memset(pstArpHdr, 0x00, sizeof(Arp_tstHdr));
    pstArpHdr->u16ArpHrd = htons(0x0001);
    pstArpHdr->u16ArpPro = htons(0x0800);
    pstArpHdr->u8ArpHln = 0x06;
    pstArpHdr->u8ArpPln = 0x04;
    pstArpHdr->u16ArpOpt = htons(0x0002);


    /*uint8 au8DstMac[ETH_ALEN] = { 0x00, 0xad, 0x24, 0x3e, 0x3b, 0x66 };
    uint8 au8SrcMac[ETH_ALEN] = { 0x10, 0x62, 0xe5, 0xf2, 0x27, 0xb5 };*/

    uint8 au8DstMac[ETH_ALEN] = { 0xF4, 0x6D, 0x04, 0xFA, 0x13, 0xD4 };
    uint8 au8SrcMac[ETH_ALEN] = { 0xE4, 0xE7, 0x49, 0xBB, 0xD4, 0x0C };
    memcpy(pstArpHdr->u8ArpSha, au8SrcMac, ETH_ALEN);
    memcpy(pstArpHdr->u8ArpTha, au8DstMac, ETH_ALEN);

    /*pstArpHdr->u32ArpSpa = u32Ipv4ToInt("10.0.2.0");
    pstArpHdr->u32ArpTpa = u32Ipv4ToInt("10.0.0.128");*/

    pstArpHdr->u32ArpSpa = u32Ipv4ToInt("192.168.10.6");
    pstArpHdr->u32ArpTpa = u32Ipv4ToInt("192.168.10.3");

    Eth_tstHdr* pstEthHeader = (Eth_tstHdr*)malloc(u8EthHdrLen);
    memset(pstEthHeader, 0x00, u8EthHdrLen);
    memcpy(pstEthHeader->u8DstMac, au8DstMac, ETH_ALEN);
    memcpy(pstEthHeader->u8SrcMac, au8SrcMac, ETH_ALEN);
    pstEthHeader->u16Type = htons(0x0806);

    uint32 u32SendBufLen = sizeof(Arp_tstHdr) + u8EthHdrLen;
    uint8 *u8SendBuf = (uint8*)malloc(sizeof(Arp_tstHdr) + u8EthHdrLen);
    memcpy(u8SendBuf, pstEthHeader, u8EthHdrLen);
    memcpy(u8SendBuf + u8EthHdrLen, pstArpHdr, sizeof(Arp_tstHdr));    
    free(pstArpHdr);
    free(pstEthHeader);

    Pcap_vSend(pSock, u8SendBuf, u32SendBufLen);
    free(u8SendBuf);
}
