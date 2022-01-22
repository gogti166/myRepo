#include "ethernet.h"
#include "arp.h"
#include "ip.h"

/* Specific code for fota, ARP enqury is not necessary here. */
Eth_tstHdr* Eth_pstCreateHeader(uint8* u8Pcb, tstPbuf *pstPbuf)
{
    Ip_tstPcb *pstPcb = (Ip_tstPcb*)u8Pcb;
    pstPbuf->u8Payload = pstPbuf->u8Payload - u8EthHdrLen;
    pstPbuf->u16Len = pstPbuf->u16Len + u8EthHdrLen;
    Eth_tstHdr* pstEthHdr = (Eth_tstHdr*)(pstPbuf->u8Payload);
    vMacToInt(LOCAL_MAC, pstEthHdr->u8SrcMac);
    /* If multicast ip */
    uint32 u32DstIp = htonl(pstPcb->u32RemoteIp);
    //printf("MAC:%08X\n", u32DstIp);
    if ((u32DstIp & 0xf0000000) == 0xe0000000)
    {
        pstEthHdr->u8DstMac[0] = MULTICAST_MAC_ADDR0;
        pstEthHdr->u8DstMac[1] = MULTICAST_MAC_ADDR1;
        pstEthHdr->u8DstMac[2] = MULTICAST_MAC_ADDR2;
        pstEthHdr->u8DstMac[3] = (u32DstIp >> 16) & 0x7f;
        pstEthHdr->u8DstMac[4] = (u32DstIp >> 8) & 0xff;
        pstEthHdr->u8DstMac[5] = (u32DstIp >> 0) & 0xff;
        printf("M2:%02X\n", pstEthHdr->u8DstMac[2]);
    }
    else
    {
        vMacToInt(REMOTE_MAC, pstEthHdr->u8DstMac);
    }
    pstEthHdr->u16Type = htons(0x0800);
    return pstEthHdr;
}

void Eth_vOutputFrm(uint8* u8Pcb, tstPbuf* pstPbuf)
{
    Eth_tstHdr* pstEthHdr = NULL;
    pstEthHdr = Eth_pstCreateHeader(u8Pcb, pstPbuf);

    Ip_tstPcb *pstPcb = (Ip_tstPcb*)u8Pcb;
    /* Use winpcap interface */
    Pcap_vSend(pstPcb->pSock, (uint8*)pstEthHdr, pstPbuf->u16Len);
}

void Eth_vInputFrm(tstPbuf *pstPbuf)
{
    Eth_tstHdr* pstEthHdr = (Eth_tstHdr*)pstPbuf->u8Payload;
    uint16 u16EthType = ntohs(pstEthHdr->u16Type);

    pstPbuf->u8Payload = pstPbuf->u8Payload + ETHNET_HLEN;
    pstPbuf->u16Len = pstPbuf->u16Len - ETHNET_HLEN;

    if (pstEthHdr->u8DstMac[0] & 1)
    {
        if ((pstEthHdr->u8DstMac[0] = MULTICAST_MAC_ADDR0) &&
            (pstEthHdr->u8DstMac[0] = MULTICAST_MAC_ADDR1) &&
            (pstEthHdr->u8DstMac[0] = MULTICAST_MAC_ADDR2))
        {
            printf("Multicast\n");
        }
    }

    if (u16EthType == 0x0806)
    {
        /* Get an arp requirement, send arp message with local MAC */
        ACE_DEBUG((LM_INFO, ACE_TEXT("Arp reply\n")));
        Arp_vReply();
    }
    else if (u16EthType == 0x0800)
    {
        Ip_vInputPkg(pstPbuf);
    }
    else
    {
        /* Other type */
    } 
}