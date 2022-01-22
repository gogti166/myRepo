#include "udp.h"
#include "ip.h"

Udp_tstPcb* pstUdpPcbs = NULL;

Udp_tstPcb *Udp_pstAllocPcb()
{
    Udp_tstPcb* pstPcb = NULL;
    pstPcb = (Udp_tstPcb*)malloc(sizeof(Udp_tstPcb));
    if (pstPcb == NULL)
    {
        ACE_DEBUG((LM_INFO, ACE_TEXT("Pcb fail\n")));
        return NULL;
    }
    else
    {
        memset(pstPcb, 0x00, sizeof(Udp_tstPcb));
        pstPcb->u8TtL = 64;
    }
    return pstPcb;
}

Udp_tstPcb *Udp_vNewUdp(uint16 u16SrcPort, uint16 u16DstPort, uint8 *u8SrcIp, uint8 *u8DstIp)
{
    Udp_tstPcb* pstPcb = Udp_pstAllocPcb();
    if (pstPcb != NULL)
    {
        bool boExisted = False;
        Udp_tstPcb *pstMovePcb = NULL;

        pstPcb->pSock = pSock;
        pstPcb->u16LocalPort = u16SrcPort;
        pstPcb->u16RemotePort = u16DstPort;
        pstPcb->u32LocalIp = u32Ipv4ToInt((char*)u8SrcIp);
        pstPcb->u32RemoteIp = u32Ipv4ToInt((char*)u8DstIp);
        pstPcb->u8IpProto = IPPROTO_UDP;
        /* Find PCB from UdpPcb-queue. addw: If alloc before , this nerver happen */
        for (pstMovePcb = pstUdpPcbs; pstMovePcb != NULL; pstMovePcb = pstMovePcb->next)
        {
            if (pstPcb == pstMovePcb)
            {
                /* This pcb is already in udpPcb-queue. */
                boExisted = True;          
                break;
            }
        }
        if (boExisted == False)
        {
            /* Insert the new udpPcb from head of udpPcb-queue. */
            pstPcb->next = pstUdpPcbs;
            pstUdpPcbs = pstPcb;
        }
    }
    return pstPcb;
}

Udp_tstHdr* Udp_pstCreateHeader(Udp_tstPcb* pstPcb, tstPbuf *pstPbuf, uint16 u16DataLen)
{
    Udp_tstHdr* pstUdphdr = NULL;

    pstPbuf->u8Payload = pstPbuf->u8Payload - u8UdpHdrLen;
    pstPbuf->u16Len = pstPbuf->u16Len + u8UdpHdrLen;
    /* Fill UDP header. */
    pstUdphdr = (Udp_tstHdr*)(pstPbuf->u8Payload);
    pstUdphdr->u16Src = htons(pstPcb->u16LocalPort);
    pstUdphdr->u16Dst = htons(pstPcb->u16RemotePort);
    pstUdphdr->u16Len = htons(u8UdpHdrLen + u16DataLen);
    pstUdphdr->u16Check = 0;
    return pstUdphdr;
}

void Udp_vSend(Udp_tstPcb *pstPcb, uint8* u8DataPtr, uint16 u16DataLen)
{
    tstPbuf *pstPbuf = NULL;
    Udp_tstHdr* pstUdphdr = NULL;
    /* Create buf as format "ETH+IP+UDP" */
    pstPbuf = pstCreatePbuf(PBUF_UDP, u16DataLen, PBUF_COPY);
    memcpy(pstPbuf->u8Payload, u8DataPtr, u16DataLen);
    pstPbuf->u16Len = u16DataLen;
    pstUdphdr = Udp_pstCreateHeader(pstPcb, pstPbuf, u16DataLen);
    pstUdphdr->u16Check = htons(u16TcpUdpCheckSum((uint8*)pstPcb, (uint8*)pstUdphdr, u8DataPtr, u16DataLen));
    Ip_vOutputPkg((uint8*)pstPcb, pstPbuf);
}

void Udp_vInputSeg(tstPbuf *pstPbuf)
{
    Udp_tstHdr* pstUdphdr = (Udp_tstHdr*)pstPbuf->u8Payload;
    uint32 u32SrcPort = ntohs(pstUdphdr->u16Src);
    uint32 u32DstPort = ntohs(pstUdphdr->u16Dst);
    Udp_tstPcb* pstMovePcb = NULL;
    for (pstMovePcb = pstUdpPcbs; pstMovePcb != NULL; pstMovePcb = pstMovePcb->next)
    {
        if ((pstMovePcb->u16LocalPort == u32DstPort) && 
            (pstMovePcb->u16RemotePort == u32SrcPort))
        {
            if (pstMovePcb->vRecvFun != NULL)
            {
                pstMovePcb->vRecvFun(pstPbuf->u8Payload + 8, pstPbuf->u16Len - 8);
            }
        }
    }

}