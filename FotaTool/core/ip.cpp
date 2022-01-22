#include "ethernet.h"
#include "ip.h"
//#include "udp.h"
//#include "common.h"

static uint16 u16Id = 0;
Ip_tstHdr *Ip_pstCreateHeader(uint8* u8Pcb, tstPbuf* pstPbuf)
{
    Ip_tstPcb *pstPcb = (Ip_tstPcb*)u8Pcb;

    pstPbuf->u8Payload = pstPbuf->u8Payload - u8IpHdrLen;
    pstPbuf->u16Len = pstPbuf->u16Len + u8IpHdrLen;
    Ip_tstHdr *pstIpHdr = (Ip_tstHdr*)(pstPbuf->u8Payload);
    pstIpHdr->u8Ihl = 0x05;
    pstIpHdr->u8Version = 0x04;
    pstIpHdr->u8Tos = 0x00;
    pstIpHdr->u16TotLen = htons(pstPbuf->u16Len);
    pstIpHdr->u16Id = u16Id;
    pstIpHdr->u8Ttl = pstPcb->u8TtL;
    pstIpHdr->u8Protocol = pstPcb->u8IpProto;
    pstIpHdr->u8Check = 0;
    pstIpHdr->u32SrcAddr = pstPcb->u32LocalIp;
    pstIpHdr->u32DstAddr = pstPcb->u32RemoteIp;
    /* Calculate IP checksum */
    uint32 u32ChkSum = 0;
    uint32 u32Num = 0;
    uint8* u8HdrPtr = (uint8*)pstIpHdr;
    uint8 u8I;
    for (u8I = 0; u8I <= 18; u8I += 2)
    {
        u32Num = (u8HdrPtr[u8I] << 8) + u8HdrPtr[u8I + 1];
        u32ChkSum += u32Num;
        u32ChkSum = (u32ChkSum & 0xffff) + (u32ChkSum >> 16);
    }
    u32ChkSum = (~u32ChkSum) & 0xffff;
    pstIpHdr->u8Check = htons((uint16)u32ChkSum);
    u16Id++;
    return pstIpHdr;
}

void Ip_vOutputPkg(uint8* u8Pcb, tstPbuf* pstPbuf)
{
    Ip_tstHdr *pstIpHdr = Ip_pstCreateHeader(u8Pcb, pstPbuf);
    Eth_vOutputFrm(u8Pcb, pstPbuf);
}

void Ip_vInputPkg(tstPbuf *pstPbuf)
{
    Ip_tstHdr *pstIpHdr = (Ip_tstHdr*)pstPbuf->u8Payload;
    uint8 u8UpLayerProto = pstIpHdr->u8Protocol;

    pstPbuf->u8Payload = pstPbuf->u8Payload + IP_HLEN;
    pstPbuf->u16Len = pstPbuf->u16Len - IP_HLEN;
    
    if (u8UpLayerProto == 0x06)
    {
        /* TCP segment */
        Tcp_vInputSeg(pstPbuf);    
    }
    else if (u8UpLayerProto == 0x11)
    {
        /* UDP segment */
        Udp_vInputSeg(pstPbuf);
    }
    else
    {
        /* Other upper layer protocol */
    }
}