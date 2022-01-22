#include "tcp.h"
#include "ip.h"

Tcp_tstPcb  *pstActivePcbs;
//Tcp_tstHdr* pstTcphdr;

ACE_Thread_Mutex MutexOut;

void vFreeSegment(Tcp_tstSeg *pstSeg)
{
    if (pstSeg != NULL)
    {
        if (pstSeg->pstPbuf != NULL)
        {
            free(pstSeg->pstPbuf);
        }
        free(pstSeg);
    }
}

Tcp_tstHdr* Tcp_pstFormatHeader(Tcp_tstPcb* pstPcb, tstPbuf *pstPbuf, uint8 u8HeadFlags, uint32 u32Seq)
{
    Tcp_tstHdr* pstTcphdr = NULL;

    /* Payload back away by 20bytes to fill TCP header. */
    pstPbuf->u8Payload = pstPbuf->u8Payload - u8TcpHdrLen;
    /* Fill a TCP header by 20bytes. */
    pstPbuf->u16Len = pstPbuf->u16Len + u8TcpHdrLen;
    /* Fill TCP header. */
    pstTcphdr = (Tcp_tstHdr*)(pstPbuf->u8Payload);
    pstTcphdr->u16Src = htons(pstPcb->u16LocalPort);
    pstTcphdr->u16Dst = htons(pstPcb->u16RemotePort);
    pstTcphdr->u32Seq = htonl(u32Seq);
    pstTcphdr->u32AckSeq = htonl(pstPcb->u32RecvNxt);//addw differ from BuffSeq
    pstTcphdr->u16Reserve = htons((uint16)(5 << 12 | (u8HeadFlags)));
    pstTcphdr->u16Window = htons(1024);
    pstTcphdr->u16UrgPtr = 0;
    pstTcphdr->u16Check = 0;
    return pstTcphdr;
}

void Tcp_vSplitSeg(Tcp_tstPcb *pstPcb, uint16 u16Split)
{
    Tcp_tstSeg *pstSeg = NULL;
    Tcp_tstSeg *pstSecondPartSeg = NULL;
    tstPbuf *pstPbuf = NULL;

    pstSeg = pstPcb->pstUnsendFront;
    if (u16Split == 0)
    {
        ACE_DEBUG((LM_INFO, ACE_TEXT("Split:0\n")));
    }

    uint8 u8SplitFlags = pstSeg->pstTcphdr->u16Reserve & TCP_FLAGS;
    uint32 u32SplitSeq = ntohl(pstSeg->pstTcphdr->u32Seq) + (uint32)u16Split;

    //ACE_DEBUG((LM_INFO, ACE_TEXT("SpSeq:%u+%d=%d\n"), ntohl(pstSeg->pstTcphdr->u32Seq), (uint32)u16Split, u32SplitSeq));
    /* The data length of second part. */
    uint16 u16LeftLen = pstSeg->u16DataLen - u16Split;//1480 - 1460 = 20
    /* Create a buf for second part. */
    pstPbuf = pstCreatePbuf(PBUF_TCP, u16LeftLen, PBUF_RAM);
    /* Copy data from split point to payload of second part. */
    memcpy(pstPbuf->u8Payload, pstSeg->pu8DataPtr + u16Split, u16LeftLen);
    pstPbuf->u16Len = pstPbuf->u16Len + u16LeftLen;
    /* Create a segment to hold the second part of original segment. */
    pstSecondPartSeg = Tcp_pstCreateSeg(pstPcb, pstPbuf, u8SplitFlags, u32SplitSeq);
    /* Update the first part. */
    pstSeg->pstPbuf->u16Len = pstSeg->pstPbuf->u16Len - u16LeftLen;//344 = 1480 - 1136

    //ACE_DEBUG((LM_INFO, ACE_TEXT("SpP:%u-%d-%d\n"), u32SplitSeq, u16LeftLen, pstSeg->pstPbuf->u16Len));
    pstSeg->pstTcphdr->u16Check = 0;
    pstSeg->u16DataLen = u16Split;
    pstSeg->pstTcphdr->u16Check = htons(u16TcpUdpCheckSum((uint8*)pstPcb, (uint8*)pstSeg->pstTcphdr, pstSeg->pu8DataPtr, pstSeg->u16DataLen));

    /* Link the second part after the first part. */
    pstSecondPartSeg->next = pstSeg->next;
    pstSeg->next = pstSecondPartSeg;

    ACE_DEBUG((LM_INFO, ACE_TEXT("Sp:%u-%d\n"), ntohl(pstSeg->pstTcphdr->u32Seq), ntohl(pstSecondPartSeg->pstTcphdr->u32Seq)));
}

Tcp_tstPcb *Tcp_pstAllocPcb()
{
    Tcp_tstPcb* pstPcb = NULL;
    pstPcb = (Tcp_tstPcb*)malloc(sizeof(Tcp_tstPcb));
    if (pstPcb == NULL)
    {
        ACE_DEBUG((LM_INFO, ACE_TEXT("Pcb fail\n")));
        return NULL;
    }
    else
    {
        memset(pstPcb, 0x00, sizeof(Tcp_tstPcb));
        pstPcb->u16BuffSize = DATA_COUNT*BYTE_LEN;
        pstPcb->u8TtL = 128;
        pstPcb->u16Mss = MSS;
        pstPcb->u16CgstWnd = 1;
        pstPcb->u16Thresh = pstPcb->u16BuffSize;
    }
    return pstPcb;
}

#ifndef API_SOCKET
Tcp_tstPcb *Tcp_vConnect(TCP_vConnectedCbk vConnectCbk)
{
    Tcp_tstPcb* pstCliPcb = NULL;
    tstPbuf *pstPbuf = NULL;
    Tcp_tstSeg* pstSeg = NULL;
    /* The Pcb will be responsible for this communication. */
    pstCliPcb = Tcp_pstAllocPcb();
    pstCliPcb->u16LocalPort = TCP_SOUR_PORT;
    pstCliPcb->u16RemotePort = TCP_DEST_PORT;
    pstCliPcb->u8TcpOutFlags = TCP_SYN;
    pstCliPcb->u8IpProto = IPPROTO_TCP;
    pstCliPcb->u32LocalIp = u32Ipv4ToInt(LOCAL_IP);
    pstCliPcb->u32RemoteIp = u32Ipv4ToInt(REMOTE_IP);
    pstCliPcb->pSock = pSock;
    //pstCliPcb->u16Mss = INITIAL_MSS;
    //stClientPcb->u32CurSeq = stClientPcb->u32CurSeq + 1;
    pstCliPcb->u32AckSeq = 0;
    /* Congestion Windows */
    //pstCliPcb->u16CgstWnd = 1;
    pstCliPcb->u16SendWnd = 4 * INITIAL_MSS;
    /* Creater a TCP segment without data. */
    pstPbuf = pstCreatePbuf(PBUF_TCP, 0, PBUF_RAM);
    /* The first segment of TCP communication, sequence should be 0. */
    pstSeg = Tcp_pstCreateSeg(pstCliPcb, pstPbuf, TCP_SYN, pstCliPcb->u32BuffSeq);
    /* We have sent a SYN-segment. */
    pstCliPcb->u32BuffSeq++;
    /* Add the first segment into Unsend-queue. */
    pstCliPcb->pstUnsendFront = pstSeg;
    pstCliPcb->pstUnsendRear = pstSeg;
	pstCliPcb->TCP_vConnectedCallback = vConnectCbk;
    /* Send SYN-segment out to request the first handshake with server. */
    Tcp_vOutputSeg(pstCliPcb);
    /* We are now in a state that SYN has been sent. */
    pstCliPcb->enState = SYN_SENT;
    pstActivePcbs = pstCliPcb;
    return pstCliPcb;
}
#else
tenErr Tcp_enConnect(Tcp_tstPcb* stPcb, const tstIpAddr *stIpAddr, const uint16 u16Port)
{
    tenErr enRet = enNoErr;
    tstPbuf *pstPbuf = NULL;
    Tcp_tstSeg* pstSeg = NULL;
    /* Local Ip and port */
    printf("02\n");
    stPcb->u32LocalIp = u32Ipv4ToInt(LOCAL_IP);
    stPcb->u16LocalPort = TCP_SOUR_PORT;
    /* Remote Ip and port */
    stPcb->u32RemoteIp = stIpAddr->u32Addr;
    stPcb->u16RemotePort = u16Port;
    printf("00\n");
    /* Initilize acknowledgement sequence to 0 */
    stPcb->u32AckSeq = 0;
    /* Initilize the send windows */
    stPcb->u16SendWnd = 4 * INITIAL_MSS;
    /* Creater a TCP segment without data. */
    pstPbuf = pstCreatePbuf(PBUF_TCP, 0, PBUF_RAM);
    printf("03\n");
    /* The first segment of TCP communication, sequence should be 0. */
    pstSeg = Tcp_pstCreateSeg(stPcb, pstPbuf, TCP_SYN, stPcb->u32BuffSeq);
    printf("04\n");
    /* Send SYN-segment out to request the first handshake with server. */
    Tcp_vOutputSeg(stPcb);
    printf("05\n");
    /* We are now in a state that SYN has been sent. */
    stPcb->enState = SYN_SENT;
    pstActivePcbs = stPcb;
    printf("01\n");
    return enRet;
}
#endif

void TCP_vClose()
{
	Tcp_tstPcb* pstPcb = pstActivePcbs;
	switch (pstPcb->enState)
	{
	case ESTABLISHED:
		TCP_vSendFin(pstPcb);
		pstPcb->enState = FIN_WAIT_1;
		break;
	}
}



