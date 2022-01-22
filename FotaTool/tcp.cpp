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
    pstPbuf = pstCreatePbuf(PBUF_TCP, u16LeftLen, PBUF_COPY);
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
    pstPbuf = pstCreatePbuf(PBUF_TCP, 0, PBUF_COPY);
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

void Tcp_vWrite(Tcp_tstPcb *pstPcb, uint8 *u8Data, uint16 u16TotalDataLen)
{
    uint16 u16SegCnt = 0;
    uint16 u16SegLen = 0;
    uint16 u16CurDataLen = 0;
    tstPbuf *pstPbuf = NULL;
    Tcp_tstSeg* pstSeg = NULL;
    Tcp_tstSeg* pstQueue = NULL;
    Tcp_tstSeg* pstCursor = NULL;
    bool boCopyData = true;

    /* TODO: should't allocate buffer for data always,use array*/

    /* The data length have write is still less than the length need to write. */
    while (u16CurDataLen < u16TotalDataLen)
    {
        u16SegCnt++;
        /* Separate TCP if length is greater than MSS. */
        u16SegLen = (u16SegCnt*MSS <= u16TotalDataLen ? MSS : (u16TotalDataLen % MSS));

        if (boCopyData)
        {   /* Create buf as format "ETH+IP+TCP+DATA" */
            pstPbuf = pstCreatePbuf(PBUF_TCP, u16SegLen, PBUF_COPY);
            memcpy(pstPbuf->u8Payload, u8Data + u16CurDataLen, u16SegLen);
        }
        else
        {
            /* Create buffer by "PBUF_TCP" that means its size consists of "ETH+IP+TCP" respective header */
            pstPbuf = pstCreatePbuf(PBUF_TCP, 0, PBUF_REF);
            /* ERROR: it will influnce tcphdr filling if change payload here!!! */
            pstPbuf->u8Payload = u8Data + u16CurDataLen;
        }
        pstPbuf->u16Len = u16SegLen;
        ACE_DEBUG((LM_INFO, ACE_TEXT("Set:%d-%d\n"), pstPcb->u32BuffSeq + u16CurDataLen, u16SegLen));
        /* Create a segment with formated tcp header */
        pstSeg = Tcp_pstCreateSeg(pstPcb, pstPbuf, (TCP_PSH | TCP_ACK), pstPcb->u32BuffSeq + u16CurDataLen);
        /* Add the new segment into segment-queue. */
        if (pstQueue == NULL)
        {
            pstQueue = pstSeg;
        }
        else
        {
            /* Add the new segment to the segment-queue tail. */
            pstCursor->next = pstSeg;
        }
        pstCursor = pstSeg;
        u16CurDataLen = u16CurDataLen + u16SegLen;
    }
    /* The buffer number. */
    pstPcb->u32BuffSeq = pstPcb->u32BuffSeq + u16TotalDataLen;
    /* The remaining buffer size. */
    pstPcb->u16BuffSize = pstPcb->u16BuffSize - u16TotalDataLen;

    /* All segments have inserted into segment-queue, delivery the segment-queue to Unsend-queue. */
    if (pstPcb->pstUnsendFront == NULL)
    {
        pstPcb->pstUnsendFront = pstQueue; 
    }
    else
    {
        /* Connect the segment-queue to the Unsend-queue tail. */
        pstPcb->pstUnsendRear->next = pstQueue;
    }
    /* Rear piont to the last node. */
    pstPcb->pstUnsendRear = pstCursor;

    /* 假设buffer中的最后一个queue member其sequence = 32121,len = 648发送出去,预料的ackSeq = 32769被Tcp_vInputSeg接收到,
    Tcp_vInputSeg会先调用Tcp_vReceive将queue全部清空,因此当Tcp_vInputSeg在调用到Tcp_vOutputSeg时因为buffer为空,就不会发送出
    任何数据,随后Tcp_vWrite抢占到时间片写入数据到buffer,但是只有等待Tcp_vInputSeg再次收到ackSeq = 32769触发Tcp_vOutputSeg,才能
    将Tcp_vWrite填充的buffer发送出去,为了减少这样的等待时间,需要app主动调用Tcp_vOutputSeg,而现在的优化是不需要app调用Tcp_vOutputSeg,
    因此需要在此处加入Tcp_vOutputSeg,即在Tcp_vWrite中调用Tcp_vOutputSeg*/


    //ACE_DEBUG((LM_INFO, ACE_TEXT("u32AckSeq:%u\n"), pstPcb->u32AckSeq));
    //ACE_DEBUG((LM_INFO, ACE_TEXT("u32BuffSeq:%u-%d\n"), pstPcb->u32BuffSeq + u16CurDataLen, u16CurDataLen));
    if (pstPcb->u32AckSeq == ntohl(pstPcb->pstUnsendFront->pstTcphdr->u32Seq))//the sequence's acknowledgement has ever been received
    {
        ACE_DEBUG((LM_INFO, ACE_TEXT("WriteSend:%u\n"), u32AckSeq));
        Tcp_vOutputSeg(pstPcb);
    }
}



