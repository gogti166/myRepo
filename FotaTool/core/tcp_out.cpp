#include "tcp.h"
#include "ip.h"

void Tcp_vOutputSeg(Tcp_tstPcb *pstPcb)
{
	// MutexOut.acquire();

	Tcp_tstSeg *pstSeg = NULL;
	uint16 u16SendWnd = 0;
	uint16 u16LeftWnd = 0;
	uint16 u16Len = 0;

	u16SendWnd = MIN_VALUE(pstPcb->u16SendWnd, SND_WINDOW);
	ACE_DEBUG((LM_INFO, ACE_TEXT("SWin:%d\n"), u16SendWnd));
	if (pstPcb->u8TcpCtrlFlags & ACK_NOW)
	{
		/* Send an ACK to finish handshake. */
		Tcp_vSendEmptyAck(pstPcb);
		/* Connection established. */
		pstPcb->enExtState = CONNECTED;
		ACE_DEBUG((LM_INFO, ACE_TEXT("Connected\n")));
	}
	/* Get segment from Unsend-queue. */
	pstSeg = pstPcb->pstUnsendFront;
	//ACE_DEBUG((LM_INFO, ACE_TEXT("1\n")));

	/* Send-windows can't hold all data, split the data. */
	if ((pstSeg != NULL) && (ntohl(pstSeg->pstTcphdr->u32Seq) + pstSeg->u16DataLen) - (pstPcb->u32AckSeq) > u16SendWnd)
	{
		/* Example:
		assume that current sequence is 10221, data length is 1480, and acked segquence is 2921, send window is 8760,
		so the left windows that we can use is 2921(acked) + 8760(sendWnd) - 10221(seq) = 1460 < 1480, it's obivously
		that the left window(1460) can't fill the data we want to send(1480), so the left data(20) need to split into next
		queue.
		*/
		u16LeftWnd = uint16((pstPcb->u32AckSeq + u16SendWnd - 1) - ntohl(pstSeg->pstTcphdr->u32Seq));
		/* Split segment when got a recv-windows that is less than length of next Unsend segment(eg. 1460) */
		ACE_DEBUG((LM_INFO, ACE_TEXT("Split:%d-%d\n"), u16LeftWnd, pstSeg->u16DataLen));
		Tcp_vSplitSeg(pstPcb, u16LeftWnd);
		/*ACE_DEBUG((LM_INFO, ACE_TEXT("Win:%d\n"), u16SendWnd));
		pstPcb->u8TcpCtrlFlags = pstPcb->u8TcpCtrlFlags | ACK_NOW;
		Tcp_vSendEmptyAck(pstPcb);
		MutexOut.release();*/
		//return;
	}

	if (pstSeg != NULL)
	{
		ACE_DEBUG((LM_INFO, ACE_TEXT("Window:%u-%d-%d-%d\n"), ntohl(pstSeg->pstTcphdr->u32Seq), pstSeg->u16DataLen,
			pstPcb->u32AckSeq, ntohl(pstSeg->pstTcphdr->u32Seq) + pstSeg->u16DataLen - (pstPcb->u32AckSeq), u16SendWnd));
	}
	else
	{
		ACE_DEBUG((LM_INFO, ACE_TEXT("UnsendQ Null\n")));
	}
	ACE_DEBUG((LM_INFO, ACE_TEXT("PreOut=>:%d-%d-%d-%d\n"), ntohl(pstSeg->pstTcphdr->u32Seq), pstSeg->u16DataLen, pstPcb->u32AckSeq, u16SendWnd));
	/* Send until the send-window is not enough */
	while ((pstSeg != NULL) && ((ntohl(pstSeg->pstTcphdr->u32Seq) + pstSeg->u16DataLen) - (pstPcb->u32AckSeq) <= u16SendWnd))
	{
		u16Len = (uint16)((uint8*)(pstSeg->pstTcphdr) - pstSeg->pstPbuf->u8Payload);
		//ACE_DEBUG((LM_INFO, ACE_TEXT("RTL:%d\n"), u16Len));
		if (u16Len != 0)
		{
			/* Retransmission, reset payload position.*/
			pstSeg->pstPbuf->u16Len = pstSeg->pstPbuf->u16Len - u16Len;
			pstSeg->pstPbuf->u8Payload = (uint8*)(pstSeg->pstTcphdr);
		}
		/* Pass package to IP layer. */
		Ip_vOutputPkg((uint8*)pstPcb, pstSeg->pstPbuf);
		ACE_DEBUG((LM_INFO, ACE_TEXT("Out=>:%d-%d\n"), ntohl(pstSeg->pstTcphdr->u32Seq), pstSeg->pstPbuf->u16Len));
		//ACE_DEBUG((LM_INFO, ACE_TEXT("Wnd:%d-%d\n"), (ntohl(pstSeg->pstTcphdr->u32Seq) + pstSeg->u16DataLen) - pstPcb->u32AckSeq, u16SendWnd));
		/* Update internal sequence after sending segment out. */
        pstPcb->u32SendNxt = ntohl(pstSeg->pstTcphdr->u32Seq) + pstSeg->u16DataLen +
			(((ntohs(pstSeg->pstTcphdr->u16Reserve) & TCP_FLAGS) & (TCP_SYN | TCP_FIN)) == 0 ? 0 : 1);
		/* Move the segment we sent from unsend-queue into unacked-queue (TODO: should check SYN segment?)*/
		if (pstPcb->pstUnackedFront == NULL)
		{
			/* Add segment into unacked-queue */
			pstPcb->pstUnackedFront = pstSeg;
			pstPcb->pstUnackedRear = pstSeg;
		}
		else
		{
			/* TODO: should add in order as sequence */
			pstPcb->pstUnackedRear->next = pstSeg;
			pstPcb->pstUnackedRear = pstSeg;
#ifdef DEBUG
			if (ntohl(pstPcb->pstUnackedRear->pstTcphdr->u32Seq) == 10241)
			{
				pstSeg = pstPcb->pstUnackedFront;
				while (pstSeg != NULL)
				{
					printf("uack:%u-%02X\n", ntohl(pstSeg->pstTcphdr->u32Seq), ntohs(pstSeg->pstTcphdr->u16Reserve) & TCP_FLAGS);
					pstSeg = pstSeg->next;
				}
				pstPcb->u32AckSeq = 6145;
				Tcp_vReceive(pstPcb);
			}
#endif
		}
		//ACE_DEBUG((LM_INFO, ACE_TEXT("uack\n"), u16Len));
		/* The segment has delivered to unacked-queue, remove it from Unsend-queue. */
		pstPcb->pstUnsendFront = pstSeg->next;
		/* Get a new segment from Unsend-queue again. */
		pstSeg = pstPcb->pstUnsendFront;
	}
	// MutexOut.release();
}

Tcp_tstSeg *Tcp_pstCreateSeg(Tcp_tstPcb* pstPcb, tstPbuf *pstPbuf, uint8 u8HeadFlags, uint32 u32Seq)
{
	/* This is used to cotrol tcp behavior. */
	Tcp_tstSeg* pstSeg = (Tcp_tstSeg*)malloc(sizeof(Tcp_tstSeg));
	uint8 u8Orient = 0;//just for testing
	if (pstSeg == NULL)
	{
		ACE_DEBUG((LM_INFO, ACE_TEXT("Pbuf fail\n")));
		return pstSeg;
	}
	memset(pstSeg, 0x00, sizeof(Tcp_tstSeg));
	/* Form tcp header with content of Pbuf */
	pstSeg->pstTcphdr = Tcp_pstFormatHeader(pstPcb, pstPbuf, u8HeadFlags, u32Seq);
	pstSeg->pstPbuf = pstPbuf;
	/* Data length shouldn't contain tcp-header.*/
	pstSeg->u16DataLen = pstPbuf->u16Len - u8TcpHdrLen;
	/* Data pointer now is at data.*/
	pstSeg->pu8DataPtr = pstPbuf->u8Payload + u8TcpHdrLen;
	//ACE_DEBUG((LM_INFO, ACE_TEXT("CU\n")));
	/* Add checksum into tcp header */
	pstSeg->pstTcphdr->u16Check = htons(u16TcpUdpCheckSum((uint8*)pstPcb, (uint8*)pstSeg->pstTcphdr, pstSeg->pu8DataPtr, pstSeg->u16DataLen));
	//ACE_DEBUG((LM_INFO, ACE_TEXT("CM\n")));

	/*if (pstPcb->u8TcpOutFlags == TCP_SYN)
	{
		pstPcb->u32BuffSeq++;
	}*/
	//ACE_DEBUG((LM_INFO, ACE_TEXT("EnQue:%d-%u\n"), u8Orient, ntohl(pstPcb->pstUnsendRear->pstTcphdr->u32Seq)));
	//pstPcb->u16QueueLen++;
	return pstSeg;
}

void Tcp_vSendEmptyAck(Tcp_tstPcb *pstPcb)
{
	Tcp_tstSeg *pstSeg = NULL;
	tstPbuf *pstPbuf = NULL;

    pstPbuf = pstCreatePbuf(PBUF_TCP, 0, PBUF_RAM);
    pstSeg = Tcp_pstCreateSeg(pstPcb, pstPbuf, TCP_ACK, pstPcb->u32SendNxt + 0);
	/* Send the ACK-segment directly, don't add it into Unsend-queue. */
	Ip_vOutputPkg((uint8*)pstPcb, pstPbuf);
	/* Reset control flag. */
	pstPcb->u8TcpCtrlFlags = DEFAULT;
	vFreeSegment(pstSeg);
}

void TCP_vSendFin(Tcp_tstPcb *pstPcb)
{
	Tcp_tstSeg *pstSeg = NULL;
	tstPbuf *pstPbuf = NULL;

    pstPbuf = pstCreatePbuf(PBUF_TCP, 0, PBUF_RAM);
	/* Note:if send only FIN, remoter doesn't rspond, remoter respond when send FIN+ACK, why? */
	//pstSeg = Tcp_pstCreateSeg(pstPcb, pstPbuf, TCP_FIN, pstPcb->u32SendNxt + 0);// only FIN
    pstSeg = Tcp_pstCreateSeg(pstPcb, pstPbuf, TCP_FIN + TCP_ACK, pstPcb->u32SendNxt + 0);// FIN + ACK
	/* Add the FIN packet to the tail of unsend-queue */
	if (pstPcb->pstUnsendRear == NULL)//if pstUnsendRear is NULL, pstUnsendRear = pstUnsendFront
	{
		ACE_DEBUG((LM_INFO, ACE_TEXT("Rear NULL\n")));
		printf("Rear NULL\n");
		pstPcb->pstUnsendRear = pstSeg;
	}
	else
	{
		ACE_DEBUG((LM_INFO, ACE_TEXT("Rear NEXT\n")));
		printf("Rear NEXT\n");
		/* Add the FIN segment to the tail of Unsend-queue */
		pstPcb->pstUnsendRear->next = pstSeg;
	}
	/* Send FIN-segment out to request disconnect with remoter */
	Tcp_vOutputSeg(pstPcb);
}

void Tcp_vWrite(Tcp_tstPcb *pstPcb, const uint8 *pu8Data, uint16 u16TotalDataLen, uint8 u8Flags)
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
        /* Copy data from application to tcp internal buffer */
        if (u8Flags & TCP_WRITE_FLAG_COPY)
        {   /* Create buf as format "ETH+IP+TCP+DATA" */
            pstPbuf = pstCreatePbuf(PBUF_TCP, u16SegLen, PBUF_RAM);
            memcpy(pstPbuf->u8Payload, pu8Data + u16CurDataLen, u16SegLen);
        }
        else
        {
            /* Create buffer by "PBUF_TCP" that means its size consists of "ETH+IP+TCP" respective header */
            //pstPbuf = pstCreatePbuf(PBUF_TCP, 0, PBUF_REF);
            /* ERROR: it will influnce tcphdr filling if change payload here!!! */
            //pstPbuf->u8Payload = u8Data + u16CurDataLen;
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