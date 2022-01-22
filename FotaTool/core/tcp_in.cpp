#include "tcp.h"
#include "ip.h"

Tcp_tstHdr* pstGbTcphdr;

void Tcp_vReceive(Tcp_tstPcb *pstPcb)
{
	Tcp_tstSeg *pstSeg = NULL;
	uint32 u32DB_RmvSeq = 0;//addw for debug
	bool boRemoved = False;
	static uint32 u32LastAckSeq = 0;
	if (pstPcb->u8TcpInFlags & TCP_ACK)
	{
		/* Update windows */
		pstPcb->u16SendWnd = ntohs(pstGbTcphdr->u16Window);

		if (pstPcb->enState == ESTABLISHED)
		{
			pstSeg = pstPcb->pstUnackedFront;
			ACE_DEBUG((LM_INFO, ACE_TEXT("PreRmv:%u-%d-%d\n"), ntohl(pstSeg->pstTcphdr->u32Seq), pstSeg->u16DataLen, pstPcb->u32AckSeq));
			/* Remove all segments that have been acked from unacked-queue. */
			while ((pstSeg != NULL) && (ntohl(pstSeg->pstTcphdr->u32Seq) + pstSeg->u16DataLen + ((ntohs(pstPcb->u8TcpInFlags) & TCP_SYN) == 0 ? 0 : 1))
				<= pstPcb->u32AckSeq)
			{
				/* The segment has been acked, front should point to next node. */
				pstPcb->pstUnackedFront = pstSeg->next;
				u32DB_RmvSeq = ntohl(pstSeg->pstTcphdr->u32Seq) + pstSeg->u16DataLen + ((ntohs(pstPcb->u8TcpInFlags) & TCP_SYN) == 0 ? 0 : 1);
				ACE_DEBUG((LM_INFO, ACE_TEXT("Rmv:%u+%d\n"), ntohl(pstSeg->pstTcphdr->u32Seq), pstSeg->u16DataLen));
				//printf("Remove:%u-%d\n", ntohl(pstSeg->pstTcphdr->u32Seq), pstSeg->u16DataLen + (((ntohs(pstSeg->pstTcphdr->u16Reserve) & TCP_FLAGS) & TCP_SYN) == 0 ? 0 : 1));            
				//printf("Remove:%u\n", ntohl(pstSeg->pstTcphdr->u32Seq)+1024);
				/* The sent-data has been acked, so we have now space for buffersize. */
				/*pstPcb->u16BuffSize = pstPcb->u16BuffSize + pstSeg->u16DataLen;*/
				vFreeSegment(pstSeg);
				pstSeg = pstPcb->pstUnackedFront;
				boRemoved = True;
			}
			/* Retransmission */
			if (u32LastAckSeq == pstPcb->u32AckSeq)
			{
				pstPcb->u8DupAcks++;
				/* Receive duplicated ACK for 3 times */
				//Ϊʲô�˴���2��
				//��Ϊ��һ���յ�ĳ��ACKʱ��u32LastAckSeq != pstPcb->u32AckSeq�Ǳ�Ȼ�ģ��ڶ����յ���ʱ����ж�
				//u32LastAckSeq == pstPcb->u32AckSeq�Ż������������u8DupAcks����1���������յ���ʱ���ж�
				//u32LastAckSeq == pstPcb->u32AckSeq�����������ʱ��u8DupAcks����2������ʱ��ͬ��ACK�Ѿ���
				//��3���յ��ˣ����u8DupAcksֻ��Ҫ�ӵ�2��˵����ͬ��ACK�յ�3����
				if (pstPcb->u8DupAcks >= 2)
				{
					/* Slash buffer space to prevent data input from application. */
					pstPcb->u16BuffSize = 0;
					//pstPcb->u16BuffSize = pstPcb->u16BuffSize - n * 1024;

#if 0
/* Regard unacked-queue as unsend-queue. *///unacked-queue��Dup ACK�������unacked seg�����ش�
					pstPcb->pstUnackedRear->next = pstPcb->pstUnsendFront;
					pstPcb->pstUnsendFront = pstPcb->pstUnackedFront;
					pstPcb->pstUnackedFront = NULL;
					pstPcb->pstUnackedRear = NULL;
#endif
					/* Regard the first unacked-seg as one of unsend-queue. *///ֻ�ش�Dup ACK�Ǹ�unacked seg
					pstPcb->pstUnackedFront->next = pstPcb->pstUnsendFront;
					pstPcb->pstUnackedFront = pstPcb->pstUnackedFront->next;
					pstPcb->pstUnsendFront = pstSeg;
					ACE_DEBUG((LM_INFO, ACE_TEXT("RT:%u-%u\n"), pstPcb->u32AckSeq, ntohl(pstPcb->pstUnsendFront->pstTcphdr->u32Seq)));
					pstPcb->u8DupAcks = 0;
				}
			}
			else
			{
				pstPcb->u8DupAcks = 0;
			}
			u32LastAckSeq = pstPcb->u32AckSeq;
			//ACE_DEBUG((LM_INFO, ACE_TEXT("RmvA:%u\n"), u32DB_RmvSeq));
			/* All sent-data have been acked, so we have space again for new data from app. */
			if ((pstSeg == NULL) && (boRemoved == True))
			{
				pstPcb->u16BuffSize = DATA_COUNT * BYTE_LEN;
				ACE_DEBUG((LM_INFO, ACE_TEXT("+:%u\n"), pstPcb->u16BuffSize));
			}
		}
#ifdef DEBUG
		pstSeg = pstPcb->pstUnackedFront;
		while (pstSeg != NULL)
		{
			printf("Rmuack:%u\n", ntohl(pstSeg->pstTcphdr->u32Seq));
			pstSeg = pstSeg->next;
		}
#endif
	}
}

void Tcp_vProcess(Tcp_tstPcb *pstPcb)
{
	switch (pstPcb->enState)
	{
	case SYN_SENT:
		if ((pstPcb->u8TcpInFlags & TCP_ACK) && (pstPcb->u8TcpInFlags & TCP_SYN))//��öԷ���ACK+SYN��Ӧ�����ڶ�������
		{
			/* Send-windows should adjust to meet feedback from remoter. */
			pstPcb->u16SendWnd = ntohs(pstGbTcphdr->u16Window);//���ʹ���Ӧ�õ��������շ������Ĵ���
			pstPcb->u32AckSeq = u32AckSeq;
			/* Respond ACK to end the three-handshakes. */
			pstPcb->u8TcpOutFlags = TCP_ACK;
			/* Increase by 1 because a SYN got. */
			pstPcb->u32RecvNxt = u32Seq + 1;
			/* We are now in a state that connection has been established. */
			pstPcb->enState = ESTABLISHED;
			/* Notify user of successful connection */
            pstPcb->TCP_vConnectedCbk(pstPcb->vCbkArg);
			/* Calculate MSS */
			/*pstPcb->u16Mss = 1460;//from option bytes*/
			pstPcb->u8TcpCtrlFlags = pstPcb->u8TcpCtrlFlags | ACK_NOW;
			Tcp_vReceive(pstPcb);
		}
		else if (pstPcb->u8TcpInFlags & TCP_RST)
		{
			ACE_DEBUG((LM_INFO, ACE_TEXT("RST")));
		}
		break;

	case ESTABLISHED:
		Tcp_vReceive(pstPcb);
		if (pstPcb->u8TcpInFlags & TCP_FIN)
		{
			ACE_DEBUG((LM_INFO, ACE_TEXT("FIN")));
			pstPcb->u8TcpOutFlags = TCP_ACK;
			Tcp_vSendEmptyAck(pstPcb);
			/* Respond ACK for FIN and change state to WAIT */
			pstPcb->enState = CLOSE_WAIT;
		}
		break;

	case FIN_WAIT_1:
		if (pstPcb->u8TcpInFlags & TCP_FIN)
		{
            if ((pstPcb->u8TcpInFlags & TCP_ACK) && (u32AckSeq == pstPcb->u32SendNxt))
			{

			}
		}
		/* We received a ACK from remoter after sent the FIN */
        else if ((pstPcb->u8TcpInFlags & TCP_ACK) && (u32AckSeq == pstPcb->u32SendNxt))
		{
			printf("FIN_WAIT_1\n");
			pstPcb->enState = FIN_WAIT_2;
		}
		else
		{
			/* unexcepted receive */
		}
		break;

	case FIN_WAIT_2:/* Wait to receive the FIN + ACK from remoter */
		printf("FIN_WAIT2\n");
		break;

	case CLOSE_WAIT:
		break;

	default:
		break;
	}
}

/* TCP segment to process (p->payload pointing to the TCP header). */
void Tcp_vInputSeg(tstPbuf *pstPbuf)
{
	Tcp_tstPcb* pstPcb = pstActivePcbs;
	pstGbTcphdr = (Tcp_tstHdr*)pstPbuf->u8Payload;
	u32Seq = ntohl(pstGbTcphdr->u32Seq);
	u32AckSeq = ntohl(pstGbTcphdr->u32AckSeq);
	pstPcb->u32AckSeq = ntohl(pstGbTcphdr->u32AckSeq);
	pstPcb->u8TcpInFlags = ntohs(pstGbTcphdr->u16Reserve) & TCP_FLAGS;
	ACE_DEBUG((LM_INFO, ACE_TEXT("InAckSeq:%u\n"), u32AckSeq));

	/*addw �յ���ack������������ȥ����sequence+len,˵������һ�������ack,��Ϊackֻ��С�ڻ�����Ѿ�����ȥ�����ݴ�С*/
    if (u32AckSeq > pstPcb->u32SendNxt)
	{
        printf("Ack-snd:%d-%d\n", u32AckSeq, pstPcb->u32SendNxt);
		/* note 192.168.10.02 ������Ҳ�ᱻ���մ������ack���󣬴Ӷ�����*/
		/* TODO: �Ƿ�Ҫ��IP���src IP��ַ���м��? */
		ACE_DEBUG((LM_INFO, ACE_TEXT("Ack error\n")));
		printf("Ack ERROR IP:\n");
		uint8 u8i = 0;
		for (u8i = 0; u8i < 20; u8i++)
		{
			printf("%02X ", *(pstPbuf->u8Payload - IP_HLEN + u8i));
		}
		printf("Ack ERROR TCP\n");
		for (u8i = 0; u8i < 20; u8i++)
		{
			printf("%02X ", *(pstPbuf->u8Payload + u8i));
		}
		printf("\n");
	}
	else
	{
		//pstInSeg.next = NULL;
		//pstInSeg.u16DataLen = 0;//addw ?
		//pstInSeg.stPbuf = pstPbuf;
		//pstInSeg.pstTcphdr = pstTcphdr;
		Tcp_vProcess(pstPcb);
		/* We moved *payload back by length of TCP header in TcpHandle_Tsk::svc. */
		/*pstPbuf->u8Payload = pstPbuf->u8Payload + u8TcpHdrLen;
		pstPbuf->u16Len = 0;*/
		ACE_DEBUG((LM_INFO, ACE_TEXT("Tcp_vOutputSeg\n")));


		/*else
		{*/
		Tcp_vOutputSeg(pstPcb);
		/*} */
	}
}