#include "common.h"
#include "thread.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "udp.h"
#include <ace/Select_Reactor.h>

int EventLoop_Tsk::svc()
{
    while (ACE_Reactor::instance()->reactor_event_loop_done() == 0)
    {
        ACE_Reactor::instance()->owner(ACE_OS::thr_self());
        ACE_Reactor::instance()->run_reactor_event_loop();
    }
    return 0;
}

int Handle_Tsk::svc()
{
    ACE_Message_Block* DequeueMb = 0;
    static tstPbuf* pstPbuf;
    while (1)
    {
        if (!this->msg_queue()->is_empty())
        {
            /* Dequeue messages which set in Recv_task. */
            this->getq(DequeueMb);
            if (boMalloced == False)
            {
                pstPbuf = pstCreatePbuf(PBUF_UDP, 0, PBUF_REF);
                boMalloced = True;
            }
            /* Don't copy, payload refers to received data. */
            pstPbuf->u8Payload = (uint8*)DequeueMb->rd_ptr();
            pstPbuf->u16Len = DequeueMb->length();
            Eth_vInputFrm(pstPbuf);
            //free(pstPbuf);
            DequeueMb->release();
        }
    }
    return 0;
}

int Recv_Tsk::svc()
{
    const uint8* u8RecvBuf = au8RecvData;
    int32 i32RcvLen = 0;
    do
    {
        i32RcvLen = Pcap_vRecv(pSock, &u8RecvBuf);
        if (i32RcvLen != -1)
        {
            if (i32RcvLen == 0)
            {
                continue;
            }
            else
            {
                /* Enqueue received messages. */
                ACE_Message_Block* EnqueueMb = new ACE_Message_Block(i32RcvLen);
                EnqueueMb->copy((char*)u8RecvBuf, i32RcvLen);
                HandleTask->putq(EnqueueMb);
            }
        }
        else
        {
            ACE_DEBUG((LM_INFO, ACE_TEXT("Recv err\n")));
            break;
        }
    } while(1);
    return 0;
}

