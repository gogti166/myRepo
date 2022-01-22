#include "api.h"
#include "tcp.h"
#include "api_msg.h"
#include "sem.h"

tstNetconn *pstAllocConn(tenConnType enType)
{
    tstNetconn* pstConn = (tstNetconn*)malloc(sizeof(tstNetconn));//TODO: use mem pool
    if (pstConn == NULL)
    {
        ACE_DEBUG((LM_INFO, ACE_TEXT("NetConn fail\n")));
    }
    
    switch (enType)
    {
    case NETCONN_TCP:
        /* Create a new PCB for TCP type */
        pstConn->unPcb.pstTcp = Tcp_pstAllocPcb();
        pstConn->enConnType = enType;
        break;

    default:
        break;
    }

    /* allocate semaphore */
    Sem_vAlloc(&pstConn->u8Semaphore, 1);

    return pstConn;
}

static void vConnectConnCbk(void* vConn)
{
    Sem_vPost(&((tstNetconn*)vConn)->u8Semaphore);
}

//static void vSetupTcpCbk(Tcp_tstPcb* pstPcb)
//{
//    /* Function called if connected successfully */
//    pstPcb->TCP_vConnectedCbk = vConnectConnCbk;
//}

void vConnectConn(tstNetconn *stConn, const tstIpAddr *stAddr, const uint16 u16Port)
{
    tenErr enErrRet = enNoErr;
    printf("4\n");
    switch (stConn->enConnType)
    {
        printf("5\n");
    case NETCONN_TCP:
        printf("6\n");
        /* Fill tcp callback */
        //vSetupTcpCbk(stConn->unPcb.pstTcp);
        /* The callback argument */
        stConn->unPcb.pstTcp->vCbkArg = (void*)stConn;
        /* Function called if connected successfully */
        stConn->unPcb.pstTcp->TCP_vConnectedCbk = vConnectConnCbk;
        /* vConnectConnCbk will be called if connected susccessfully */
        printf("8\n");
        enErrRet = Tcp_enConnect(stConn->unPcb.pstTcp, stAddr, u16Port);
        printf("Tcp_enConnect:%d\n", enErrRet);
        if (enErrRet == enNoErr)//Request to connect but not connected yet
        {
            /* Blocking style, wait here until connected successfully */
            uint16 u16WaitTime = Sem_u16Wait(&(stConn->u8Semaphore));
            printf("Wait time:%d\n", u16WaitTime);
        }
        else
        {
            ACE_DEBUG((LM_INFO, ACE_TEXT("Tcp connect fail\n")));
        }
        break;

    default:
        printf("7\n");
        break;
    }
}

tenErr enConnSend(tstNetconn *stConn, const uint8* pu8Data, uint16 u16Size, uint16 u16VectorCnt, uint8 u8Flags)
{
    tstConnVector stVector;
    stVector.vPtr = pu8Data;
    stVector.u16Len = u16Size;

    uint16 u16I;
    uint32 u32TotalSize = 0;
    for (u16I = 0; u16I < u16VectorCnt; u16I++)
    {
        /* TODO: check whether the u32Size is right or not? */
        u32TotalSize = u32TotalSize + u16Size;
    }
    Tcp_vWrite(stConn->unPcb.pstTcp, pu8Data, u16Size, u8Flags);
    return enNoErr;
}
