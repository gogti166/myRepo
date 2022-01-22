#include "cdef.h"
#include "socket.h"
#include "api_msg.h"

static tstSocket stSockets[SOCKETS_NUM];

static tstSocket* stGetSock(int iFd)
{
    tstSocket* stRet = NULL;
    if ((iFd < 0) || (iFd >= SOCKETS_NUM))
    {
        ACE_DEBUG((LM_INFO, ACE_TEXT("Socket out of range\n")));
    }
    else
    {
        stRet = &stSockets[iFd];
    }
    return stRet;
}

static int iAllocSock(tstNetconn* pstInConn)
{
    int iSock = 0;
    int i = 0;
    /* Loop to find a free socket */
    for (i = 0; i < SOCKETS_NUM; i++)
    {
        /* The socket is not allocated, so can be used */
        if (stSockets[i].pstConn == NULL)
        {
            stSockets[i].pstConn = pstInConn;
            break;
        }
    }
    /* Loop done but find no any free socket */
    if (i == SOCKETS_NUM)
    {
        i = -1;
    }
    return i;
}

int iSocket(int iDomain, int iType, int iProtocol)
{
    tstNetconn* pstConn = NULL;
    int iRet = 0;

    switch (iType)
    {
    case SOCK_STREAM://TCP
        pstConn = pstAllocConn(NETCONN_TCP);
        break;

    default:
        break;
    }

    if (pstConn == NULL)
    {
        ACE_DEBUG((LM_INFO, ACE_TEXT("Socket fail\n")));
        iRet = -1;
    }
    else
    {
        /* Bind the conn to allocated socket */
        iRet = iAllocSock(pstConn);
    }
    return iRet;
}

int iConnect(int iSock, const tstSockAddr* stSockAddr , const uint32 u32AddrLen)
{
    int iRet;
    tstSocket* stSock = NULL;
    /* Get socket structure by socket descriptor */
    stSock = stGetSock(iSock);
    if (stSock == NULL)
    {
        iRet = -1;
        printf("iConnect:%d\n", iRet);
    }
    else
    {
        printf("1\n");
        if (stSockAddr->sa_u8family == AF_INET)//IPV4
        {
            tstSockAddrIn* stSockIn = (tstSockAddrIn*)stSockAddr;
            tstIp4Addr stRemoteAddr = (tstIp4Addr)stSockIn->sin_stAddr;
            uint16 u16RemotePort = stSockIn->sin_u16Port;
            printf("2\n");
            vConnectConn(stSock->pstConn, &stRemoteAddr, u16RemotePort);
            printf("3\n");
        }
    }
    return 0;
}

int iSendto(int iSock)
{
    tstSocket* stSock = NULL;
    int iRet;

    stSock = stGetSock(iSock);
    if (stSock == NULL)
    {
        iRet = -1;
        printf("iSendto:%d\n", iRet);
    }
    return 0;
}

static 

int iSend(int iSock, const uint8* pu8Data, uint16 u16Size, int iFlags)
{
    tstSocket* stSock = NULL;
    int iRet;
    uint8 u8WriteFlags = 0x00;

    stSock = stGetSock(iSock);
    if (stSock == NULL)
    {
        iRet = -1;
        printf("iSend:%d\n", iRet);
    }
    else
    {
        /* Don't use sendto if TCP, because TCP use connected socket */
        if (stSock->pstConn->enConnType != NETCONN_TCP)
        {
            /* Sendto function can be used by a unconnected socket like UDP */
            //iSendto(iSock);
        }
        else
        {
            u8WriteFlags = NETCONN_COPY;
            enConnSend(stSock->pstConn, pu8Data, u16Size, 1, u8WriteFlags);
        }
    }
    return 0;
}

//tenErr enConnSend(tstNetconn *stConn, const void* vpstData, uint32 u32Size);

int iWrite(int iSock, const uint8* pu8Data, uint16 u16Size)
{
    int iRet = iSend(iSock, pu8Data, u16Size, 0);
    return iRet;
}