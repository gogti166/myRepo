#ifndef __SOCKET_H__
#define __SOCKET_H__

#define SOCK_STREAM     1
#define SOCK_DGRAM      2
#define SOCK_RAW        3

#define SOCKETS_NUM     10

#include "ip_addr.h"
#include "api_msg.h"


#define MSG_MORE       0x10    /* Sender will send more */

typedef struct a
{
    tstNetconn* pstConn;
}tstSocket;

typedef struct
{
    /* AF_INET, AF_INET6, AF_UNSPEC */
    sa_family_t  sa_u8family;
    /* IP address + port */
    uint8        sa_u8data[14];//see tstSockAddr_In
}tstSockAddr;

typedef struct
{
    /* AF_INET, AF_INET6, AF_UNSPEC */
    sa_family_t     sin_u8family;
    /* Port */
    uint16          sin_u16Port;
    /* IP address */
    tstIpAddr       sin_stAddr;
    /* Not use, just use as a complement */
    uint8           sin_u8Zero[8];
}tstSockAddrIn;

int iSocket(int iDomain, int iType, int iProtocol);
int iConnect(int iSock, const tstSockAddr* stSockAddr, const uint32 u32AddrLen);

#endif