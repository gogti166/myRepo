#ifndef __API_H__
#define __API_H__

#include "cdef.h"
#include "tcp.h"

#define NETCONN_COPY        0x01
#define NETCONN_MORE        0x02
#define NETCONN_DONTBLOCK   0x04

typedef enum
{
    NETCONN_TCP = 0x10,
}tenConnType;

typedef struct
{
    union
    {
        Tcp_tstPcb* pstTcp;
    }unPcb;

    /* used to synchronously execute functions */
    uint8 u8Semaphore;//op_completed
    int iSocket;
    tenConnType enConnType;

}tstNetconn;

typedef struct
{
    const void* vPtr;
    uint16  u16Len;
}tstConnVector;

#endif