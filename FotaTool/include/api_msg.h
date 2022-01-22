#ifndef __API_MSG_H__
#define __API_MSG_H__

#include "cdef.h"
#include "tcp.h"
#include "api.h"
#include "ip_addr.h"



/****************************************
          function definition
*****************************************/
tstNetconn *pstAllocConn(tenConnType enType);
void vConnectConn(tstNetconn *stConn, const tstIpAddr *stAddr, const uint16 u16Port);
tenErr enConnSend(tstNetconn *stConn, const uint8* pu8Data, uint16 u16Size, uint16 u16VectorCnt, uint8 u8Flags);
#endif