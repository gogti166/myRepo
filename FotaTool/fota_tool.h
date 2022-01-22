#ifndef __FOTA_TOOL_H__
#define __FOTA_TOOL_H__

#include "cdef.h"
#include "udp.h"

using namespace std;

/* | PduId(4Bytes) | PduLength(4Bytes) | PduData | */
#define PDU_HEADER_LEN      8

#define SEND_BUFFER_SZIE 1024*32

void Tool_vFullUpdate(void);

#endif