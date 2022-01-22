#ifndef __TCP_H__
#define __TCP_H__

#include "cdef.h"
#include "common.h"
#include "ace/Semaphore.h"
#include "ip_addr.h"


#define   TCP_FLAGS     0x3fU
#define   INITIAL_MSS   536
#define   MSS           1460

#define   TCP_WND    (4*INITIAL_MSS)

#define TCP_HLEN    20
#define SND_WINDOW  32*1024

/* Flags for "apiflags" parameter in tcp_write */
#define TCP_WRITE_FLAG_COPY 0x01
#define TCP_WRITE_FLAG_MORE 0x02

struct Tcp_stPcb;
//typedef void(*TCP_vConnectedCbk)(void *vArg, struct Tcp_stPcb *pstpcb, tenErr enErr);
typedef void(*TCP_tvConnectedCbk)(void* vArg);

typedef struct  
{
    uint16 u16Src;
    uint16 u16Dst;
    uint32 u32Seq;
    uint32 u32AckSeq;
    uint16 u16Reserve;
    uint16 u16Window;
    uint16 u16Check;
    uint16 u16UrgPtr;
}Tcp_tstHdr;

typedef enum
{
    SYN_SENT,
    ESTABLISHED,
	FIN_WAIT_1,
	FIN_WAIT_2,
    /* Wait for close of current connection */
    CLOSE_WAIT,
}Tcp_tenState;

typedef enum
{
    DEFAULT,
    CONNECTED,
}Tcp_tenExtState;

typedef struct Tcp_stSeg
{
    struct Tcp_stSeg *next;
    /* tcp sequence */
    uint32 u32Seq;
    tstPbuf *pstPbuf;
    /* tcp header */
    Tcp_tstHdr *pstTcphdr;
    /* tcp data */
    uint8 *pu8DataPtr;
    /* Length of tcp data */
    uint16 u16DataLen;
}Tcp_tstSeg;

/* Package control block */
typedef struct Tcp_stPcb
{
    pcap_t *pSock;
    uint32 u32LocalIp;
    uint32 u32RemoteIp;
    uint8 u8TtL;
    uint8 u8IpProto;

    struct Tcp_stPcb *next;
    
    uint16 u16LocalPort;
    uint16 u16RemotePort;

    Tcp_tenState enState;
    Tcp_tenExtState enExtState;

#define DEFAULT     0x00U
#define ACK_NOW     0x02U

    uint8 u8TcpCtrlFlags;

#define TCP_FIN 0x01U
#define TCP_SYN 0x02U
#define TCP_RST 0x04U
#define TCP_PSH 0x08U
#define TCP_ACK 0x10U
#define TCP_URG 0x20U
#define TCP_ECE 0x40U
#define TCP_CWR 0x80U

    uint8 u8TcpOutFlags;
    uint8 u8TcpInFlags;

    uint32 u32AckSeq;//LastAck
    uint32 u32SendNxt;//snd_nxt

    uint32 u32BuffSeq;//u32SndLbb;
    /* Available buffer space for sending (in bytes). */
    uint16 u16BuffSize;//snd_buf

    uint16 u16Mss;

    uint32 u32RecvNxt;

    uint16 u16Thresh;
    uint16 u16SendWnd;
    uint16 u16CgstWnd;/* Congestion windows */

	/* fast retransmit/recovery */
	uint8 u8DupAcks;

    Tcp_tstSeg* pstUnsendFront;
    Tcp_tstSeg* pstUnsendRear;

    Tcp_tstSeg* pstUnackedFront;
    Tcp_tstSeg* pstUnackedRear;

    //tstPbuf *pstActivePbuf;

    /* package sequence */
    uint32 u32Seq;//addw dont' need

    uint16 u16QueueLen;
    /* actual package */
    //ETHTP_stDataMsg  stEthDataMsg;

    void* vCbkArg;
    TCP_tvConnectedCbk TCP_vConnectedCbk;

}Tcp_tstPcb;

extern Tcp_tstPcb  *pstActivePcbs;

#define API_SOCKET

Tcp_tstPcb *Tcp_pstAllocPcb();
void vFreeSegment(Tcp_tstSeg*);
/* This function is used to create a Tcp header. */
Tcp_tstHdr* Tcp_pstFormatHeader(Tcp_tstPcb*, tstPbuf*, uint8, uint32);

#ifndef API_SOCKET
Tcp_tstPcb *Tcp_vConnect(TCP_vConnectedCbk vConnectCbk);
#else
tenErr Tcp_enConnect(Tcp_tstPcb* stPcb, const tstIpAddr *stIpAddr, const uint16 u16Port);
#endif

/* This function is used to write user data into a 32KB buffer. */
void Tcp_vWrite(Tcp_tstPcb *pstPcb, const uint8 *u8Data, uint16 u16TotalDataLen, uint8 u8Flags);
void Tcp_vOutputSeg(Tcp_tstPcb*);
void Tcp_vInputSeg(tstPbuf*);
void Tcp_vProcess(Tcp_tstPcb*);
void Tcp_vReceive(Tcp_tstPcb*);
/* This function is used to split an intact segment. */
void Tcp_vSplitSeg(Tcp_tstPcb*, uint16);
/*output*/
void Tcp_vSendEmptyAck(Tcp_tstPcb*);
Tcp_tstSeg *Tcp_pstCreateSeg(Tcp_tstPcb*, tstPbuf*, uint8, uint32);

void TCP_vClose();
void TCP_vSendFin(Tcp_tstPcb *pstPcb);
#endif