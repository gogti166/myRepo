#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <ace/OS.h>
#include <ace/Thread.h>

#include "thread.h"
#include "timer.h"

//#include <sys/stat.h>
//#include <errno.h>
//#include "ace/Message_Block.h"
//

#include "config.h"
#include "cdef.h"
#include "err.h"

using namespace std;
/*****************************************************************
*                             cdef                               *
******************************************************************/
#define     False     0x00
#define     True      0x01

#define     BLOCK     True
#define     UNBLOCK   False

#define     MAX_VALUE(x, y)   (((x) > (y)) ? (x) : (y))
#define     MIN_VALUE(x, y)   (((x) < (y)) ? (x) : (y))


#define     BYTE_LEN  1024
#define     HEX       16

///* | PduId(4Bytes) | PduLength(4Bytes) | PduData | */
//#define PDU_HEADER_LEN      8

/*****************************************************************
*                             ethernet                           *
******************************************************************/
/* This pseudo header is used to calculate TCP/UDP checksum */
typedef struct psudhdr
{
    uint32 u32SrcIP;
    uint32 u32DstIP;
    uint16 u16Zero : 8;
    uint16 u16Proto : 8;
    uint16 u16TotLen;
}tstPsudHdr;

typedef struct stPackageBuf
{
    uint8 *u8Payload;
    /* Length of ETH+IP+TCP(UDP)+DATA */
    uint16 u16Len;
}tstPbuf;

//typedef enum ETHSOAD_enSocCastType
//{
//    /** No cast mechanism for TCP. */
//    ETHSOAD_nenNone = 0,
//
//    /** UDP Unicast. */
//    ETHSOAD_nenUnicast,
//
//    /** UDP Multicast. */
//    ETHSOAD_nenMulticast,
//
//    /** UDP Broadcast. */
//    ETHSOAD_nenBroadcast
//}ETHSOAD_tenSocCastType;


/******************************************************************
*                              Fota                               *
*******************************************************************/
typedef enum
{
    ETHTP_nenAuth,
    ETHTP_nenFirstStart,
    ETHTP_nenStart,
    ETHTP_nenData,
    ETHTP_nenEnd
}ETHTP_tenDataType;

/* Differ from DataType above , this is for statemachine. */
typedef enum
{
    FOTA_nenAuth,
    FOTA_nenFirstStart,
    FOTA_nenStart,
    FOTA_nenData,
    FOTA_nenReData,
    FOTA_nenEnd,
    FOTA_nenIdle
}FOTA_tenTransferStatus;

/* Ethtp header */
typedef struct ETHTP_stMsg
{
    uint32      u32MessageID;
    uint32      u32PayloadLength;
    uint32      u32LeftOverMessage;
    uint16      u16PayloadType;
    uint16      u16Flags;
}ETHTP_tstMsg;

/* TP header format, see Hyundai ES96595-05, chapter 10 */
typedef struct ETHTP_stStartEndMsg
{
    uint32      u32MessageID;
    uint32      u32PayloadLength;
    uint32      u32LeftOverMessage;
    uint16      u16PayloadType;
    uint16      u16Flags;
    //uint8       u8VersionInfo[8];
    uint32      u32TotalSize;
    uint32      u32TransferredSize;
    uint32      u32CurrentSize;
}ETHTP_tstStartEndMsg;

/* enum and structure */
enum FOTA__enEthTPMsgID
{
    nenStartTriggerID = 0x0000uL,   /** Start trigger message id */
    nenDataTransferID = 0x0100uL,   /** Data transfer message id */
    nenEndTriggerID = 0x0200uL      /** End trigger message id */
};
typedef enum FOTA__enEthTPMsgID FOTA__tenEthTPMsgID;

typedef struct ETHSOAD_tstPduInfoType
{
    /*PDU Id*/
    uint32 EthSoAd_u32PDUId;
    /*length of PDU in bytes */
    uint32 EthSoAd_u32PduLen;
    /*pointer to the PDU payload*/
    //uint8* EthSoAd__pu8PduDataPtr;
}ETHIL_tstPDUInfoType;


#define PBUF_LINK_ENCAPSULATION_HLEN  0 //NO vlan
#define PBUF_LINK_HLEN                14 
#define PBUF_IP_HLEN                  20
#define PBUF_TCP_HLEN                 20
#define PBUF_UDP_HLEN                 8

typedef enum
{
    PBUF_TCP = PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN + PBUF_IP_HLEN + PBUF_TCP_HLEN,//PBUF_TRANSPORT
    PBUF_UDP = PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN + PBUF_IP_HLEN + PBUF_UDP_HLEN,
    PBUF_IP = PBUF_LINK_ENCAPSULATION_HLEN + PBUF_LINK_HLEN + PBUF_IP_HLEN,
}Pbuf_tenLayer;

typedef enum
{
    PBUF_RAM,
    PBUF_REF,
}Pbuf_tenType;

typedef struct TCP_stAuth
{
    uint32 u32Seq;
    uint8  u8Payload[16];
}Tcp_tstAuth;

typedef enum
{
    nenERR_NoError = 0x00u,
    nenERR_NoRespToUpdateStart = 0x04u,
    nenERR_StartMsg_Missing = 0x05u,
    nenERR_StartMsg_NewVersion = 0x06u,
    nenERR_StartMsg_NewTotalSize = 0x07u,
    nenERR_DataOverSize = 0x08u,
    nenERR_DataUnderSize = 0x09u,
    nenERR_EndMsg_Timeout = 0x0Au,
    nenERR_EndMsg_MismatchVersion = 0x0B,
    nenERR_EndMsg_MismatchTotalSize = 0x0C,
    nenERR_EndMsg_MismatchStartAddr = 0x0D,
    nenERR_EndMsg_MismatchLength = 0x0Eu,
    nenERR_StopByIGNOff = 0x10u,
    nenERR_DataTransfer_Timeout = 0x11u,
    nenERR_SW_WrongFormat = 0x13u,
    nenERR_GcSignVerifyFailed = 0x16u,
    nenERR_MCU_EraseFail = 0x1A,
    nenERR_MCU_FlashFail = 0x1D
}FOTA__tenErrorCode;

/******************************************************************
*                              PDU                                *
*******************************************************************/
/*========= PDU CLU_24_200ms-Tx ==========*/
//#define ETHCOM_PDU_CLU_24_200ms_SIZE  (0x10)
//typedef union
//{
//    /* User messages */
//    struct  {
//        uint64 CLU_Crc24Val : 16;
//        uint64 CLU_AlvCnt24Val : 8;
//        uint64 CLU_ErrorCode : 6;
//        uint64 CLU_UpdateDataTransferError : 1;
//        uint64 CLU_UpdateCondition_Crank : 2;
//        uint64 CLU_UpdateCondition_PPositon : 2;
//        uint64 CLU_UpdateCondition_ParkBrake : 2;
//        uint64 CLU_UpdateCondition_Lamp : 2;
//        uint64 CLU_UpdateCondition_Hood : 2;
//        uint64 unused41 : 23;
//        uint64 CLU_UpdateTotalSize : 32;
//        uint64 CLU_UpdateCurrentSize : 32;
//    }ETHCOM_stPduCLU_24_200ms;
//    /* Byte array */
//    uint8 pdu[ETHCOM_PDU_CLU_24_200ms_SIZE];
//}PDU_tunCLU_24_200ms;


/******************************************************************
*                       data defination                           *
*******************************************************************/

//typedef enum
//{
//    nenMsg_621,
//    nenMsg_Max
//}ETHSOAD_tenArrMsgID;

//typedef struct ETHSOAD_stUDPSocket
//{
//    ETHSOAD_tenArrMsgID enArrayId;
//
//    uint32                  u32PduId;
//    uint32                  u32PduLength;
//    uint8*                  u8pPduDataPtr;
//
//    ETHSOAD_tenSocCastType  enSocCastType;
//    string      strDestIPAddr;
//    uint16      u16DestPortNum;
//    string      strSrcIPAddr;
//    uint16      u16SrcPortNum;
//}ETHSOAD_tstUDPSocket;

/******************************************************************
*                           Function                              *
*******************************************************************/
void vInit();

//typedef struct Tcp_stPcb Tcp_tstPcb;
uint16 u16TcpUdpCheckSum(uint8*, uint8*, uint8*, uint16);
void vSeqUpdate(uint16 u16DataLen);

//uint16 vFillTcpPackage(ETHTP_tenDataType u8PshFLag);
//uint16 vFillUdpPackage(ETHSOAD_tenArrMsgID enArrId);
void vSendAuth();
/* This function is used to send TCP message, if u8Buffer is NULL, send only TCP header without payload. */
void vTcpOutputPackage(pcap_t* ifd, uint8* u8Buffer, uint16 u16DataLen);
void vSendUdpMsg(pcap_t* ifd, uint8* u8Buffer, uint16 u16DataLen);
void vTcpHandler(uint8* u8Data, uint32 u32Len);
void vUdpHandler(uint8* u8Data, uint32 u32Len);

void vUpdateProcess(uint8);

uint32 u32Ipv4ToInt(const char*);
void vMacToInt(const char*, uint8*);

tstPbuf* pstCreatePbuf(Pbuf_tenLayer, uint16, Pbuf_tenType);

/*****************************************************************
*                             code                               *
******************************************************************/
extern pcap_t *pSock;

//#define ETHSOAD_RXBUFF_SIZE 200
//extern uint8 au8TxBuf[ETHSOAD_RXBUFF_SIZE];

extern uint8 au8RecvData[1024];
extern uint8 au8Payload[FILE_READ_SIZE + 16];

extern FOTA_tenTransferStatus u8CurrentStatus;

extern bool boHandShake;
extern bool boFullUpdate;

extern uint8 au8Version[8];

/* Time */
extern clock_t clkStart;
extern clock_t clkFinish;

/**********************
ip content
***********************/
extern uint16  u16Tot_len;
extern uint8   u8UppLayerProto;//protocol in transport layer
extern uint32  u32DestIpAddr;


/**********************
tcp content
***********************/
extern uint32  u32Seq;
extern uint32  u32AckSeq;
extern uint8   u8ACK;
extern uint8   u8SYN;
extern uint8   u8PSH;
extern uint8   u8FIN;

/**********************
common content
***********************/
extern uint8   u8EthHdrLen;
extern uint8   u8EthVhdrLen;
extern uint8   u8IpHdrLen;
extern uint8   u8TcpHdrLen;
extern uint8   u8UdpHdrLen;
extern uint8   u8PsudHdrLen;

/**********************
from part
***********************/
extern uint32 u32PrgLength;
/*****************************************************************
*                            test                                *
******************************************************************/
//extern PDU_tunCLU_24_200ms       as_CLU_24_200ms;
//extern ETHSOAD_tstUDPSocket      ETHSOAD_stUDPconfig[];

typedef enum
{
    TEST_NoStartCheck,
    TEST_StartVersionCheck,
    TEST_StartTotalSizeCheck,
    TEST_EndVersionCheck,
    TEST_EndTotalSizeCheck,
    TEST_EndTransferredSizeCheck,
    TEST_EndCurrentSizeCheck,
    TEST_OverSizeCheck,
    TEST_UnderSizeCheck,
    TEST_EndTimeOut,
    TEST_NoCheck,
}TEST_tenCheckItem;

//typedef enum
//{
//	ERR_OK = 0,
//}tenErr;
//extern Timer* UptTimer;

#define FULL_UPDATE
#endif