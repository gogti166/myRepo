#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <vector>

#include <sys/stat.h>
#include <errno.h>

#include <WS2tcpip.h>

#include "ace/Task.h"
#include "ace/OS.h"
#include "ace/Message_Block.h"
#include "ace/Thread.h"
#include "ace/Semaphore.h"

#include <ace/Select_Reactor.h>

#include <pcap.h>

#include "config.h"

using namespace std;


/*****************************************************************
*                             cdef                               *
******************************************************************/
#define     False     0x00
#define     True      0x01

#define     BLOCK     True
#define     UNBLOCK   False

//typedef unsigned char        bool;
typedef unsigned char        uint8;
typedef unsigned short       uint16;
typedef unsigned int         uint32;
typedef unsigned long long   uint64;

/* | PduId(4Bytes) | PduLength(4Bytes) | PduData | */
#define PDU_HEADER_LEN      8

/*****************************************************************
*                             ethernet                           *
******************************************************************/


#define ETH_ALEN 6

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
*                           Function                              *
*******************************************************************/
void vInit();
void vSeqUpdate(uint16 u16DataLen);

//uint16 vFillTcpPackage(ETHTP_tenDataType u8PshFLag);
//uint16 vFillUdpPackage(ETHSOAD_tenArrMsgID enArrId);
void vSendAuth();
/* This function is used to send TCP message, if u8Buffer is NULL, send only TCP header without payload. */
void vSendTcpMsg(pcap_t* ifd, uint8* u8Buffer, uint16 u16DataLen);
void vSendUdpMsg(pcap_t* ifd, uint8* u8Buffer, uint16 u16DataLen);
void vTcpHandler(uint8* u8Data, uint32 u32Len);
//void vUdpHandler(uint8* u8Data, uint32 u32Len);
/* This function is used to request the first handshake. */
void vRequestConnect();


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
extern uint32  u32Ack_seq;
extern uint8   u8ACK;
extern uint8   u8SYN;
extern uint8   u8PSH;
extern uint8   u8FIN;

/**********************
common content
***********************/
extern uint8   u8LinkHdrLen;
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

typedef enum
{
    Timer_nenCycle200ms,
    Timer_nenCycle2000ms,
    nenTimer_Number
}Timer_tenCycle;

typedef struct
{
    long   lTimeHandle;
    uint8  u8TimeId;
    bool   boStart;
    /*uint32 u32Delay;
    uint32 u32Interval;*/
}tstTimer;

//extern Timer* clGeneralTimer;

#define FULL_UPDATE