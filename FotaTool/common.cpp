#include "common.h"
#include "interface.h"
#include "tcp.h"
#include "udp.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "timer.h"
#include "ace/streams.h"



/*****************************************************************
*                             code                               *
******************************************************************/
pcap_t *pSock;

//Timer *ComTimer;

//#define ETHSOAD_RXBUFF_SIZE 200
//uint8 au8TxBuf[ETHSOAD_RXBUFF_SIZE] = { 0 };

uint8 au8RecvData[1024] = { 0 };

uint8 au8Payload[FILE_READ_SIZE + 16] = { 0 };
uint8 au8RePayload[FILE_READ_SIZE + 16] = { 0 };

FOTA_tenTransferStatus u8CurrentStatus;

bool boHandShake = False;
bool boWaveHand = False;



//uint32 u32Transmitted = 0;

//Timer* UptTimer;

//uint8 au8Version[8] = { 0 };

/* Display process as percentage format */
uint32 u32Portion = 0;
uint32 u32CompletedPortion = 0;
uint8 u8Pi = 1;

/* Time */
clock_t clkStart;
clock_t clkFinish;

ACE_Thread_Mutex    Term_Mutex;
ACE_Condition_Thread_Mutex Term_Cond(Term_Mutex);

/**********************
ip content
***********************/
uint16  u16Tot_len = 0;
uint8   u8UppLayerProto = 0;//protocol in transport layer
uint32  u32DestIpAddr = 0;


/**********************
tcp content
***********************/
uint32  u32Seq = 0;
uint32  u32AckSeq = 0;
uint8   u8TcpGetFlags = 0;
uint8   u8ACK = 0;
uint8   u8SYN = 0;
uint8   u8PSH = 0;
uint8   u8FIN = 0;

/**********************
common content
***********************/
uint8   u8EthHdrLen = 0;
uint8   u8EthVhdrLen = 0;
uint8   u8IpHdrLen = 0;
uint8   u8TcpHdrLen = 0;
uint8   u8UdpHdrLen = 0;
uint8   u8PsudHdrLen = 0;//12
uint8   u8StartEndMsgLen = 0; 
uint16   u16DataMsgLen = 0;

/*************************************
*       Section Initialization       *
**************************************/
//PDU_tunCLU_24_200ms                    as_CLU_24_200ms = { 0 };

//ETHSOAD_tstUDPSocket ETHSOAD_stUDPconfig[] =
//{  
//    { nenMsg_621, 0x00000621, ETHCOM_PDU_CLU_24_200ms_SIZE, (uint8*)&as_CLU_24_200ms, ETHSOAD_nenUnicast, "10.0.1.0", 51914, "10.0.0.128", 50721 },//CLU_24_200ms 21 app
//};

uint32 u32Ipv4ToInt(const char* u8IpString)
{
    struct in_addr stAddr;
    ACE_OS::inet_pton(AF_INET, u8IpString, (void *)&stAddr);
    return stAddr.s_addr;
}

void vMacToInt(const char* chPtr, uint8* u8Pa)
{
    uint8 u8I = 0;
    uint8 u8DecValue = 0;
    uint8 u8HexValue = 0;
    uint8 u8HexNo = 0;
    uint8 u8Ai = 0;
    for (u8I = 0; u8I < 17; u8I++)
    {
        /* Between '0'and '9' */
        if ((chPtr[u8I] > 47) && (chPtr[u8I] < 58))
        {
            u8DecValue = (chPtr[u8I] - 48)*(HEX >> (u8HexNo * 4));
            u8HexValue = u8HexValue + u8DecValue;
            u8HexNo++;
        }
        /* Between 'A' and 'F' */
        else if ((chPtr[u8I] > 64) && (chPtr[u8I] < 71))
        {
            u8DecValue = (chPtr[u8I] - 65 + 0xA)*(HEX >> (u8HexNo * 4));
            u8HexValue = u8HexValue + u8DecValue;
            u8HexNo++;
        }
        /* Between 'a' and 'f' */
        else if ((chPtr[u8I] > 96) && (chPtr[u8I] < 103))
        {
            u8DecValue = (chPtr[u8I] - 97 + 0xa)*(HEX >> (u8HexNo * 4));
            u8HexValue = u8HexValue + u8DecValue;
            u8HexNo++;
        }
        else
        {
            /* Maybe '-' or ':', skip it */
        }
        if (u8HexNo == 2)
        {
            u8Pa[u8Ai] = u8HexValue;
            u8Ai++;
            u8HexNo = 0;
            u8DecValue = 0;
            u8HexValue = 0;
        }
    }
}

#define ProcessBarLength 50
void vUpdateProcess(uint8 u8Percent)
{
    uint8 u8I;
    putchar('[');
    for (u8I = 1; u8I <= ProcessBarLength; ++u8I)
    {
        putchar(u8I * 100 <= u8Percent*ProcessBarLength ? '>' : ' ');
    }
    putchar(']');
    printf("%3d%%", u8Percent);
    for (u8I = 0; u8I != ProcessBarLength + 6; ++u8I)
    {
        putchar('\b');
    }
}

void vInit()
{
    /* ACE DEBUG */
    ACE_OSTREAM_TYPE *output = new std::ofstream("log.txt");
    ACE_LOG_MSG->msg_ostream(output, 1);
    ACE_LOG_MSG->set_flags(ACE_Log_Msg::OSTREAM);
    ACE_LOG_MSG->clr_flags(ACE_Log_Msg::STDERR | ACE_Log_Msg::LOGGER);
    /* Header length */
    u8EthHdrLen = sizeof(Eth_tstHdr);
    u8IpHdrLen = sizeof(Ip_tstHdr);
    u8TcpHdrLen = sizeof(Tcp_tstHdr);
    u8UdpHdrLen = sizeof(Udp_tstHdr);
    u8PsudHdrLen = sizeof(tstPsudHdr);
    u8StartEndMsgLen = sizeof(ETHTP_tstStartEndMsg);
    u8CurrentStatus = FOTA_nenFirstStart;
    /* Pcap handler */
    pSock = Pcap_pGetSock();
    /* Create ACE task */
    EventLoop_Tsk* EventLoop = new EventLoop_Tsk();
    Handle_Tsk* Handler = new Handle_Tsk();
    Recv_Tsk*  RecvHandle = new Recv_Tsk(Handler, pSock);
    EventLoop->open();
    RecvHandle->open();
    Handler->open();
    printf("Task run\n");
}

uint16 u16UdpPayloadLen = 0;
uint16 u16UdpSrcPort;
uint16 u16UdpDstPort;

/* u32Length = OptionLen + DataLen */
uint16 u16TcpUdpCheckSum(uint8* u8Pcb, uint8 *u8Hdr, uint8 *u8Data, uint16 u16DataLen)
{
    Ip_tstPcb *pstPcb = (Ip_tstPcb*)u8Pcb;
    uint8 u8HdrLen = 0;
    if (pstPcb->u8IpProto == IPPROTO_TCP)
    {
        u8HdrLen = u8TcpHdrLen;
    }
    else
    {
        u8HdrLen = u8UdpHdrLen;
    }

    tstPsudHdr* pstPseudoHdr = (tstPsudHdr*)malloc(u8PsudHdrLen);
    memset(pstPseudoHdr, 0x00, u8PsudHdrLen);
    if (pstPseudoHdr == NULL)
    {
        ACE_DEBUG((LM_INFO, ACE_TEXT("Cksum fail\n")));
    }

    pstPseudoHdr->u32SrcIP = pstPcb->u32LocalIp;
    pstPseudoHdr->u32DstIP = pstPcb->u32RemoteIp;
    pstPseudoHdr->u16Zero = 0;
    pstPseudoHdr->u16Proto = pstPcb->u8IpProto;
    
    uint16 u16PseudoPayloadLen = (uint16)u8HdrLen + u16DataLen;
    uint16 u16TotalLen = u16PseudoPayloadLen + u8PsudHdrLen;

    pstPseudoHdr->u16TotLen = htons(u16PseudoPayloadLen);
    uint8* u8SumBuf = (uint8*)malloc(u16TotalLen + 1);
    memset(u8SumBuf, 0x00, u16TotalLen + 1);
    memcpy(u8SumBuf, pstPseudoHdr, u8PsudHdrLen);
    memcpy(u8SumBuf + u8PsudHdrLen, u8Hdr, u8HdrLen);
    memcpy(u8SumBuf + u8PsudHdrLen + u8HdrLen, u8Data, u16DataLen);
    uint32 u32checkSum = 0;
    uint16 u16I;
    for (u16I = 0; u16I < u16TotalLen; u16I += 2)
    {
        uint16 u16first = (uint16)u8SumBuf[u16I] << 8;
        uint16 u16second = (uint16)u8SumBuf[u16I + 1] & 0x00ff;
        u32checkSum += (uint32)(u16first + u16second);       
    }
    while (1)
    {
        uint16 u16c = (u32checkSum >> 16);
        if (u16c > 0)
        {
            u32checkSum = (u32checkSum << 16) >> 16;
            u32checkSum += u16c;
        }
        else
        {
            break;
        }
    }
    free(pstPseudoHdr);
    free(u8SumBuf);
    return (uint16)~u32checkSum;
}

FILE* iFilefd = NULL;
uint32 u32PrgLength = 0;

uint32 u32CopyLength = FILE_READ_SIZE;
uint32 u32CurrentSize = FILE_READ_SIZE*DATA_COUNT;

//uint16 vFillTcpPackage(ETHTP_tenDataType u8PshFLag)
//{
//    uint16 u16PayLoadLen = 0;
//    static uint32 u32EndTransferredSize = 0;
//    static uint32 u32EndCopyLength = 0;
//
//    switch (u8PshFLag)
//    {
//    case ETHTP_nenAuth:{
//        ETHTP_tstMsg* pBuffer = (ETHTP_tstMsg*)malloc(sizeof(ETHTP_tstMsg));
//        memset(pBuffer, 0x00, sizeof(ETHTP_tstMsg));
//        /* Authenticate */
//        pBuffer->u32MessageID = 0;
//        pBuffer->u32PayloadLength = 0;
//        pBuffer->u32LeftOverMessage = 0;
//        pBuffer->u16PayloadType = 0;
//        pBuffer->u16Flags = htons(1);
//
//        u16PayLoadLen = 16;
//        u16Tot_len = u8IpHdrLen + u8TcpHdrLen + u16PayLoadLen;
//        memcpy(au8Payload, pBuffer, sizeof(ETHTP_tstMsg));
//        free(pBuffer);
//        break;
//    }
//
//    case ETHTP_nenFirstStart:{
//        /* variable initialization */
//        iFilefd = NULL;
//        u32PrgLength = 0;
//        u32Transmitted = 0;
//        u32CopyLength = FILE_READ_SIZE;
//        u32EndTransferredSize = 0;
//        u32EndCopyLength = 0;
//
//        /* file operation */
//        errno_t err;
//        struct stat stFileSate;
//        err = fopen_s(&iFilefd, FILE_PATH, "rb");
//        if (err != 0)
//        {
//            printf("Open failed: can't find file in specified path.\n");
//            exit(0);
//        }
//        stat(FILE_PATH, &stFileSate);
//        u32PrgLength = stFileSate.st_size;
//        printf("File size:%d Bytes\n", u32PrgLength);
//        u32Portion = u32PrgLength / 100;
//        u32CompletedPortion = u32Portion;
//
//        /* data handling */
//        ETHTP_tstStartEndMsg* pBuffer = (ETHTP_tstStartEndMsg*)malloc(sizeof(ETHTP_tstStartEndMsg));
//        memset(pBuffer, 0x00, sizeof(ETHTP_tstStartEndMsg));
//
//        pBuffer->u32MessageID = htonl(nenStartTriggerID);
//        pBuffer->u32PayloadLength = htonl(sizeof(ETHTP_tstStartEndMsg) - 16);
//        pBuffer->u32LeftOverMessage = 0;
//        pBuffer->u16PayloadType = 0;
//        pBuffer->u16Flags = 0;
//        //memcpy(pBuffer->u8VersionInfo, au8Version, 8);        
//        pBuffer->u32TotalSize = htonl(u32PrgLength);
//        pBuffer->u32TransferredSize = 0;
//        pBuffer->u32CurrentSize = 0;
//        vUpdateProcess(u8Pi - 1);
//        u16PayLoadLen = sizeof(ETHTP_tstStartEndMsg);
//        u16Tot_len = u8IpHdrLen + u8TcpHdrLen + u16PayLoadLen;
//        memcpy(au8Payload, pBuffer, sizeof(ETHTP_tstStartEndMsg));
//        free(pBuffer);
//        break;
//    }
//
//    case ETHTP_nenStart:{
//        ETHTP_tstStartEndMsg* pBuffer = (ETHTP_tstStartEndMsg*)malloc(sizeof(ETHTP_tstStartEndMsg));
//        memset(pBuffer, 0x00, sizeof(ETHTP_tstStartEndMsg));
//
//        pBuffer->u32MessageID = htonl(nenStartTriggerID);
//        pBuffer->u32PayloadLength = htonl(sizeof(ETHTP_tstStartEndMsg) - 16);
//        pBuffer->u32LeftOverMessage = 0;
//        pBuffer->u16PayloadType = 0;
//        pBuffer->u16Flags = 0;
//        //memcpy(pBuffer->u8VersionInfo, au8Version, 8);
//        pBuffer->u32TotalSize = htonl(u32PrgLength);
//        pBuffer->u32TransferredSize = htonl(u32Transmitted);
//
//        /* Calculate currentSize for the last frame */
//        if (u32Transmitted + u32CurrentSize > u32PrgLength)
//        {
//            /* Length of remaining data is less than "FILE_READ_SIZE*DATA_COUNT" */
//            u32CurrentSize = u32PrgLength - u32Transmitted;
//        }
//
//        pBuffer->u32CurrentSize = htonl(u32CurrentSize);
//
//        u16PayLoadLen = sizeof(ETHTP_tstStartEndMsg);
//        u16Tot_len = u8IpHdrLen + u8TcpHdrLen + u16PayLoadLen;
//        memcpy(au8Payload, pBuffer, sizeof(ETHTP_tstStartEndMsg));
//        free(pBuffer);
//        /* Used for end message. */
//        u32EndTransferredSize = u32Transmitted;
//        u32EndCopyLength = u32CurrentSize;
//        break;
//    }
//
//    case ETHTP_nenData:{
//        ETHTP_tstDataMsg* pBuffer = (ETHTP_tstDataMsg*)malloc(sizeof(ETHTP_tstDataMsg));
//        memset(pBuffer, 0x00, sizeof(ETHTP_tstDataMsg));
//        pBuffer->u32MessageID = htonl(nenDataTransferID);
//        pBuffer->u32PayloadLength = htonl(u32CopyLength);
//        pBuffer->u32LeftOverMessage = 0;
//        pBuffer->u16PayloadType = 0;
//        pBuffer->u16Flags = 0;
//        memset(pBuffer->u8EthData, 0x00, FILE_READ_SIZE);
//        u32CopyLength = fread(pBuffer->u8EthData, 1, FILE_READ_SIZE, iFilefd);
//        u16PayLoadLen = u32CopyLength + 16;
//        u16Tot_len = u8IpHdrLen + u8TcpHdrLen + u16PayLoadLen;
//        memcpy(au8Payload, pBuffer, sizeof(ETHTP_tstDataMsg));
//        free(pBuffer);
//        /* It shows data size that have transmitted. */
//        u32Transmitted = u32Transmitted + u32CopyLength;
//		ACE_DEBUG((LM_INFO, ACE_TEXT("Data:%d\n"), u32Transmitted));
//        if (u32Transmitted >= u32CompletedPortion)
//        {
//            u8Pi++;
//            u32CompletedPortion = u8Pi*u32Portion;
//            vUpdateProcess(u8Pi - 1);
//        }
//        /* Last remaining data which is less then FILE_READ_SIZE */
//        if (u32Transmitted + FILE_READ_SIZE > u32PrgLength)
//        {
//            u32CopyLength = u32PrgLength - u32Transmitted;
//        }
//        break;
//    }
//
//    case ETHTP_nenEnd:{
//        ETHTP_tstStartEndMsg* pBuffer = (ETHTP_tstStartEndMsg*)malloc(sizeof(ETHTP_tstStartEndMsg));
//        memset(pBuffer, 0x00, sizeof(ETHTP_tstStartEndMsg));
//
//        pBuffer->u32MessageID = htonl(nenEndTriggerID);
//        pBuffer->u32PayloadLength = htonl(sizeof(ETHTP_tstStartEndMsg) - 16);
//        pBuffer->u32LeftOverMessage = 0;
//        pBuffer->u16PayloadType = 0;
//        pBuffer->u16Flags = 0;
//
//        //memcpy(pBuffer->u8VersionInfo, au8Version, 8);
//        pBuffer->u32TotalSize = htonl(u32PrgLength);
//
//        pBuffer->u32TransferredSize = htonl(u32EndTransferredSize);
//        pBuffer->u32CurrentSize = htonl(u32EndCopyLength);
//
//        u16PayLoadLen = sizeof(ETHTP_tstStartEndMsg);
//        u16Tot_len = u8IpHdrLen + u8TcpHdrLen + u16PayLoadLen;
//        memcpy(au8Payload, pBuffer, sizeof(ETHTP_tstStartEndMsg));
//        free(pBuffer);
//
//        if (u32Transmitted == u32PrgLength)
//        {
//            fclose(iFilefd);
//            /* Notify the main task of data transmission done. */
//            Term_Cond.signal();
//        }
//        break;
//    }
//
//    default:{
//        printf("Package error\n");
//    }
//            break;
//    }
//    return u16PayLoadLen;
//}

void vSeqUpdate(uint16 u16DataLen)
{
    if ((uint32)0xFFFFFFFF - u32Seq < (uint32)u16DataLen)
    {
        u32Seq = ((uint32)u16DataLen - (0xFFFFFFFF - u32Seq)) - 1;//include 0
    }
    else
    {
        u32Seq = u32Seq + (uint32)u16DataLen;
    }
}

tstPbuf* pstCreatePbuf(Pbuf_tenLayer enLayer, uint16 u16DataLen, Pbuf_tenType enType)
{
    tstPbuf *pstPbuf = NULL;
    uint16 u16LayerLen = (uint16)enLayer;
    switch (enType)
    {
    case PBUF_COPY:
        if ((pstPbuf = (tstPbuf*)malloc(sizeof(tstPbuf) + u16LayerLen + u16DataLen)) == NULL)
        {
            ACE_DEBUG((LM_INFO, ACE_TEXT("Pbuf copy\n")));
            return NULL;
        }
        else
        {
            memset(pstPbuf, 0x00, sizeof(tstPbuf) + u16LayerLen + u16DataLen);
            /* Payload points to data part. */
            pstPbuf->u8Payload = (uint8*)pstPbuf + sizeof(tstPbuf) + u16LayerLen;
            /* We didn't fill anything into Pbuf. */
            pstPbuf->u16Len = 0;
        }
        break;

    case PBUF_REF:
        if ((pstPbuf = (tstPbuf*)malloc(sizeof(tstPbuf))) == NULL)
        {
            ACE_DEBUG((LM_INFO, ACE_TEXT("Pbuf refer\n")));
            return pstPbuf;
        }
        else
        {
            memset(pstPbuf, 0x00, sizeof(tstPbuf));
            /* Payload points to data part. */
            pstPbuf->u8Payload = NULL;
            /* We didn't fill anything into Pbuf. */
            pstPbuf->u16Len = 0;
        }
        break;

    default:
        ACE_DEBUG((LM_INFO, ACE_TEXT("Pbuf\n")));
        break;
    }
    return pstPbuf;
}

//void vFreePbuf(tstPbuf *pstPbuf)
//{
//    free();
//}