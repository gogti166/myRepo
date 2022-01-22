#include "type.h"
#include "thread.h"
#include "ace/streams.h"
#include "Interface.h"

/*****************************************************************
*                             code                               *
******************************************************************/
pcap_t *pSock;

#define ETHSOAD_RXBUFF_SIZE 200
uint8 au8TxBuf[ETHSOAD_RXBUFF_SIZE] = { 0 };

uint8 au8RecvData[1024] = { 0 };

uint8 au8Payload[FILE_READ_SIZE + 16] = { 0 };
uint8 au8RePayload[FILE_READ_SIZE + 16] = { 0 };

FOTA_tenTransferStatus u8CurrentStatus;

bool boHandShake = False;
bool boWaveHand = False;
bool boConnected = False;


uint32 u32Transmitted = 0;

Timer* clGeneralTimer;

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
uint32  u32Ack_seq = 0;
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
uint8   u8PsudHdrLen = 0;
uint8   u8StartEndMsgLen = 0; 
uint16   u16DataMsgLen = 0;

/*************************************
*       Section Initialization       *
**************************************/
PDU_tunCLU_24_200ms                    as_CLU_24_200ms = { 0 };

ETHSOAD_tstUDPSocket ETHSOAD_stUDPconfig[] =
{  
    { nenMsg_621, 0x00000621, ETHCOM_PDU_CLU_24_200ms_SIZE, (uint8*)&as_CLU_24_200ms, ETHSOAD_nenUnicast, "10.0.1.0", 51914, "10.0.0.128", 50721 },//CLU_24_200ms 21 app
};

uint32 u32Ipv4ToInt(const char* u8IpString)
{
    struct in_addr stAddr;
    inet_pton(AF_INET, u8IpString, (void *)&stAddr);
    return stAddr.s_addr;
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
    u8LinkHdrLen = sizeof(u8EthHdrLen);
    u8IpHdrLen = sizeof(Ip_tstHdr);
    u8TcpHdrLen = sizeof(Tcp_tstHdr);
    u8UdpHdrLen = sizeof(Udp_tstHdr);
    u8PsudHdrLen = sizeof(tstPsudHdr);
    
    u16DataMsgLen = sizeof(ETHTP_tstDataMsg);
    u8StartEndMsgLen = sizeof(ETHTP_tstStartEndMsg);
    u8CurrentStatus = FOTA_nenFirstStart;
}

uint16 u16UdpPayloadLen = 0;
uint16 u16UdpSrcPort;
uint16 u16UdpDstPort;


uint16 u16TcpUdpCheckSum(const uint8* u8buf, size_t size)
{
    uint32 u32checkSum = 0;
    size_t i;
    for (i = 0; i < size; i += 2)
    {
        uint16 u16first = (uint16)u8buf[i] << 8;
        uint16 u16second = (uint16)u8buf[i + 1] & 0x00ff;
        u32checkSum += u16first + u16second;
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
    return (uint16)~u32checkSum;
}

FILE* iFilefd = NULL;
uint32 u32PrgLength = 0;

uint32 u32CopyLength = FILE_READ_SIZE;
uint32 u32CurrentSize = FILE_READ_SIZE*DATA_COUNT;

uint16 vFillTcpPackage(ETHTP_tenDataType u8PshFLag)
{
    uint16 u16PayLoadLen = 0;
    static uint32 u32EndTransferredSize = 0;
    static uint32 u32EndCopyLength = 0;

    switch (u8PshFLag)
    {
    case ETHTP_nenAuth:{
        ETHTP_tstMsg* pBuffer = (ETHTP_tstMsg*)malloc(sizeof(ETHTP_tstMsg));
        memset(pBuffer, 0x00, sizeof(ETHTP_tstMsg));
        /* Authenticate */
        pBuffer->u32MessageID = 0;
        pBuffer->u32PayloadLength = 0;
        pBuffer->u32LeftOverMessage = 0;
        pBuffer->u16PayloadType = 0;
        pBuffer->u16Flags = htons(1);

        u16PayLoadLen = 16;
        u16Tot_len = u8IpHdrLen + u8TcpHdrLen + u16PayLoadLen;
        memcpy(au8Payload, pBuffer, sizeof(ETHTP_tstMsg));
        free(pBuffer);
        break;
    }

    case ETHTP_nenFirstStart:{
        /* variable initialization */
        iFilefd = NULL;
        u32PrgLength = 0;
        u32Transmitted = 0;
        u32CopyLength = FILE_READ_SIZE;
        u32EndTransferredSize = 0;
        u32EndCopyLength = 0;

        /* file operation */
        errno_t err;
        struct stat stFileSate;
        err = fopen_s(&iFilefd, FILE_PATH, "rb");
        if (err != 0)
        {
            printf("Open failed: can't find file in specified path.\n");
            exit(0);
        }
        stat(FILE_PATH, &stFileSate);
        u32PrgLength = stFileSate.st_size;
        printf("File size:%d Bytes\n", u32PrgLength);
        u32Portion = u32PrgLength / 100;
        u32CompletedPortion = u32Portion;

        /* data handling */
        ETHTP_tstStartEndMsg* pBuffer = (ETHTP_tstStartEndMsg*)malloc(sizeof(ETHTP_tstStartEndMsg));
        memset(pBuffer, 0x00, sizeof(ETHTP_tstStartEndMsg));

        pBuffer->u32MessageID = htonl(nenStartTriggerID);
        pBuffer->u32PayloadLength = htonl(sizeof(ETHTP_tstStartEndMsg) - 16);
        pBuffer->u32LeftOverMessage = 0;
        pBuffer->u16PayloadType = 0;
        pBuffer->u16Flags = 0;
        //memcpy(pBuffer->u8VersionInfo, au8Version, 8);        
        pBuffer->u32TotalSize = htonl(u32PrgLength);
        pBuffer->u32TransferredSize = 0;
        pBuffer->u32CurrentSize = 0;
        vUpdateProcess(u8Pi - 1);
        u16PayLoadLen = sizeof(ETHTP_tstStartEndMsg);
        u16Tot_len = u8IpHdrLen + u8TcpHdrLen + u16PayLoadLen;
        memcpy(au8Payload, pBuffer, sizeof(ETHTP_tstStartEndMsg));
        free(pBuffer);
        break;
    }

    case ETHTP_nenStart:{
        ETHTP_tstStartEndMsg* pBuffer = (ETHTP_tstStartEndMsg*)malloc(sizeof(ETHTP_tstStartEndMsg));
        memset(pBuffer, 0x00, sizeof(ETHTP_tstStartEndMsg));

        pBuffer->u32MessageID = htonl(nenStartTriggerID);
        pBuffer->u32PayloadLength = htonl(sizeof(ETHTP_tstStartEndMsg) - 16);
        pBuffer->u32LeftOverMessage = 0;
        pBuffer->u16PayloadType = 0;
        pBuffer->u16Flags = 0;
        //memcpy(pBuffer->u8VersionInfo, au8Version, 8);
        pBuffer->u32TotalSize = htonl(u32PrgLength);
        pBuffer->u32TransferredSize = htonl(u32Transmitted);

        /* Calculate currentSize for the last frame */
        if (u32Transmitted + u32CurrentSize > u32PrgLength)
        {
            /* Length of remaining data is less than "FILE_READ_SIZE*DATA_COUNT" */
            u32CurrentSize = u32PrgLength - u32Transmitted;
        }

        pBuffer->u32CurrentSize = htonl(u32CurrentSize);

        u16PayLoadLen = sizeof(ETHTP_tstStartEndMsg);
        u16Tot_len = u8IpHdrLen + u8TcpHdrLen + u16PayLoadLen;
        memcpy(au8Payload, pBuffer, sizeof(ETHTP_tstStartEndMsg));
        free(pBuffer);
        /* Used for end message. */
        u32EndTransferredSize = u32Transmitted;
        u32EndCopyLength = u32CurrentSize;
        break;
    }

    case ETHTP_nenData:{
        ETHTP_tstDataMsg* pBuffer = (ETHTP_tstDataMsg*)malloc(sizeof(ETHTP_tstDataMsg));
        memset(pBuffer, 0x00, sizeof(ETHTP_tstDataMsg));
        pBuffer->u32MessageID = htonl(nenDataTransferID);
        pBuffer->u32PayloadLength = htonl(u32CopyLength);
        pBuffer->u32LeftOverMessage = 0;
        pBuffer->u16PayloadType = 0;
        pBuffer->u16Flags = 0;
        memset(pBuffer->u8EthData, 0x00, FILE_READ_SIZE);
        u32CopyLength = fread(pBuffer->u8EthData, 1, FILE_READ_SIZE, iFilefd);
        u16PayLoadLen = u32CopyLength + 16;
        u16Tot_len = u8IpHdrLen + u8TcpHdrLen + u16PayLoadLen;
        memcpy(au8Payload, pBuffer, sizeof(ETHTP_tstDataMsg));
        free(pBuffer);
        /* It shows data size that have transmitted. */
        u32Transmitted = u32Transmitted + u32CopyLength;
		ACE_DEBUG((LM_INFO, ACE_TEXT("Data:%d\n"), u32Transmitted));
        if (u32Transmitted >= u32CompletedPortion)
        {
            u8Pi++;
            u32CompletedPortion = u8Pi*u32Portion;
            vUpdateProcess(u8Pi - 1);
        }
        /* Last remaining data which is less then FILE_READ_SIZE */
        if (u32Transmitted + FILE_READ_SIZE > u32PrgLength)
        {
            u32CopyLength = u32PrgLength - u32Transmitted;
        }
        break;
    }

    case ETHTP_nenEnd:{
        ETHTP_tstStartEndMsg* pBuffer = (ETHTP_tstStartEndMsg*)malloc(sizeof(ETHTP_tstStartEndMsg));
        memset(pBuffer, 0x00, sizeof(ETHTP_tstStartEndMsg));

        pBuffer->u32MessageID = htonl(nenEndTriggerID);
        pBuffer->u32PayloadLength = htonl(sizeof(ETHTP_tstStartEndMsg) - 16);
        pBuffer->u32LeftOverMessage = 0;
        pBuffer->u16PayloadType = 0;
        pBuffer->u16Flags = 0;

        //memcpy(pBuffer->u8VersionInfo, au8Version, 8);
        pBuffer->u32TotalSize = htonl(u32PrgLength);

        pBuffer->u32TransferredSize = htonl(u32EndTransferredSize);
        pBuffer->u32CurrentSize = htonl(u32EndCopyLength);

        u16PayLoadLen = sizeof(ETHTP_tstStartEndMsg);
        u16Tot_len = u8IpHdrLen + u8TcpHdrLen + u16PayLoadLen;
        memcpy(au8Payload, pBuffer, sizeof(ETHTP_tstStartEndMsg));
        free(pBuffer);

        if (u32Transmitted == u32PrgLength)
        {
            fclose(iFilefd);
            /* Notify the main task of data transmission done. */
            Term_Cond.signal();
        }
        break;
    }

    default:{
        printf("Package error\n");
    }
            break;
    }
    return u16PayLoadLen;
}

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

ACE_Thread_Mutex TcpMutex;
Tcp_tstAuth stAuth = { 0 };
uint8 u8UnackedNum = 0;
void vSendAuth()
{
    if ((boConnected == True) && (u8UnackedNum == 0))
    {
        TcpMutex.acquire();
        u8ACK = 1;
        u8PSH = 1;
        u8SYN = 0;
        uint16 u16Len = vFillTcpPackage(ETHTP_nenAuth);
        stAuth.u32Seq = u32Seq;
        memcpy(stAuth.u8Payload, au8Payload, u16Len);
        //vSendTcpMsg(pSock, au8Payload, u16Len);
        vSeqUpdate(0x10);
        TcpMutex.release();
    }
}

Tcp_tstPcb* pstLinkHead = (Tcp_tstPcb*)malloc(sizeof(Tcp_tstPcb));
Tcp_tstPcb* pstMovePointer = pstLinkHead;
uint32 u32LastSeq = 0;
uint32 u32CurrentSeq = 0;
bool boAuthHappen = False;
void vTcpDataTransfer()
{
    uint8 u8Cnt = 0;
    uint16 u16Len = 0;
    uint32 u32CurrentSeq = 0;
    Tcp_tstPcb* pstUnackedLink = NULL;
    TcpMutex.acquire();
    switch (u8CurrentStatus)
    {
    case FOTA_nenFirstStart:
        /* Send the first Start */
        u8ACK = 1;
        u8PSH = 1;
        u8SYN = 0;
        u16Len = vFillTcpPackage(ETHTP_nenFirstStart);
        //vSendTcpMsg(pSock, au8Payload, u16Len);
        vSeqUpdate(u16Len);
        u8CurrentStatus = FOTA_nenStart;
        break;

    case FOTA_nenStart:
        /* Send Start */
        u8ACK = 1;
        u8PSH = 1;
        u8SYN = 0;
        u16Len = vFillTcpPackage(ETHTP_nenStart);

        //vSendTcpMsg(pSock, au8Payload, u16Len);
        vSeqUpdate(u16Len);
        u8CurrentStatus = FOTA_nenData;
        break;

    case FOTA_nenData:
        /* Send Data */
        u8ACK = 1;
        u8PSH = 1;
        u8SYN = 0;
        pstMovePointer = pstLinkHead;
        /* The tcp send-windows shouldn't be greater than recv-windows */
        for (u8Cnt = 0; u8Cnt < DATA_COUNT; u8Cnt++)
        {
            u16Len = vFillTcpPackage(ETHTP_nenData);
            /* TCP segment is greater than MSS */
            if (u16Len > MSS)
            {
                uint16 u16Segment, u16SegmentLen;
                for (u16Segment = 1; u16Segment*MSS < u16Len + MSS; u16Segment++)
                {
                    u16SegmentLen = (u16Segment*MSS <= u16Len ? MSS : (u16Len % MSS));
                    u16Tot_len = u8IpHdrLen + u8TcpHdrLen + u16SegmentLen;
                    //vSendTcpMsg(pSock, au8Payload + (u16Segment - 1)*MSS, u16SegmentLen);
                    vSeqUpdate(u16SegmentLen);
                }
            }
            else
            {
                /* Save packages in unacked-list then send it out. */
                if ((pstUnackedLink = (Tcp_tstPcb*)malloc(sizeof(Tcp_tstPcb))) == NULL)
                {
                    ACE_DEBUG((LM_INFO, ACE_TEXT("LinkNode Fail\n")));
                }
                else
                {
                    pstUnackedLink->u32Seq = u32Seq;
                    memcpy((uint8*)&(pstUnackedLink->stEthDataMsg), au8Payload, u16Len);
                    pstMovePointer->next = pstUnackedLink;
                    pstMovePointer = pstUnackedLink;
                    u8UnackedNum++;
                    //vSendTcpMsg(pSock, au8Payload, u16Len);
                    vSeqUpdate(u16Len);
                    /* The last data may be less than 1040. */
                    if (u16Len != u16DataMsgLen)
                    {
                        u16DataMsgLen = u16Len;
                        break;
                    }
                }
            }
        }
        u32LastSeq = u32Seq;
        u8CurrentStatus = FOTA_nenEnd;
        break;

    case FOTA_nenReData:
        /* Resend data */
        u8ACK = 1;
        u8PSH = 1;
        u8SYN = 0;
        pstMovePointer = pstLinkHead->next;
        for (u8Cnt = 0; u8Cnt < u8UnackedNum; u8Cnt++)
        {
            u32CurrentSeq = u32Seq;
            /* Auth has sent before resend, we need to record the auth sequence for EndTrigger. */
            if (u32CurrentSeq - u32LastSeq == 16)
            {
                boAuthHappen = True;
            }
            u32Seq = pstMovePointer->u32Seq;
            /* Retrive package which still not be acked from unacked-list then resend it. */
            memset(au8RePayload, 0x00, sizeof(ETHTP_tstDataMsg));
            memcpy(au8RePayload, (uint8*)&(pstMovePointer->stEthDataMsg), sizeof(ETHTP_tstDataMsg));
            pstMovePointer = pstMovePointer->next;
            u16Tot_len = u8IpHdrLen + u8TcpHdrLen + u16DataMsgLen;
            //vSendTcpMsg(pSock, au8RePayload, sizeof(ETHTP_tstDataMsg));
            vSeqUpdate(sizeof(ETHTP_tstDataMsg));
        }
        u8CurrentStatus = FOTA_nenEnd;
        break;

    case FOTA_nenEnd:
        /* Send End */
        u8ACK = 1;
        u8PSH = 1;
        u8SYN = 0;
        u16Len = vFillTcpPackage(ETHTP_nenEnd);
        if (boAuthHappen == True)
        {
            u32Seq = u32Seq + 16;
            boAuthHappen = False;
        }
        //vSendTcpMsg(pSock, au8Payload, u16Len);
        vSeqUpdate(u16Len);
        /* The next start will be triggered by Ethcc message(0x00000621), see vUdpHandler. */
        u8CurrentStatus = FOTA_nenIdle;
        break;

    default:
        /* No handling for idle state */
        break;
    }
    TcpMutex.release();
}

void vTcpHandler(uint8* u8Data, uint32 u32Len)
{
    /* |ACK|PSH|RST|SYN|FIN| */
    uint8 u8ControlFlag = (*(u8Data + 13)) & 0xFF;
    Tcp_tstHdr* pstTcpHeader = (Tcp_tstHdr*)u8Data;
    static bool boFirstStart = False;
    static uint8 u8Unack = 0;
    static uint32 u32TempSeq = 0;
    switch (u8ControlFlag)
    {
    case 0x12: /*10010:ACK+SYN, 2rd handshake from server*/
        if (boHandShake)
        {
            /* The 3rd handshake */
            u8ACK = 1;
            u8PSH = 0;
            u8SYN = 0;
            u8FIN = 0;
            /* got a SYN from server(cluster) */
            u32Ack_seq = ntohl(pstTcpHeader->u32Seq) + 1;
            /* respond ACK */
            //vSendTcpMsg(pSock, NULL, 0);
            /* Handshake done, connection has been established. */
            boHandShake = False;
            boConnected = True;
            vSeqUpdate(0);
            printf("Connected\n");
        }
        /* After connection, send authentication cyclically after 100ms. */
        clGeneralTimer->Timer_vStart(Timer_nenCycle2000ms, 100, 2000, 0);
        break;

    case 0x18:/*11000:ACK+PSH*/
        /* Received 16bytes from cluster, it's actually always 00 00...02 */
        u32Ack_seq = u32Ack_seq + 0x10;
        /* If no following data, should respond ACK */
        u8ACK = 1;
        u8SYN = 0;
        /* respond ACK */
        //vSendTcpMsg(pSock, NULL, 0);
        vSeqUpdate(0);
        break;

    case 0x10:/*10000:ACK*/
        if (boWaveHand == False)
        {
            if (boFirstStart == False)
            {
                u8CurrentStatus = FOTA_nenFirstStart;
                boFirstStart = True;
            }
            /* There are some packages which never be acked. */
            if (u8UnackedNum > 0)
            {
                uint8 u8Cnt = 0;
                Tcp_tstPcb* pstDeLink = pstLinkHead->next;
                Tcp_tstPcb* pstTempDeLink = pstDeLink;
                /* Delete packages which have been acked by cluster from unacked-list. */
                for (u8Cnt = 0; u8Cnt < u8UnackedNum; u8Cnt++)
                {
                    if (pstDeLink->u32Seq + u16DataMsgLen <= ntohl(pstTcpHeader->u32AckSeq))
                    {
                        pstTempDeLink = pstDeLink;
                        pstDeLink = pstDeLink->next;
                        pstLinkHead->next = pstDeLink;
                        free(pstTempDeLink);
                    }
                    else
                    {
                        break;
                    }
                }
                u8UnackedNum = u8UnackedNum - u8Cnt;
				ACE_DEBUG((LM_INFO, ACE_TEXT("ACK:%d\n"), ntohl(pstTcpHeader->u32AckSeq)));
                /* If always receive a message with the same ack-number for 3 times. */
                if (u32TempSeq == ntohl(pstTcpHeader->u32AckSeq))
                {
                    u8Unack++;
                }
                else
                {
                    u8Unack = 0;
                }
                u32TempSeq = ntohl(pstTcpHeader->u32AckSeq);
                /* The TCP package may lost, we have to resend. */
                if (u8Unack > 3)
                {
					u8CurrentStatus = FOTA_nenReData;
                    vTcpDataTransfer();
                    u8Unack = 0;
                }
            }
            /* All sent-packages have been acked, we can send the next frame. */
            if (u8UnackedNum == 0)
            {
                vTcpDataTransfer();
            }
        }
        break;

    case 0x04: /*00100:RST*/
    case 0x14:
    {
        pcap_close(pSock);
        printf("RST\n");
    }
    break;

    case 0x19:
    {
        u32Ack_seq = ntohl(pstTcpHeader->u32Seq) + 1;
        u8ACK = 1;
        u8SYN = 0;
        u8PSH = 0;
        u8FIN = 0;
        u16Tot_len = u8IpHdrLen + u8TcpHdrLen;
        /* respond ACK */
        //vSendTcpMsg(pSock, NULL, 0);
        vSeqUpdate(0);
        printf("Disconnected\n");
        boWaveHand = False;
        boConnected = False;
    }
    break;

    default:
        //printf("Flag:%02X\n",u8ControlFlag);
        break;
    }
}

/*************************************
*         Section UDP handling       *
**************************************/
void vUdpHandler(uint8* u8Data, uint32 u32Len)
{
    uint32 u32PduId = 0;
    uint32 u32PduLen = 0;
    static uint32 u32TempValue = 0;
    static bool boError = False;

    ETHIL_tstPDUInfoType* pBuffer = (ETHIL_tstPDUInfoType*)u8Data;
    u32PduId = ntohl(pBuffer->EthSoAd_u32PDUId);
    u32PduLen = ntohl(pBuffer->EthSoAd_u32PduLen);

    /* Thes first 8bytes consist of "PduID" and "PduLen". */
    if (u32PduLen != u32Len - PDU_HEADER_LEN)
    {
        printf("Data miss\n");
        return;
    }

    switch (u32PduId)
    {  
    case 0x00000301:
    case 0x00000621:
    {
        memcpy(as_CLU_24_200ms.pdu, u8Data + PDU_HEADER_LEN, u32PduLen);
        if ((as_CLU_24_200ms.ETHCOM_stPduCLU_24_200ms.CLU_UpdateCurrentSize == u32Transmitted) &&
            (u32TempValue != u32Transmitted))
        {
            /* Only once inspite of cyclic ethcc message. */
            u32TempValue = u32Transmitted;
            u8CurrentStatus = FOTA_nenStart;
            vTcpDataTransfer();
        }

        if ((as_CLU_24_200ms.ETHCOM_stPduCLU_24_200ms.CLU_UpdateDataTransferError == 1)
            && (boError == False))
        {
            boError = True;
            printf("E:%d\n", as_CLU_24_200ms.ETHCOM_stPduCLU_24_200ms.CLU_ErrorCode);
        }

        break;
    }

    default:
    {
        //printf("Unknow message\n");
        break;
    }
    }
}








/* Create a buffer to hold the whole package. */
tstPbuf* pstCreatePackage(Pbuf_tenLayer enLayer, uint16 u16DataLen)
{
    tstPbuf *pstPbuf = NULL;
    uint16 u16LayerLen = (uint16)enLayer;

    pstPbuf = (tstPbuf*)malloc(sizeof(tstPbuf) + u16LayerLen + u16DataLen);
    memset(pstPbuf, 0x00, sizeof(tstPbuf) + u16LayerLen + u16DataLen);

    pstPbuf->u8Payload = (uint8*)pstPbuf + sizeof(tstPbuf) + u16LayerLen;
    /* We still not fill anything into payload. */
    pstPbuf->u16FillLen = 0;
    return pstPbuf;
}

void vRecvTcpMsg(Tcp_tstPcb *pstPcb, tstPbuf *pstPbuf)
{

}

void vRequestConnect()
{
    Tcp_tstPcb* stClientPcb = NULL;
    tstPbuf *pstPbuf = NULL;

    /* The Pcb will be responsible for this communication. */    
    stClientPcb = (Tcp_tstPcb*)malloc(sizeof(Tcp_tstPcb));
    stClientPcb->u16LocalPort = TCP_SOUR_PORT;
    stClientPcb->u16RemotePort = TCP_DEST_PORT;
    stClientPcb->u8TcpFlags = TCP_SYN;
    stClientPcb->u8IpProto = IPPROTO_TCP;
    stClientPcb->u32LocalIp = u32Ipv4ToInt(LOCAL_IP);
    stClientPcb->u32RemoteIp = u32Ipv4ToInt(REMOTE_IP);
    stClientPcb->pFp = pSock;

    pstPbuf = pstCreatePackage(PBUF_TRANSPORT, 0);
    vSendTcpMsg(stClientPcb, pstPbuf);
    /* We are now in a state that SYN has been sent. */
    stClientPcb->enState = SYN_SENT;
}

void vRequestDisconnect()
{
    if (boConnected == True)
    {
        u8ACK = 1;
        u8PSH = 0;
        u8SYN = 0;
        u8FIN = 1;
        u16Tot_len = u8IpHdrLen + u8TcpHdrLen;
        /* Send only SYN */
        //vSendTcpMsg(pSock, NULL, 0);
        /* Increase 1 for FIN. */
        vSeqUpdate(1);
        boWaveHand = True;
        //printf("Request Disconnection\n");
    }
    else
    {
        printf("Never connected\n");
    }
}

int main(int argc, char* argv[])
{
#ifdef FU_TEST
    iCard = *argv[1] - '0';
    printf("%d\n", iCard);
#endif

    ACE_OSTREAM_TYPE *output = new std::ofstream("log.txt");
    ACE_LOG_MSG->msg_ostream(output, 1);
    ACE_LOG_MSG->set_flags(ACE_Log_Msg::OSTREAM);
    ACE_LOG_MSG->clr_flags(ACE_Log_Msg::STDERR | ACE_Log_Msg::LOGGER);

    pSock = pGetRawSocket();
    vInit();
    EventLoop_Tsk* EventLoop = new EventLoop_Tsk();
    TcpHandle_Tsk* TcpHandle = new TcpHandle_Tsk();
    UdpHandle_Tsk* UdpHandle = new UdpHandle_Tsk();
    Recv_Tsk*  RecvHandle = new Recv_Tsk(TcpHandle, UdpHandle, pSock);

    clkStart = clock();
    EventLoop->open();
    RecvHandle->open();
    TcpHandle->open();
    UdpHandle->open();

    clGeneralTimer = new Timer();
    vRequestConnect();

    Term_Cond.wait();
    printf("Update complete\n");
    /* Disconnect with cluster */
    vRequestDisconnect();
	while(boConnected);
    /* Close all task */
    //RecvHandle->close();
    //TcpHandle->close();
    //UdpHandle->close();
    //EventLoop->close();
    /* Wait for all tasks to quit. */
    Sleep(100);
    pcap_close(pSock);
    clkFinish = clock();
    uint32 u32Duration = (uint32)(clkFinish - clkStart) / CLOCKS_PER_SEC;
    printf("Spent:%dsec\n", u32Duration);
    return 0;
}