#include "cdef.h"
#include "common.h"
#include "tcp.h"
#include "timer.h"
#include "fota_tool.h"

void Tool_vFullUpdate(Tcp_tstPcb* stCliPcb)
{  
    FILE* Fd = NULL;
    uint32 u32FileLen = 0;
    uint32 u32ReadLen = 0;
    uint32 u32Transmitted = 0;
    uint8  u8EthData[SEND_BUFFER_SZIE] = { 0 };
    uint8* pBuffer = u8EthData;
    bool boTrigSend = False;

    //Tcp_tstPcb* stCliPcb = Tcp_vConnect();
    //while (!(stCliPcb->enExtState == CONNECTED));
    
    /* Open the prg file for transmission */
    if (fopen_s(&Fd, FILE_PATH, "rb") != 0)
    {
        printf("Open failed: can't find file in specified path.\n");
        exit(0);
    }
    else
    {
        struct stat stFileSate;
        stat(FILE_PATH, &stFileSate);
        u32FileLen = stFileSate.st_size;
        printf("File size:%d Bytes\n", u32FileLen);
    }

    /* Start transmission */
    clkStart = clock();
    while (u32Transmitted < u32FileLen)
    { 
        if (stCliPcb->u16BuffSize > 0)
        {
            /* Fill buffer */
            memset(pBuffer, 0x00, SEND_BUFFER_SZIE);
            u32ReadLen = fread(pBuffer, 1, SEND_BUFFER_SZIE, Fd);
            /* Write to TCP buffer and send. */
            Tcp_vWrite(stCliPcb, (uint8*)pBuffer, SEND_BUFFER_SZIE, 0);
            u32Transmitted = u32Transmitted + u32ReadLen;
            if (boTrigSend == False)
            {
                printf("Triger Send\n");
                Tcp_vOutputSeg(stCliPcb);
                boTrigSend = True;
            }
        }
    }    
    clkFinish = clock();
    uint32 u32Duration = (uint32)(clkFinish - clkStart) / CLOCKS_PER_SEC;
    printf("\nSpent:%dsec\n", u32Duration);

}
