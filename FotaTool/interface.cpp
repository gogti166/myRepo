#include "cdef.h"
#include "config.h"
#include "interface.h"

pcap_t* Pcap_pGetSock()
{
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    pcap_t *pfp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int inum;
    int i = 0;

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        printf("Error in pcap_findalldevs : %s\n", errbuf);
        exit(1);
    }
    for (dev = alldevs; dev; dev = dev->next)
    {
#ifndef FU_TEST
        printf("%d. %s", ++i, dev->name);
        if (dev->description)
            printf(" (%s)\n", dev->description);
        else
            printf(" (No description available)\n");
#endif
    }
#ifdef FU_TEST
    inum = iCard;
#else
    printf("Enter the interface number (1-%d):", i);
    //scanf_s("%d", &inum);
	inum = 5;
#endif
    /* get selected adapter */
    for (dev = alldevs, i = 0; i< inum - 1; dev = dev->next, i++);
    /* open device */
    if ((pfp = pcap_open_live(dev->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1, errbuf)) == NULL)
    {
        fprintf(stderr, "\nUnable to open the adapter, not supported by WinPcap\n");
        pcap_freealldevs(alldevs);
        exit(1);
    }
    /*Possible regulation:
    "src port 6245  or src port 49263"
    "host 10.0.0.128 or host 239.0.1.128"
    */
    char u8Filter[] = "src host 255.255.255.255 and src host 255.255.255.255 or src host 255.255.255.255";
    memset(u8Filter, 0x00, sizeof(u8Filter));
    uint32 u32Netmask;
    struct bpf_program stCode;

    sprintf_s(u8Filter, "src host %s and dst host %s or src host %s", REMOTE_IP, LOCAL_IP, MULTICAST_IP);
    /* get the netmask, used at compiling the filter */
    if (dev->addresses != NULL)
        u32Netmask = ((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
    else
        u32Netmask = 0xffffff;	/* 255.255.255.0 */

    /* compile the filter */
    if (pcap_compile(pfp, &stCode, u8Filter, 1, u32Netmask) < 0)
    {
        printf("Filter compile err\n");
        pcap_freealldevs(alldevs);
        exit(-1);
    }

    /* set the filter */
    if (pcap_setfilter(pfp, &stCode) < 0)
    {
        printf("Filetr err\n");
        pcap_freealldevs(alldevs);
        exit(-1);
    }
    pcap_freealldevs(alldevs);
    return pfp;
}

int32 Pcap_vRecv(pcap_t* pfp, const uint8** chBuf)
{
    struct pcap_pkthdr *pstHeader;
    int res = 0;
    int32 i32Len = 0;
    if ((res = pcap_next_ex(pfp, &pstHeader, chBuf)) != 1)
    {
        if (res == 0)
        {
            i32Len = 0;
        }
        else
        {
            i32Len = -1;
        }
    }
    else
    {
        i32Len = pstHeader->len; 
    }
    return i32Len;
}

void Pcap_vSend(pcap_t* pfp, uint8* u8Data, uint16 u16DataLen)
{
    uint8 u8Ret = 0;
    u8Ret = pcap_sendpacket(pfp, u8Data, u16DataLen);
    if (u8Ret != 0)
    {
        printf("Pcap:%d-%02X-%d\n", u8Ret, *u8Data, u16DataLen);
        fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(pfp));
    }
}
