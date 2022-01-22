#include <pcap.h>
#include "cdef.h"

pcap_t* Pcap_pGetSock();
int32 Pcap_vRecv(pcap_t*, const uint8**);
void Pcap_vSend(pcap_t*, uint8*, uint16);