/*****************************************************************
*                          configuration                         *
******************************************************************/
#define FULL_UPDATE
/* file */
#ifdef FULL_UPDATE
#define     FILE_PATH   FILE_PATH_90M

#define     FILE_PATH_250K        "D:\\Project\\MyFotaTool_FU\\Path\\250K.bin"
#define     FILE_PATH_6M        "D:\\Project\\MyFotaTool_FU\\Path\\6M.bin"
#define     FILE_PATH_30M        "D:\\Project\\MyFotaTool_FU\\Path\\30M.bin"
#define     FILE_PATH_90M        "D:\\Project\\MyFotaTool_FU\\Path\\90M.bin"
#else
#define     FILE_PATH        "D:\\Project\\MyFotaTool_FU\\Path\\error.bin" 
#endif

/* Exclude header. */
#define   FILE_READ_SIZE    1024

/* Data bytes in one frame, example 28K per transmission;
but don't exceed 32, see the cluster's recv-windows. */
#define   DATA_COUNT  32

/* ethcc */
#define   UDP_SOUR_PORT    0xC06F
#define   UDP_DEST_PORT    0xCACB
                        
#define   MULTICAST_IP     "239.0.1.128"

/* These two ports are used for ETHTP */
#define   TCP_SOUR_PORT    53131 
#define   TCP_DEST_PORT    53136

            
/* Don't configure VLAN in PC */
#define  VLAN_PRIO        0
#define  VLAN_CFI         0
#define  VLAN_VID         129

#define  VLAN_LEN         0
//#define FU_TEST


/**************************************
			  REMOTE CONFIG
***************************************/
#define WORK_STATION
//#define ASUS_WIRELESS
/* network */
#ifdef WORK_STATION
#define   REMOTE_MAC		"B4-69-21-9B-74-D6"
#define   REMOTE_IP			"192.168.10.8"
#elif defined  ASUS_WIRELESS
#define   REMOTE_MAC		"78-92-9C-06-74-08" //ASUS
#define   REMOTE_IP			"192.168.10.13"
#else
#define   REMOTE_MAC		"E0-19-54-6D-FE-3E" //ZTE
#define   REMOTE_IP			"192.168.1.5"
#endif

/**************************************
			  LOCAL CONFIG
***************************************/
#define WIRELESS
/* Don't configed to be the same as
the ip get by "ipconfig/all". */
#ifdef WIRELESS
#define   LOCAL_IP			"192.168.10.5"
#define   LOCAL_MAC			"A8-93-4A-30-03-89"
#else
#define   LOCAL_IP			"192.168.1.8"
#define   LOCAL_MAC			"F8-E4-3B-77-C1-E5"
#endif