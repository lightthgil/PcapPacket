#ifndef __PCAP_PACKET_H__
#define __PCAP_PACKET_H__

extern const char *c_LogPacketFileDir;

#ifndef PCAP_FILE_HEADER_MAGIC
#define PCAP_FILE_HEADER_MAGIC 0xa1b2c3d4
#endif /* PCAP_FILE_HEADER_MAGIC */
#ifndef PCAP_FILE_HEADER_VERSION_MAJOR
#define PCAP_FILE_HEADER_VERSION_MAJOR 2
#endif /* PCAP_FILE_HEADER_VERSION_MAJOR */
#ifndef PCAP_FILE_HEADER_VERSION_MINOR
#define PCAP_FILE_HEADER_VERSION_MINOR 4
#endif /* PCAP_FILE_HEADER_VERSION_MINOR */
#ifndef PCAP_FILE_HEADER_LEN_NOT_LIMIT
#define PCAP_FILE_HEADER_LEN_NOT_LIMIT 65535
#endif /* PCAP_FILE_HEADER_LEN_NOT_LIMIT */

typedef enum _PcapLinkType
{
	PcapLinkType_BSD = 0,
	PcapLinkType_Ethernet = 1,
	PcapLinkType_TokenRing = 6,
	PcapLinkType_ARCnet = 7,
	PcapLinkType_SLIP = 8,
	PcapLinkType_PPP = 9,
	PcapLinkType_FDDI = 10,
	PcapLinkType_LlcOrSnapEncapsulatedATM = 100,
	PcapLinkType_RawIP = 101,
	PcapLinkType_BsdOrOssLIP = 102,
	PcapLinkType_BsdOrOssPPP = 103,
	PcapLinkType_CiscoHDLC = 104,
	PcapLinkType_802_11 = 105,
	PcapLinkType_LaterOpenBSDLoopbackDevices = 108,
	PcapLinkType_SpecialLinuxCookedCapture = 113,
	PcapLinkType_LocalTalk = 114
}PcapLinkType;

typedef struct _PcapFileHeader
{
	ULONG magic;	/* magic number ,The magic number has the value hex a1b2c3d4. */
	USHORT version_major;	/* major version number,The major version number should have the value 2 */
	USHORT version_minor;	/* minor version number,The minor version number should have the value 4 */
	ULONG timezone;	/* time zone offset field that actually not used, so you can (and probably should) just make it 0 */
	ULONG sigfigs;	/* time stamp accuracy field tha not actually used,so you can (and probably should) just make it 0 */
	ULONG snaplen;	/* snapshot length" field;The snapshot length field should
                      	   be the maximum number of bytes perpacket that will
                      	   be captured. If the entire packet is captured, make
                      	   it 65535; if you only capture, for example, the first 64 bytes of the packet, make it 64. */
    ULONG linktype;	/* link layer type field.The link-layer type depends on the type of link-layer header that the
                           packets in the capture file have:
                           0          BSD       loopback devices, except for later OpenBSD
                           1          Ethernet, and Linux loopback devices
                           6          802.5 Token Ring
                           7          ARCnet
                           8          SLIP
                           9          PPP
                           10         FDDI
                           100        LLC/SNAP-encapsulated ATM
                           101        raw IP, with no link
                           102        BSD/OS SLIP
                           103        BSD/OS PPP
                           104        Cisco HDLC
                           105        802.11
                           108        later OpenBSD loopback devices (with the AF_value in network byte order)
                           113        special Linux cooked capture
                           114        LocalTalk */
}PcapFileHeader;

typedef struct _PcapTime
{
	ULONG GMTtime;	/* a UNIX-format time-in-seconds when the packet was
                           captured, i.e. the number of seconds since January
                           1,1970, 00:00:00 GMT (that GMT, *NOT* local time!) */
	ULONG microTime;	/* the number of microseconds since that second when the packet was captured */
}PcapTime;

typedef struct _PcapPacketHeader
{
	PcapTime timeSpec;	/* a time stamp */
	ULONG caplen;	/* the number of bytes of packet data that were captured */
	ULONG len;		/* the actual length of the packet, in bytes (which may
                           be greater than the previous number, if you are not saving the entire packet) */
}PcapPacketHeader;

#ifndef LOG_PACKET_FILE_DIR
#define LOG_PACKET_FILE_DIR CBString(c_LogPacketFileDir)
#endif /* LOG_PACKET_FILE_DIR */
#ifndef LOG_PACKET_FILE_NAME
#define LOG_PACKET_FILE_NAME (LOG_PACKET_FILE_DIR + "capture.pcap")
#endif
#ifndef LOG_PACKET_MAX_NUM
#define LOG_PACKET_MAX_NUM	BIT16			/* 64K个 */
#endif /* LOG_PACKET_MAX_NUM */
#ifndef LOG_PACKET_MAX_FILE_BYTES
#define LOG_PACKET_MAX_FILE_BYTES	BIT22	/* 8M,可容纳1024字节的包4K个，64字节的包64K个*/
#endif /* LOG_PACKET_MAX_FILE_BYTES */

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN                         6
#endif /* ETHER_ADDR_LEN */


#define ETHTYPE_FAST_ETH (65000)		/* 快速以太报文(业务板与主控之间交互)的以太网类型定义为自定义的65000 */
#define ETHYTPE_BCM2CPU_PTP	(65001)		/* BCM提到CPU的PTP报文 */
#define ETHTYPE_DEBUG_STRING (65002)	/* 调试命令 */

typedef struct pcap_eth_header
{
	BYTE dst[ETHER_ADDR_LEN];
	BYTE src[ETHER_ADDR_LEN];
	USHORT type;
}PCAP_ETH_HEADER;

class PcapPacket
{
public:
	PcapPacket(CBString fileName = LOG_PACKET_FILE_NAME, ULONG maxPacketNum = LOG_PACKET_MAX_NUM, ULONG64 maxFileByte = LOG_PACKET_MAX_FILE_BYTES);
	~PcapPacket();
	
	void SetFileHeader(PcapFileHeader const &m_fileHdr);
	void open();
	void close();
	void write(const char * buf, const int len, const char * paddingBuf = NULL, const int paddingLen = 0);
	void writeString(const char * String, const int Stringlen);
	void writeAddEthHead(const char * buf, const int len, const PCAP_ETH_HEADER &preEtherHeader);
	void writeAddEthHead(const char * buf, const int len, const unsigned short ethType);
	void writeReplaceEthType(const char * buf, const int len, const unsigned short ethType);
	void removeFile();
	const CBString &GetFileName();

private:
	nsp_mutex_handle m_hMutex; 	
	PcapFileHeader m_fileHdr;
	CBString m_fileName;
	#ifdef SUPPORT_STD
	std::ofstream m_out;
	#else
	FILE *m_out;
	#endif
	ULONG m_currentPacketNum;
	ULONG m_maxPacketNum;
	ULONG64 m_currentFileByte;
	ULONG64 m_maxFileByte;
};

#endif
