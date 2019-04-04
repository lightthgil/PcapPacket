const char *c_LogPacketFileDir = "/ramdisk:0/";
PcapPacket::PcapPacket(CBString fileName, ULONG maxPacketNum, ULONG64 maxFileByte)
{
	m_hMutex = 0;
	create_mutex(m_hMutex, "CPcapPacket");

	m_fileName = fileName;

	m_fileHdr.magic = PCAP_FILE_HEADER_MAGIC;
	m_fileHdr.version_major = PCAP_FILE_HEADER_VERSION_MAJOR;
	m_fileHdr.version_minor = PCAP_FILE_HEADER_VERSION_MINOR;
	m_fileHdr.timezone = 0;
	m_fileHdr.sigfigs = 0;
	m_fileHdr.snaplen = PCAP_FILE_HEADER_LEN_NOT_LIMIT;
	m_fileHdr.linktype = PcapLinkType_Ethernet;

	m_currentPacketNum = 0;
	m_currentFileByte = 0;
	if(0 == maxPacketNum)
	{
		m_maxPacketNum = LOG_PACKET_MAX_NUM;
	}
	else
	{
		m_maxPacketNum = maxPacketNum;
	}
	if(0 == maxFileByte)
	{
		m_maxFileByte = LOG_PACKET_MAX_FILE_BYTES;
	}
	else
	{
		m_maxFileByte = maxFileByte;
	}

#ifndef SUPPORT_STD
	m_out = NULL;
#endif

	open();
}

PcapPacket::~PcapPacket()
{
	close();
	removeFile();

    if (m_hMutex)
    {
        lock_mutex(m_hMutex);
        delete_mutex(m_hMutex);
        m_hMutex = 0;
    }
}


void PcapPacket::SetFileHeader(PcapFileHeader const &fileHdr)
{
	memcpy(&m_fileHdr, &fileHdr, sizeof(m_fileHdr));
}

void PcapPacket::open()
{
    lock_mutex(m_hMutex); 
#ifdef SUPPORT_STD
	if(m_out.is_open())
	{
		m_out.close();
	}
	m_out.open(m_fileName, std::ios::out|std::ios::binary);
#else
	m_out = fopen(m_fileName, "wb+");
#endif
	
	m_currentFileByte = 0;
	m_currentPacketNum = 0;

#ifdef SUPPORT_STD
	m_out.write((const char *)(&m_fileHdr), sizeof(m_fileHdr));
#else
	if(NULL != m_out)
	{
		fwrite((const char *)(&m_fileHdr), sizeof(m_fileHdr), 1, m_out);
	}
#endif
	m_currentFileByte += sizeof(m_fileHdr);
	unlock_mutex(m_hMutex);

	return;
}

void PcapPacket::close()
{
    lock_mutex(m_hMutex);
#ifdef SUPPORT_STD
	if(m_out.is_open())
	{
		m_out.close();
	}
#else
	if(NULL != m_out)
	{
		fclose(m_out);
		m_out = NULL;
	}
#endif
	unlock_mutex(m_hMutex);
}

void PcapPacket::write(const char * buf, const int len, const char * paddingBuf, const int paddingLen)
{
	if((len <= 0) || (NULL == buf) || (paddingLen < 0))
	{
	    return;
	}

	/* 控制文件大小 */
    lock_mutex(m_hMutex);
	if((m_currentFileByte >= m_maxFileByte) || (m_currentPacketNum >= m_maxPacketNum))
	{
		unlock_mutex(m_hMutex);
		return;
	}
	unlock_mutex(m_hMutex);

	PcapPacketHeader packetHeader = {0};
	ULONG most=0,  least=0;
	
	NSPReadTimeBase(most, least);
	NSPTimeBaseToTime(most, least);

	packetHeader.timeSpec.GMTtime = most;
	packetHeader.timeSpec.microTime = least;
	packetHeader.len = len + paddingLen;
	
    lock_mutex(m_hMutex);
	packetHeader.caplen = ((len + paddingLen) < m_fileHdr.snaplen) ? (len + paddingLen) : m_fileHdr.snaplen;

#ifdef SUPPORT_STD
	m_out.write((const char *)(&packetHeader), sizeof(packetHeader));
	if((NULL != paddingBuf) && (paddingLen > 0))
	{
		m_out.write(paddingBuf, paddingLen);
	}
	m_out.write(buf, len);
#else
	if(NULL != m_out)
	{
		fwrite((const char *)(&packetHeader), sizeof(packetHeader), 1, m_out);
		if((NULL != paddingBuf) && (paddingLen > 0))
		{
			fwrite(paddingBuf, paddingLen, 1, m_out);
		}
		fwrite(buf, len, 1, m_out);
	}
#endif
	m_currentFileByte = m_currentFileByte + sizeof(packetHeader) + len + paddingLen;
	m_currentPacketNum++;
	unlock_mutex(m_hMutex);

	return;
}

void PcapPacket::writeString(const char * String, const int Stringlen)
{
	writeAddEthHead(String, Stringlen, ETHTYPE_DEBUG_STRING);

	return;
}

void PcapPacket::writeAddEthHead(const char * buf, const int len, const PCAP_ETH_HEADER &preEtherHeader)
{
	write(buf, len, (const char *)&preEtherHeader, sizeof(preEtherHeader));

	return;
}


void PcapPacket::writeAddEthHead(const char * buf, const int len, const unsigned short ethType)
{
	PCAP_ETH_HEADER pre_ether_header;
	memset(&pre_ether_header, 0, sizeof(pre_ether_header));
	pre_ether_header.type = htons(ethType);
	write(buf, len, (const char *)&pre_ether_header, sizeof(pre_ether_header));

	return;
}

void PcapPacket::writeReplaceEthType(const char * buf, const int len, const unsigned short ethType)
{
	PCAP_ETH_HEADER pre_ether_header;
	memcpy(&pre_ether_header, buf, 12);
	pre_ether_header.type = htons(ethType);
	write(buf + sizeof(pre_ether_header), len - sizeof(pre_ether_header), (const char *)&pre_ether_header, sizeof(pre_ether_header));

	return;
}



void PcapPacket::removeFile()
{
	lock_mutex(m_hMutex);
	if(0 != m_fileName.length())
	{
#ifdef SUPPORT_STD
		std::remove(m_fileName);
#else
		remove(m_fileName);
#endif
	}
	
		unlock_mutex(m_hMutex);
	return;
}


const CBString &PcapPacket::GetFileName()
{
	return m_fileName;
}

