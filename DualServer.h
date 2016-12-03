/**************************************************************************
*   Copyright (C) 2005 by Achal Dhir (achaldhir@gmail.com)                *
*   Copyright (C) 2016 by Aaron John Schlosser (aaron@aaronschlosser.com) *
*                                                                         *
*   This program is free software; you can redistribute it and/or modify  *
*   it under the terms of the GNU General Public License as published by  *
*   the Free Software Foundation; either version 2 of the License, or     *
*   (at your option) any later version.                                   *
*                     a                                                   *
*   This program is distributed in the hope that it will be useful,       *
*   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
*   GNU General Public License for more details.                          *
*                                                                         *
*   You should have received a copy of the GNU General Public License     *
*   along with this program; if not, write to the                         *
*   Free Software Foundation, Inc.,                                       *
*   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
***************************************************************************/
//This file defines all structures and constants
//for both DHCP and DNS Servers

#define MYBYTE unsigned char
#define MYWORD unsigned short
#define MYDWORD unsigned int

#ifdef _MSC_VER
   #define strcasecmp _stricmp
   #define _CRT_SECURE_NO_WARNINGS
   #pragma comment(lib, "ws2_32.lib")
   #pragma comment(lib, "iphlpapi.lib")
#endif

#include <string>
#include <map>
using namespace std;

#define MAX_SERVERS 125
#define MAX_DHCP_RANGES 125
#define MAX_DNS_RANGES 32
#define MAX_RANGE_SETS 125
#define MAX_RANGE_FILTERS 32
#define MAX_COND_FORW 125
#define MAX_TCP_CLIENTS 16
#define MAX_WILD_HOSTS 125

#define RCODE_NOERROR 		0
#define RCODE_FORMATERROR	1
#define RCODE_SERVERFAIL	2
#define RCODE_NAMEERROR		3
#define RCODE_NOTIMPL 		4
#define RCODE_REFUSED 		5
#define RCODE_YXDOMAIN 		6
#define RCODE_YXRRSET 		7
#define RCODE_NXRRSET 		8
#define RCODE_NOTAUTH 		9
#define RCODE_NOTZONE 		10

#define OPCODE_STANDARD_QUERY	0
#define OPCODE_INVERSE_QUERY	1
#define OPCODE_SRVR_STAT_REQ	2
#define OPCODE_NOTIFY			4
#define OPCODE_DYNAMIC_UPDATE	5

#define DNS_TYPE_A		1
#define DNS_TYPE_NS		2
#define DNS_TYPE_MD		3
#define DNS_TYPE_MF		4
#define DNS_TYPE_CNAME	5
#define DNS_TYPE_SOA	6
#define DNS_TYPE_MB		7
#define DNS_TYPE_MG		8
#define DNS_TYPE_MR		9
#define DNS_TYPE_NULL	10
#define DNS_TYPE_WKS	11
#define DNS_TYPE_PTR	12
#define DNS_TYPE_HINFO	13
#define DNS_TYPE_MINFO	14
#define DNS_TYPE_MX		15
#define DNS_TYPE_TXT	16
#define DNS_TYPE_AAAA	28
#define DNS_TYPE_IXFR	251
#define DNS_TYPE_AXFR	252
#define DNS_TYPE_MAILB	253
#define DNS_TYPE_MAILA	254
#define DNS_TYPE_ANY	255

#define DNS_CLASS_IN	1
#define DNS_CLASS_CS	2
#define DNS_CLASS_CH	3
#define DNS_CLASS_HS	4
#define DNS_CLASS_NONE	254
#define DNS_CLASS_ANY	255

#define IPPORT_DNS 53

struct dnsHeader
{
	unsigned xid :16;	//query identification number
	/* byte boundry */
	unsigned rd: 1;		//recursion desired
	unsigned tc: 1;		//truncated message
	unsigned aa: 1;		//authoritive answer
	unsigned opcode: 4;	//option code
	unsigned qr: 1;		//response flag
	/* byte boundry */
	unsigned rcode :4;	//response code
	unsigned cd: 1;		//checking disabled by resolver
	unsigned at: 1;		//authentic data from named
	unsigned unused :1;	//unused
	unsigned ra: 1;		//recursion available
	/* byte boundry */
	union
	{
		struct
		{
			unsigned qdcount :16;	//number of question entries
			unsigned ancount :16;	//number of answer entries
			unsigned nscount :16;	//number of authority entries
			unsigned adcount :16;	//number of additional entries
		};
		struct
		{
			unsigned zcount :16;	//number of zone entries
			unsigned prcount :16;	//number of prerequisit entries
			unsigned ucount :16;	//number of update entries
			unsigned arcount :16;	//number of other entries
		};
	};
};

/*
struct dnsHeader
{
	unsigned xid :16;	// query identification number
	unsigned qr: 1;		// response flag
	unsigned opcode: 4;	// purpose of message
	unsigned aa: 1;		// authoritive answer
	unsigned tc: 1;		// truncated message
	unsigned rd: 1;		// recursion desired
	// byte boundry 	// fields in fourth byte
	unsigned ra: 1;		// recursion available
	unsigned unused :1;	// unused bits (MBZ as of 4.9.3a3)
	unsigned at: 1;		// authentic data from named
	unsigned cd: 1;		// checking disabled by resolver
	unsigned rcode :4;	// response code
	// byte boundry 	// remaining bytes
	union {
		struct {
			MYWORD qdcount;
			MYWORD ancount;
			MYWORD nscount;
			MYWORD adcount;
		};
		struct {
			MYWORD zcount;
			MYWORD prcount;
			MYWORD ucount;
			MYWORD arcount;
		};
	};
};
*/

struct dnsPacket
{
	struct dnsHeader header;
	char data;
};

struct data10
{
	char zone[256];
	MYWORD zLen;
	MYDWORD dns[2];
	MYBYTE currentDNS;
	MYBYTE lastDNS;
};

struct data16
{
	char wildcard[256];
	MYDWORD ip;
};

struct data18
{
	MYBYTE currentInd;
	bool done;
};

struct data7 //cache
{
	char *mapname;
	time_t expiry;
	union
	{
		struct
		{
			MYBYTE cType;
			MYBYTE dnsType;
			MYBYTE sockInd;
			MYBYTE dnsIndex;
		};
		struct
		{
			unsigned fixed: 1;
			unsigned local: 1;
			unsigned display: 1;
			unsigned reserved1: 5;
			char rangeInd;
			MYWORD dhcpInd;
		};
	};
	union
	{
		char *name;
		MYBYTE *options;
	};
	union
	{
		int bytes;
		MYDWORD ip;
		SOCKADDR_IN *addr;
	};
	union
	{
		MYBYTE *response;
		char *hostname;
		char *query;
	};
	MYBYTE data;
};

struct data71 //Lump
{
	char *mapname;
	MYBYTE *response;
	char *hostname;
	char *query;
	SOCKADDR_IN *addr;
	MYBYTE *options;
	MYWORD optionSize;
	int bytes;
	MYBYTE cType;
	MYBYTE dnsType;
};

typedef multimap<string, data7*> hostMap;
typedef multimap<time_t, data7*> expiryMap;

struct data5 //dns request
{
	dnsPacket *dnsp;
	char *dp;
	char raw[2048];
	char query[256];
	char cname[256];
	char mapname[256];
	char tempname[256];
	char extbuff[264];
	hostMap::iterator iterBegin;
	SOCKET sock;
	SOCKADDR_IN addr;
	SOCKADDR_IN remote;
	socklen_t sockLen;
	linger ling;
	int bytes;
	MYWORD qLen;
	MYWORD qclass;
	MYBYTE dnsType;
	MYBYTE qType;
	MYBYTE cType;
	MYBYTE sockInd;
	MYBYTE dnsIndex;
};

enum
{
	CTYPE_NONE,
	CTYPE_DHCP_ENTRY,
	CTYPE_LOCAL_A,
	CTYPE_LOCAL_PTR_AUTH,
	CTYPE_LOCAL_PTR_NAUTH,
	CTYPE_LOCALHOST_A,
	CTYPE_LOCALHOST_PTR,
	CTYPE_SERVER_A_AUTH,
	CTYPE_SERVER_PTR_AUTH,
	CTYPE_SERVER_A_NAUTH,
	CTYPE_SERVER_PTR_NAUTH,
	CTYPE_LOCAL_CNAME,
	CTYPE_EXT_CNAME,
	CTYPE_STATIC_A_AUTH,
	CTYPE_STATIC_PTR_AUTH,
	CTYPE_STATIC_A_NAUTH,
	CTYPE_STATIC_PTR_NAUTH,
	CTYPE_NS,
	CTYPE_SOA,
	CTYPE_AXFR,
	CTYPE_CACHED,
	CTYPE_NON_CACHED,
	CTYPE_QUEUE,
	CTYPE_DNS_CHECK,
	QTYPE_IP,
	QTYPE_HOSTNAME,
	QTYPE_A_EXT,
	QTYPE_A_BARE,
	QTYPE_A_LOCAL,
	QTYPE_A_ZONE,
	QTYPE_P_EXT,
	QTYPE_P_LOCAL,
	QTYPE_P_ZONE,
	QTYPE_CHILDZONE
};

struct data12 //dns range
{
	MYDWORD rangeStart;
	MYDWORD rangeEnd;
};

struct dns_rr
{
	char *name;
	MYWORD type, _class;
	MYDWORD ttl;
	MYWORD rdlength;
	char *rdata;
	union {
		struct
		{
			long address;
		} a;
		struct
		{
			char *cname;
		} cname;
		struct
		{
			char *cpu, *os;
		} hinfo;
		struct
		{
			char *madname;
		} mb;
		struct
		{
			char *madname;
		} md;
		struct
		{
			char *madname;
		} mf;
		struct
		{
			char *mgmname;
		} mg;
		struct
		{
			char *rmailbx, *emailbx;
		} minfo;
		struct
		{
			char *newname;
		} mr;
		struct
		{
			int preference;
			char *exchange;
		} mx;
		struct
		{
			char *nsdname;
		} ns;
		struct
		{
			char *data;
		} null;
		struct
		{
			char *ptrdname;
		} ptr;
		struct
		{
			char *mname, *rname;
			unsigned serial, refresh, retry, expire, minimum;
		} soa;
		struct
		{
			char **txt_data;
		} txt;
		struct
		{
			int address;
			MYBYTE protocol;
			int bitmapsize;
			char *bitmap;
		} wks;
	} data;
};

struct data11 //mx
{
	char hostname[256];
	MYWORD pref;
};

struct ConnType
{
	SOCKET sock;
	SOCKADDR_IN addr;
	SOCKADDR_IN remote;
	MYDWORD server;
	MYWORD port;
	bool loaded;
	bool ready;
};

#define BOOTP_REQUEST  1
#define BOOTP_REPLY    2

#define DHCP_MESS_NONE       0
#define DHCP_MESS_DISCOVER   1
#define DHCP_MESS_OFFER      2
#define DHCP_MESS_REQUEST	 3
#define DHCP_MESS_DECLINE	 4
#define DHCP_MESS_ACK		 5
#define DHCP_MESS_NAK		 6
#define DHCP_MESS_RELEASE    7
#define DHCP_MESS_INFORM	 8


// DHCP OPTIONS
#define DHCP_OPTION_PAD						0
#define DHCP_OPTION_NETMASK          		1
#define DHCP_OPTION_TIMEOFFSET       		2
#define DHCP_OPTION_ROUTER           		3
#define DHCP_OPTION_TIMESERVER       		4
#define DHCP_OPTION_NAMESERVER       		5
#define DHCP_OPTION_DNS              		6
#define DHCP_OPTION_LOGSERVER        		7
#define DHCP_OPTION_COOKIESERVER     		8
#define DHCP_OPTION_LPRSERVER        		9
#define DHCP_OPTION_IMPRESSSERVER    		10
#define DHCP_OPTION_RESLOCSERVER     		11
#define DHCP_OPTION_HOSTNAME         		12
#define DHCP_OPTION_BOOTFILESIZE     		13
#define DHCP_OPTION_MERITDUMP        		14
#define DHCP_OPTION_DOMAINNAME       		15
#define DHCP_OPTION_SWAPSERVER       		16
#define DHCP_OPTION_ROOTPATH         		17
#define DHCP_OPTION_EXTSPATH         		18
#define DHCP_OPTION_IPFORWARD        		19
#define DHCP_OPTION_NONLOCALSR       		20
#define DHCP_OPTION_POLICYFILTER     		21
#define DHCP_OPTION_MAXREASSEMBLE    		22
#define DHCP_OPTION_IPTTL            		23
#define DHCP_OPTION_PATHMTUAGING     		24
#define DHCP_OPTION_PATHMTUPLATEAU   		25
#define DHCP_OPTION_INTERFACEMTU     		26
#define DHCP_OPTION_SUBNETSLOCAL     		27
#define DHCP_OPTION_BCASTADDRESS     		28
#define DHCP_OPTION_MASKDISCOVERY    		29
#define DHCP_OPTION_MASKSUPPLIER     		30
#define DHCP_OPTION_ROUTERDISCOVERY  		31
#define DHCP_OPTION_ROUTERSOLIC      		32
#define DHCP_OPTION_STATICROUTE      		33
#define DHCP_OPTION_TRAILERENCAPS    		34
#define DHCP_OPTION_ARPTIMEOUT       		35
#define DHCP_OPTION_ETHERNETENCAPS   		36
#define DHCP_OPTION_TCPTTL           		37
#define DHCP_OPTION_TCPKEEPALIVEINT  		38
#define DHCP_OPTION_TCPKEEPALIVEGRBG 		39
#define DHCP_OPTION_NISDOMAIN        		40
#define DHCP_OPTION_NISSERVERS       		41
#define DHCP_OPTION_NTPSERVERS       		42
#define DHCP_OPTION_VENDORSPECIFIC   		43
#define DHCP_OPTION_NETBIOSNAMESERV  		44
#define DHCP_OPTION_NETBIOSDGDIST    		45
#define DHCP_OPTION_NETBIOSNODETYPE  		46
#define DHCP_OPTION_NETBIOSSCOPE     		47
#define DHCP_OPTION_X11FONTS         		48
#define DHCP_OPTION_X11DISPLAYMNGR   		49
#define DHCP_OPTION_REQUESTEDIPADDR  		50
#define DHCP_OPTION_IPADDRLEASE      		51
#define DHCP_OPTION_OVERLOAD         		52
#define DHCP_OPTION_MESSAGETYPE      		53
#define DHCP_OPTION_SERVERID         		54
#define DHCP_OPTION_PARAMREQLIST     		55
#define DHCP_OPTION_MESSAGE          		56
#define DHCP_OPTION_MAXDHCPMSGSIZE   		57
#define DHCP_OPTION_RENEWALTIME      		58
#define DHCP_OPTION_REBINDINGTIME    		59
#define DHCP_OPTION_VENDORCLASSID    		60
#define DHCP_OPTION_CLIENTID         		61
#define DHCP_OPTION_NETWARE_IPDOMAIN        62
#define DHCP_OPTION_NETWARE_IPOPTION        63
#define DHCP_OPTION_NISPLUSDOMAIN    		64
#define DHCP_OPTION_NISPLUSSERVERS   		65
#define DHCP_OPTION_TFTPSERVER       		66
#define DHCP_OPTION_BOOTFILE         		67
#define DHCP_OPTION_MOBILEIPHOME     		68
#define DHCP_OPTION_SMTPSERVER       		69
#define DHCP_OPTION_POP3SERVER       		70
#define DHCP_OPTION_NNTPSERVER       		71
#define DHCP_OPTION_WWWSERVER        		72
#define DHCP_OPTION_FINGERSERVER     		73
#define DHCP_OPTION_IRCSERVER        		74
#define DHCP_OPTION_STSERVER         		75
#define DHCP_OPTION_STDASERVER       		76
#define DHCP_OPTION_USERCLASS        		77
#define DHCP_OPTION_SLPDIRAGENT      		78
#define DHCP_OPTION_SLPDIRSCOPE      		79
#define DHCP_OPTION_CLIENTFQDN       		81
#define DHCP_OPTION_RELAYAGENTINFO     		82
#define DHCP_OPTION_I_SNS     				83
#define DHCP_OPTION_NDSSERVERS       		85
#define DHCP_OPTION_NDSTREENAME      		86
#define DHCP_OPTION_NDSCONTEXT		 		87
#define DHCP_OPTION_AUTHENTICATION			90
#define DHCP_OPTION_CLIENTSYSTEM			93
#define DHCP_OPTION_CLIENTNDI				94
#define DHCP_OPTION_LDAP					95
#define DHCP_OPTION_UUID_GUID				97
#define DHCP_OPTION_USER_AUTH				98
#define DHCP_OPTION_P_CODE					100
#define DHCP_OPTION_T_CODE					101
#define DHCP_OPTION_NETINFOADDRESS			112
#define DHCP_OPTION_NETINFOTAG				113
#define DHCP_OPTION_URL						114
#define DHCP_OPTION_AUTO_CONFIG				116
#define DHCP_OPTION_NAMESERVICESEARCH		117
#define DHCP_OPTION_SUBNETSELECTION			118
#define DHCP_OPTION_DOMAINSEARCH			119
#define DHCP_OPTION_SIPSERVERSDHCP			120
#define DHCP_OPTION_CLASSLESSSTATICROUTE	121
#define DHCP_OPTION_CCC						122
#define DHCP_OPTION_GEOCONF					123
#define DHCP_OPTION_V_IVENDORCLASS			124
#define DHCP_OPTION_V_IVENDOR_SPECIFIC		125
#define DHCP_OPTION_TFPTSERVERIPADDRESS		128
#define DHCP_OPTION_CALLSERVERIPADDRESS		129
#define DHCP_OPTION_DISCRIMINATIONSTRING	130
#define DHCP_OPTION_REMOTESTATISTICSSERVER	131
#define DHCP_OPTION_802_1PVLANID			132
#define DHCP_OPTION_802_1QL2PRIORITY		133
#define DHCP_OPTION_DIFFSERVCODEPOINT		134
#define DHCP_OPTION_HTTPPROXYFORPHONE_SPEC	135
#define DHCP_OPTION_SERIAL					252
#define DHCP_OPTION_BP_FILE					253
#define DHCP_OPTION_NEXTSERVER				254
#define DHCP_OPTION_END						255

//#define DHCP_VENDORDATA_SIZE		 272
//#define DHCP_VENDORDATA_SIZE		 64
//#define DHCP_VENDORDATA_SIZE		 784
//#define DHCP_PACKET_SIZE			1024
//#define DHCP_MIN_SIZE				 44
//#define DHCP_MAX_CLIENTS			 254
#define IPPORT_DHCPS   67
#define IPPORT_DHCPC   68
#define VM_STANFORD  0x5354414EUL
#define VM_RFC1048   0x63825363UL

struct data3
{
	MYBYTE opt_code;
	MYBYTE size;
	MYBYTE value[256];
};

typedef map<string, data7*> dhcpMap;

struct dhcp_header
{
	MYBYTE bp_op;
	MYBYTE bp_htype;
	MYBYTE bp_hlen;
	MYBYTE bp_hops;
	MYDWORD bp_xid;
	struct
	{
		unsigned bp_secs:16;
		unsigned bp_spare:7;
		unsigned bp_broadcast:1;
		unsigned bp_spare1:8;
	};
	MYDWORD bp_ciaddr;
	MYDWORD bp_yiaddr;
	MYDWORD bp_siaddr;
	MYDWORD bp_giaddr;
	MYBYTE bp_chaddr[16];
	char bp_sname[64];
	MYBYTE bp_file[128];
	MYBYTE bp_magic_num[4];
};

struct dhcp_packet
{
	dhcp_header header;
	MYBYTE vend_data[1024 - sizeof(dhcp_header)];
};

struct data13 //dhcp range
{
	MYBYTE rangeSetInd;
	MYDWORD rangeStart;
	MYDWORD rangeEnd;
	MYDWORD mask;
	MYBYTE *options;
	time_t *expiry;
	data7 **dhcpEntry;
};

struct data14 //rangeSet
{
	MYBYTE active;
	MYBYTE *macStart[MAX_RANGE_FILTERS];
	MYBYTE *macEnd[MAX_RANGE_FILTERS];
	MYBYTE macSize[MAX_RANGE_FILTERS];
	MYBYTE *vendClass[MAX_RANGE_FILTERS];
	MYBYTE vendClassSize[MAX_RANGE_FILTERS];
	MYBYTE *userClass[MAX_RANGE_FILTERS];
	MYBYTE userClassSize[MAX_RANGE_FILTERS];
	MYDWORD subnetIP[MAX_RANGE_FILTERS];
	MYDWORD targetIP;
};

struct data17
{
	MYBYTE macArray[MAX_RANGE_SETS];
	MYBYTE vendArray[MAX_RANGE_SETS];
	MYBYTE userArray[MAX_RANGE_SETS];
	MYBYTE subnetArray[MAX_RANGE_SETS];
	bool macFound;
	bool vendFound;
	bool userFound;
	bool subnetFound;
};

struct data19
{
	SOCKET sock;
	SOCKADDR_IN remote;
	socklen_t sockLen;
	linger ling;
	int memSize;
	int bytes;
	char *dp;
};

struct data20
{
	MYBYTE options[sizeof(dhcp_packet)];
	MYWORD optionSize;
	MYDWORD ip;
	MYDWORD mask;
	MYBYTE rangeSetInd;
};

struct data9 //dhcpRequst
{
	MYDWORD lease;
	union
	{
		char raw[sizeof(dhcp_packet)];
		dhcp_packet dhcpp;
	};
	char hostname[256];
	char chaddr[64];
	char tempbuff[256];
	MYDWORD specifiedServers[MAX_SERVERS];
	MYDWORD specifiedDnsServers[MAX_SERVERS];
	MYDWORD server;
	MYDWORD reqIP;
	int bytes;
	SOCKADDR_IN remote;
	socklen_t sockLen;
	MYWORD messsize;
	MYBYTE *vp;
	data7 *dhcpEntry;
	data3 agentOption;
	data3 clientId;
	data3 subnet;
	data3 vendClass;
	data3 userClass;
	MYDWORD subnetIP;
	MYDWORD targetIP;
	MYDWORD rebind;
	MYDWORD dns;
	MYBYTE paramreqlist[256];
	MYBYTE opAdded[256];
	MYBYTE req_type;
	MYBYTE resp_type;
	MYBYTE sockInd;
};

struct DhcpConnType
{
	SOCKET sock;
	SOCKADDR_IN addr;
	MYDWORD server;
	MYWORD port;
	MYDWORD mask;
	int broadCastVal;
	int broadCastSize;
	int reUseVal;
	int reUseSize;
	int donotRouteVal;
	int donotRouteSize;
	bool loaded;
	bool ready;
};

struct data4
{
	char opName[40];
	MYBYTE opTag;
	MYBYTE opType;
	bool permitted;
};

struct data15
{
	union
	{
		//MYDWORD ip;
		unsigned ip:32;
		MYBYTE octate[4];
	};
};

struct data8 //client
{
	MYWORD dhcpInd;
	MYBYTE bp_hlen;
	MYBYTE local;
	MYDWORD source;
	MYDWORD ip;
	time_t expiry;
	MYBYTE bp_chaddr[16];
	char hostname[64];
};

struct data1
{
	DhcpConnType dhcpConn[MAX_SERVERS];
	ConnType dnsUdpConn[MAX_SERVERS];
	ConnType forwConn;
	ConnType dnsTcpConn[MAX_SERVERS];
	ConnType httpConn;
	MYDWORD allServers[MAX_SERVERS];
	MYDWORD listenServers[MAX_SERVERS];
	MYDWORD listenMasks[MAX_SERVERS];
	MYDWORD staticServers[MAX_SERVERS];
	MYDWORD staticMasks[MAX_SERVERS];
	MYDWORD dns[MAX_SERVERS];
	SOCKET maxFD;
	MYBYTE currentDNS;
	bool ready;
	bool busy;
	bool bindfailed;
};

struct data2
{
	WSADATA wsaData;
	char zone[256];
	MYBYTE zLen;
	char authoritySmall[256];
	char authority[256];
	MYBYTE aLen;
	CHAR nsP[256];
	CHAR nsS[256];
	//CHAR nsP[2][256];
	//CHAR nsABare[256];
	//CHAR nsPBare[256];
	char servername[128];
	char servername_fqn[256];
	data11 mxServers[2][5];
	MYBYTE mxCount[2];
	MYDWORD mask;
	MYDWORD lease;
	MYDWORD serial1;
	MYDWORD serial2;
	MYDWORD refresh;
	MYDWORD retry;
	MYDWORD expire;
	MYDWORD minimum;
	MYWORD minCache;
	MYWORD maxCache;
	MYDWORD dhcpSize;
	time_t expireTime;
	MYDWORD httpClients[8];
	MYDWORD specifiedServers[MAX_SERVERS];
	MYDWORD specifiedDnsServers[MAX_SERVERS];
	MYDWORD zoneServers[MAX_TCP_CLIENTS];
	data10 dnsRoutes[MAX_COND_FORW];
	data16 wildHosts[MAX_WILD_HOSTS];
	data12 dnsRanges[MAX_DNS_RANGES];
	data13 dhcpRanges[MAX_DHCP_RANGES];
	data14 rangeSet[MAX_RANGE_SETS];
	ConnType dhcpReplConn;
	MYBYTE hasFilter;
	MYDWORD rangeStart;
	MYDWORD rangeEnd;
	MYBYTE *options;
	MYWORD dhcpInd;
	char logFileName[_MAX_PATH];
	MYDWORD failureCount;
	time_t dhcpRepl;
	time_t dnsRepl;
	time_t dnsCheck;
	MYBYTE rangeCount;
	MYBYTE dhcpLogLevel;
	MYBYTE dnsLogLevel;
	MYBYTE authorized;
	MYBYTE replication;
};

//Function Prototypes
FILE *openSection(const char *sectionName, MYBYTE serial);
MYBYTE fromBase64(MYBYTE *target, char *source);
MYBYTE fromUUE(MYBYTE *target, char *source);
MYBYTE getBaseValue(MYBYTE a);
MYBYTE makeLocal(char *mapname);
MYBYTE pIP(void *raw, MYDWORD data);
MYBYTE pULong(void *raw, MYDWORD data);
MYBYTE pUShort(void *raw, MYWORD data);
MYBYTE addServer(MYDWORD *array, MYBYTE maxServers, MYDWORD ip);
MYDWORD *findServer(MYDWORD *array, MYBYTE maxServers, MYDWORD ip);
MYDWORD alad(data9 *req);
MYDWORD calcMask(MYDWORD rangeStart, MYDWORD rangeEnd);
MYDWORD chad(data9 *req);
MYDWORD fIP(void *raw);
MYDWORD fULong(void *raw);
MYDWORD getClassNetwork(MYDWORD ip);
MYDWORD getSerial(char *zone);
MYDWORD getZone(MYBYTE ind, char *zone);
MYDWORD resad(data9 *req);
MYDWORD sdmess(data9 *req);
MYDWORD sendRepl(data7 *dhcpEntry);
MYDWORD sendRepl(data9 *req);
MYWORD fQu(char *query, dnsPacket *mess, char *raw);
MYWORD fUShort(void *raw);
MYWORD fdnmess(data5 *req);
MYWORD frdnmess(data5 *req);
MYWORD gdmess(data9 *req, MYBYTE sockInd);
MYWORD gdnmess(data5 *req, MYBYTE sockInd);
MYWORD myTokenize(char *target, char *source, const char *sep, bool whiteSep);
MYWORD pQu(char *raw, char *query);
MYWORD qLen(char *query);
MYWORD recvTcpDnsMess(char *target, SOCKET sock, MYWORD targetSize);
MYWORD scanloc(data5 *req);
MYWORD sdnmess(data5 *req);
MYWORD sendTCPmess(data5 *req);
bool checkMask(MYDWORD mask);
bool checkRange(data17 *rangeData, char rangeInd);
bool chkQu(char *query);
bool detectChange();
bool getSecondary();
bool getSection(const char *sectionName, char *buffer, MYBYTE serial, char *fileName);
bool isIP(char *str);
bool isInt(char *str);
bool isLocal(MYDWORD ip);
bool stopService(SC_HANDLE service);
bool wildcmp(char *string, char *wild);
char *IP2Auth(MYDWORD ip);
char *IP2String(char *target, MYDWORD ip);
char *IP2String(char *target, MYDWORD ip, MYBYTE dnsType);
char *IP62String(char *target, MYBYTE *source);
char *cloneString(char *string);
char *genHostName(char *target, MYBYTE *hex, MYBYTE bytes);
char *getHexValue(MYBYTE *target, char *source, MYBYTE *size);
char *hex2String(char *target, MYBYTE *hex, MYBYTE bytes);
char *myLower(char *string);
char *myUpper(char *string);
char *readSection(char* buff, FILE *f);
char *setMapName(char *tempbuff, char *mapname, MYBYTE dnsType);
char *strquery(data5 *req);
char *toBase64(MYBYTE *source, MYBYTE length);
char *toUUE(char *tempbuff, MYBYTE *source, MYBYTE length);
char getRangeInd(MYDWORD ip);
char* getResult(data5 *req);
char* myGetToken(char* buff, MYBYTE index);
char* myTrim(char *target, char *source);
data7 *createCache(data71 *lump);
data7 *findDHCPEntry(char *key);
data7 *findEntry(char *key, MYBYTE dnsType);
data7 *findEntry(char *key, MYBYTE dnsType, MYBYTE cType);
data7 *findQueue(char *key);
int getIndex(char rangeInd, MYDWORD ip);
int main(int argc, TCHAR* argv[]);
void WINAPI ServiceControlHandler(DWORD controlCode);
void WINAPI ServiceMain(DWORD /*argc*/, TCHAR* /*argv*/[]);
void __cdecl checkZone(void *lpParam);
void __cdecl init(void *lpParam);
void __cdecl logDebug(void *lpParam);
void __cdecl logThread(void *lpParam);
void __cdecl sendHTTP(void *lpParam);
void __cdecl sendToken(void *lpParam);
void __cdecl updateStateFile(void *lpParam);
void add2Cache(char *hostname, MYDWORD ip, time_t expiry, MYBYTE aType, MYBYTE pType);
void addDHCPRange(char *dp);
void addEntry(data7 *entry);
void addHostNotFound(char *hostname);
void addMacRange(MYBYTE rangeSetInd, char *macRange);
void addOptions(data9 *req);
void addRRA(data5 *req);
void addRRAOne(data5 *req);
void addRRAd(data5 *req);
void addRRAny(data5 *req);
void addRRCNOne(data5 *req);
void addRRCache(data5 *req, data7 *cache);
void addRREmpty(data5 *req);
void addRRError(data5 *req, MYBYTE rcode);
void addRRExt(data5 *req);
void addRRLocalhostA(data5 *req, data7 *cache);
void addRRLocalhostPtr(data5 *req, data7 *cache);
void addRRMX(data5 *req);
void addRRMXOne(data5 *req, MYBYTE m);
void addRRNS(data5 *req);
void addRRNone(data5 *req);
void addRRPtr(data5 *req);
void addRRPtrOne(data5 *req);
void addRRSOA(data5 *req);
void addRRSTAOne(data5 *req);
void addRRServerA(data5 *req);
void addRRWildA(data5 *req, MYDWORD ip);
void addUserClass(MYBYTE rangeSetInd, char *userClass, MYBYTE userClassSize);
void addVendClass(MYBYTE rangeSetInd, char *vendClass, MYBYTE vendClassSize);
void calcRangeLimits(MYDWORD ip, MYDWORD mask, MYDWORD *rangeStart, MYDWORD *rangeEnd);
void checkSize();
void closeConn();
void debug(const char *mess);
void debug(int i);
void delDnsEntry(data7* cache);
void emptyCache(MYBYTE ind);
void expireEntry(MYDWORD ip);
void getInterfaces(data1 *network);
void holdIP(MYDWORD ip);
void installService();
void listCache();
void listDhcpCache();
void loadDHCP();
void loadOptions(FILE *f, const char *sectionName, data20 *optionData);
void lockIP(MYDWORD ip);
void lockOptions(FILE *f);
void logDHCPMess(char *logBuff, MYBYTE logLevel);
void logDNSMess(char *logBuff, MYBYTE logLevel);
void logDNSMess(data5 *req, char *logBuff, MYBYTE logLevel);
void logDirect(char *mess);
void logMess(char *logBuff, MYBYTE logLevel);
void logTCPMess(data5 *req, char *logBuff, MYBYTE logLevel);
void mySplit(char *name, char *value, char *source, char splitChar);
void procHTTP(data19 *req);
void procTCP(data5 *req);
void pvdata(data9 *req, data3 *op);
void recvRepl(data9 *req);
void runProg();
void runService();
void sendScopeStatus(data19 *req);
void sendServerName();
void sendStatus(data19 *req);
void setLeaseExpiry(data7 *dhcpEntry);
void setLeaseExpiry(data7 *dhcpEntry, MYDWORD lease);
void setTempLease(data7 *dhcpEntry);
void showError(MYDWORD enumber);
void uninstallService();
void updateDNS(data9 *req);
FILE *pullZone(SOCKET sock);
