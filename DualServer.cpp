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
// Dual Service.cpp
#include <stdio.h>
#include <winsock2.h>
#include <time.h>
#include <tchar.h>
#include <ws2tcpip.h>
#include <limits.h>
#include <iphlpapi.h>
#include <process.h>
#include <math.h>
#include "DualServer.h"

//Global Variables
bool kRunning = true;
bool verbatim = false;
SERVICE_STATUS serviceStatus;
SERVICE_STATUS_HANDLE serviceStatusHandle = 0;
HANDLE stopServiceEvent = 0;
//Network network;
Network network;
Config config;
DHCPRequest token;
DHCPRequest dhcpRequest;
DNSRequest dnsr;
Lump lump;
data18 magin;
_Byte currentInd = 0;
hostMap dnsCache[2];
dhcpMap dhcpCache;
expiryMap dnsAge[2];
//expiryMap dhcpAge;
char serviceName[] = "DUALServer";
char displayName[] = "Dual DHCP DNS Service";
//char tempbuff[512];
//char extbuff[512];
//char logBuff[512];
char htmlTitle[256] = "";
char filePATH[_MAX_PATH];
char iniFile[_MAX_PATH];
char leaFile[_MAX_PATH];
char logFile[_MAX_PATH];
char htmFile[_MAX_PATH];
char lnkFile[_MAX_PATH];
char tempFile[_MAX_PATH];
char cliFile[_MAX_PATH];
char arpa[] = ".in-addr.arpa";
char ip6arpa[] = ".ip6.arpa";
bool dhcpService = true;
bool DNSService = true;
time_t t = time(NULL);
timeval tv;
fd_set readfds;
fd_set writefds;
HANDLE lEvent;
HANDLE fEvent;
HANDLE rEvent;

//constants
const char NBSP = 32;
const char RANGESET[] = "RANGE_SET";
const char GLOBALOPTIONS[] = "GLOBAL_OPTIONS";
const char base64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const char send200[] = "HTTP/1.1 200 OK\r\nDate: %s\r\nLast-Modified: %s\r\nContent-Type: text/html\r\nConnection: Close\r\nContent-Length:         \r\n\r\n";
const char send200JSON[] = "HTTP/1.1 200 OK\r\nDate: %s\r\nLast-Modified: %s\r\nContent-Type: application/json\r\nConnection: Close\r\nContent-Length:         \r\n\r\n";
//const char send200[] = "HTTP/1.1 200 OK\r\nDate: %s\r\nLast-Modified: %s\r\nContent-Type: text/html\r\nConnection: Close\r\nTransfer-Encoding: chunked\r\n";
//const char send403[] = "HTTP/1.1 403 Forbidden\r\nDate: %s\r\nLast-Modified: %s\r\nContent-Type: text/html\r\nConnection: Close\r\n\r\n";
const char send403[] = "HTTP/1.1 403 Forbidden\r\n\r\n<h1>403 Forbidden</h1>";
const char send404[] = "HTTP/1.1 404 Not Found\r\n\r\n<h1>404 Not Found</h1>";
const char td200[] = "<td>%s</td>";
const char sVersion[] = "Dual DHCP DNS Server (2016) Version 0.0.1 Windows Alpha Build";
const char htmlStart[] = "<html>\n<head>\n<title>%s</title><meta http-equiv=\"refresh\" content=\"60\">\n<meta http-equiv=\"cache-control\" content=\"no-cache\">\n</head>\n";
//const char bodyStart[] = "<body bgcolor=\"#cccccc\"><table width=\"800\"><tr><td align=\"center\"><font size=\"5\"><b>%s</b></font></b></b></td></tr><tr><td align=\"right\"><a target=\"_new\" href=\"http://dhcp-dns-server.sourceforge.net/\">http://dhcp-dns-server.sourceforge.net/</b></b></td></tr></table>";
const char bodyStart[] = "<body bgcolor=\"#cccccc\"><table width=640><tr><td align=\"center\"><font size=\"5\"><b>%s</b></font></td></tr><tr><td align=\"right\"><a target=\"_new\" href=\"http://dhcp-dns-server.sourceforge.net\">https://github.com/ajschlosser/Dual-DHCP-DNS-Server</td></tr></table>";
//const char bodyStart[] = "<body bgcolor=\"#cccccc\"><table width=640><tr><td align=\"center\"><font size=\"5\"><b>%s</b></font></td></tr><tr><td align=\"center\"><font size=\"5\">%s</font></td></tr></table>";
const data4 opData[] =
    {
		{ "SubnetMask", 1, 3 , 1},
		{ "TimeOffset", 2, 4 , 1},
		{ "Router", 3, 3 , 1},
		{ "TimeServer", 4, 3 , 1},
		{ "NameServer", 5, 3 , 1},
		{ "DomainServer", 6, 3 , 1},
		{ "LogServer", 7, 3 , 1},
		{ "QuotesServer", 8, 3 , 1},
		{ "LPRServer", 9, 3 , 1},
		{ "ImpressServer", 10, 3 , 1},
		{ "RLPServer", 11, 3, 1},
		{ "Hostname", 12, 1, 1},
		{ "BootFileSize", 13, 5 , 1},
		{ "MeritDumpFile", 14, 1 , 1},
		{ "DomainName", 15, 1 , 1},
		{ "SwapServer", 16, 3 , 1},
		{ "RootPath", 17, 1 , 1},
		{ "ExtensionFile", 18, 1 , 1},
		{ "ForwardOn/Off", 19, 7 , 1},
		{ "SrcRteOn/Off", 20, 7 , 1},
		{ "PolicyFilter", 21, 8 , 1},
		{ "MaxDGAssembly", 22, 5 , 1},
		{ "DefaultIPTTL", 23, 6 , 1},
		{ "MTUTimeout", 24, 4 , 1},
		{ "MTUPlateau", 25, 2 , 1},
		{ "MTUInterface", 26, 5 , 1},
		{ "MTUSubnet", 27, 7 , 1},
		{ "BroadcastAddress", 28, 3 , 1},
		{ "MaskDiscovery", 29, 7 , 1},
		{ "MaskSupplier", 30, 7 , 1},
		{ "RouterDiscovery", 31, 7 , 1},
		{ "RouterRequest", 32, 3 , 1},
		{ "StaticRoute", 33, 8 , 1},
		{ "Trailers", 34, 7 , 1},
		{ "ARPTimeout", 35, 4 , 1},
		{ "Ethernet", 36, 7 , 1},
		{ "DefaultTCPTTL", 37, 6 , 1},
		{ "KeepaliveTime", 38, 4 , 1},
		{ "KeepaliveData", 39, 7 , 1},
		{ "NISDomain", 40, 1 , 1},
		{ "NISServers", 41, 3 , 1},
		{ "NTPServers", 42, 3 , 1},
		{ "VendorSpecificInf", 43, 2 , 0},
		{ "NETBIOSNameSrv", 44, 3 , 1},
		{ "NETBIOSDistSrv", 45, 3 , 1},
		{ "NETBIOSNodeType", 46, 6 , 1},
		{ "NETBIOSScope", 47, 1 , 1},
		{ "XWindowFont", 48, 1 , 1},
		{ "XWindowManager", 49, 3 , 1},
		{ "AddressRequest", 50, 3, 0},
		{ "AddressTime", 51, 4 , 1},
		{ "OverLoad", 52, 7, 0},
		{ "DHCPMsgType", 53, 6, 0},
		{ "DHCPServerId", 54, 3, 0},
		{ "ParameterList", 55, 2 , 0},
		{ "DHCPMessage", 56, 1, 0},
		{ "DHCPMaxMsgSize", 57, 5, 0},
		{ "RenewalTime", 58, 4 , 1},
		{ "RebindingTime", 59, 4 , 1},
		{ "ClassId", 60, 1, 0},
		{ "ClientId", 61, 2, 0},
		{ "NetWareIPDomain", 62, 1 , 1},
		{ "NetWareIPOption", 63, 2 , 1},
		{ "NISDomainName", 64, 1 , 1},
		{ "NISServerAddr", 65, 3 , 1},
		{ "TFTPServerName", 66, 1 , 1},
		{ "BootFileOption", 67, 1 , 1},
		{ "HomeAgentAddrs", 68, 3 , 1},
		{ "SMTPServer", 69, 3 , 1},
		{ "POP3Server", 70, 3 , 1},
		{ "NNTPServer", 71, 3 , 1},
		{ "WWWServer", 72, 3 , 1},
		{ "FingerServer", 73, 3 , 1},
		{ "IRCServer", 74, 3 , 1},
		{ "StreetTalkServer", 75, 3 , 1},
		{ "STDAServer", 76, 3 , 1},
		{ "UserClass", 77, 1, 0},
		{ "DirectoryAgent", 78, 1 , 1},
		{ "ServiceScope", 79, 1 , 1},
		{ "RapidCommit", 80, 2, 0},
		{ "ClientFQDN", 81, 2, 0},
		{ "RelayAgentInformation", 82, 2, 0},
		{ "iSNS", 83, 1 , 1},
		{ "NDSServers", 85, 3 , 1},
		{ "NDSTreeName", 86, 1 , 1},
		{ "NDSContext", 87, 1 , 1},
		{ "LDAP", 95, 1 , 1},
		{ "PCode", 100, 1 , 1},
		{ "TCode", 101, 1 , 1},
		{ "NetInfoAddress", 112, 3 , 1},
		{ "NetInfoTag", 113, 1 , 1},
		{ "URL", 114, 1 , 1},
		{ "AutoConfig", 116, 7 , 1},
		{ "NameServiceSearch", 117, 2 , 1},
		{ "SubnetSelectionOption", 118, 3 , 1},
		{ "DomainSearch", 119, 1 , 1},
		{ "SIPServersDHCPOption", 120, 1 , 1},
		{ "121", 121, 1 , 1},
		{ "CCC", 122, 1 , 1},
		{ "TFTPServerIPaddress", 128, 3 , 1},
		{ "CallServerIPaddress", 129, 3 , 1},
		{ "DiscriminationString", 130, 1 , 1},
		{ "RemoteStatisticsServerIPAddress", 131, 3 , 1},
		{ "HTTPProxyPhone", 135, 3 , 1},
		{ "OPTION_CAPWAP_AC_V4", 138, 1 , 1},
		{ "OPTIONIPv4_AddressMoS", 139, 1 , 1},
		{ "OPTIONIPv4_FQDNMoS", 140, 1 , 1},
		{ "SIPUAServiceDomains", 141, 1 , 1},
		{ "OPTIONIPv4_AddressANDSF", 142, 1 , 1},
		{ "IPTelephone", 176, 1 , 1},
		{ "ConfigurationFile", 209, 1 , 1},
		{ "PathPrefix", 210, 1 , 1},
		{ "RebootTime", 211, 4 , 1},
		{ "OPTION_6RD", 212, 1 , 1},
		{ "OPTION_V4_ACCESS_DOMAIN", 213, 1 , 1},
		{ "BootFileName", 253, 1 , 1},
        { "NextServer", 254, 3, 1},
    };

void WINAPI ServiceControlHandler(DWORD controlCode)
{
	switch (controlCode)
	{
		case SERVICE_CONTROL_INTERROGATE:
			break;

		case SERVICE_CONTROL_SHUTDOWN:
		case SERVICE_CONTROL_STOP:
			serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
			serviceStatus.dwWaitHint = 20000;
			serviceStatus.dwCheckPoint = 1;
			SetServiceStatus(serviceStatusHandle, &serviceStatus);
			kRunning = false;

			SetEvent(stopServiceEvent);
			return;

		case SERVICE_CONTROL_PAUSE:
			break;

		case SERVICE_CONTROL_CONTINUE:
			break;

		default:
			if (controlCode >= 128 && controlCode <= 255)
				break;
			else
				break;
	}

	SetServiceStatus(serviceStatusHandle, &serviceStatus);
}

void WINAPI ServiceMain(DWORD /*argc*/, TCHAR* /*argv*/[])
{
	char logBuff[512];
	serviceStatus.dwServiceType = SERVICE_WIN32;
	serviceStatus.dwCurrentState = SERVICE_STOPPED;
	serviceStatus.dwControlsAccepted = 0;
	serviceStatus.dwWin32ExitCode = NO_ERROR;
	serviceStatus.dwServiceSpecificExitCode = NO_ERROR;
	serviceStatus.dwCheckPoint = 0;
	serviceStatus.dwWaitHint = 0;

	serviceStatusHandle = RegisterServiceCtrlHandler(serviceName, ServiceControlHandler);

	if (serviceStatusHandle)
	{
		serviceStatus.dwCurrentState = SERVICE_START_PENDING;
		SetServiceStatus(serviceStatusHandle, &serviceStatus);

		if (_beginthread(init, 0, 0) == 0)
		{
			if (verbatim || config.dnsLogLevel || config.dhcpLogLevel)
			{
				sprintf(logBuff, "Thread Creation Failed");
				logMessage(logBuff, 1);
			}
			exit(-1);
		}

		tv.tv_sec = 20;
		tv.tv_usec = 0;

		stopServiceEvent = CreateEvent(0, FALSE, FALSE, 0);
		serviceStatus.dwControlsAccepted |= (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
		serviceStatus.dwCurrentState = SERVICE_RUNNING;
		SetServiceStatus(serviceStatusHandle, &serviceStatus);

		do
		{
			if (!network.ready)
			{
				Sleep(1000);
				network.busy = false;
				continue;
			}

			if (!network.dhcpConn[0].ready && !network.DNS_UDPConnections[0].ready)
			{
				Sleep(1000);
				network.busy = false;
				continue;
			}

			//Sleep(200000);
			//debug("good");

			FD_ZERO(&readfds);
			network.busy = true;

			if (dhcpService)
			{
				if (network.HTTPConnection.ready)
					FD_SET(network.HTTPConnection.sock, &readfds);
				if (network.APIConnection.ready)
					FD_SET(network.APIConnection.sock, &readfds);

				for (int i = 0; i < MAX_SERVERS && network.dhcpConn[i].ready; i++)
					FD_SET(network.dhcpConn[i].sock, &readfds);

				if (config.dhcpReplConn.ready)
					FD_SET(config.dhcpReplConn.sock, &readfds);
			}

			if (DNSService)
			{
				for (int i = 0; i < MAX_SERVERS && network.DNS_UDPConnections[i].ready; i++)
					FD_SET(network.DNS_UDPConnections[i].sock, &readfds);

				for (int i = 0; i < MAX_SERVERS && network.DNS_TCPConnections[i].ready; i++)
					FD_SET(network.DNS_TCPConnections[i].sock, &readfds);

				if (network.forwConn.ready)
					FD_SET(network.forwConn.sock, &readfds);
			}

			if (select(network.maxFD, &readfds, NULL, NULL, &tv))
			{
				t = time(NULL);

				if (dhcpService)
				{
					if (network.HTTPConnection.ready && FD_ISSET(network.HTTPConnection.sock, &readfds))
					{
						SocketRequest *req = (SocketRequest*)calloc(1, sizeof(SocketRequest));

						if (req)
						{
							req->sockLen = sizeof(req->remote);
							req->sock = accept(network.HTTPConnection.sock, (sockaddr*)&req->remote, &req->sockLen);
							errno = WSAGetLastError();

							if (errno || req->sock == INVALID_SOCKET)
							{
								sprintf(logBuff, "Accept Failed, WSAError %u", errno);
								logDHCPMessage(logBuff, 1);
								free(req);
							}
							else
								processHTTP(req);
						}
						else
						{
							sprintf(logBuff, "Memory Error");
							logDHCPMessage(logBuff, 1);
						}
					}

					if (network.APIConnection.ready && FD_ISSET(network.APIConnection.sock, &readfds))
					{
						SocketRequest *req = (SocketRequest*)calloc(1, sizeof(SocketRequest));

						if (req)
						{
							req->sockLen = sizeof(req->remote);
							req->sock = accept(network.APIConnection.sock, (sockaddr*)&req->remote, &req->sockLen);
							errno = WSAGetLastError();

							if (errno || req->sock == INVALID_SOCKET)
							{
								sprintf(logBuff, "Accept Failed, WSAError %u", errno);
								logDHCPMessage(logBuff, 1);
								free(req);
							}
							else
								processHTTP(req);
						}
						else
						{
							sprintf(logBuff, "Memory Error");
							logDHCPMessage(logBuff, 1);
						}
					}

					if (config.dhcpReplConn.ready && FD_ISSET(config.dhcpReplConn.sock, &readfds))
					{
						errno = 0;
						dhcpRequest.sockLen = sizeof(dhcpRequest.remote);

						dhcpRequest.bytes = recvfrom(config.dhcpReplConn.sock,
											   dhcpRequest.raw,
											   sizeof(dhcpRequest.raw),
											   0,
											   (sockaddr*)&dhcpRequest.remote,
											   &dhcpRequest.sockLen);

						errno = WSAGetLastError();

						if (errno || dhcpRequest.bytes <= 0)
							config.dhcpRepl = 0;
					}

					for (int i = 0; i < MAX_SERVERS && network.dhcpConn[i].ready; i++)
					{
						if (FD_ISSET(network.dhcpConn[i].sock, &readfds) && gdmess(&dhcpRequest, i) && sdmess(&dhcpRequest))
							alad(&dhcpRequest);
					}
				}

				if (DNSService)
				{
					for (int i = 0; i < MAX_SERVERS && network.DNS_UDPConnections[i].ready; i++)
					{
						if (FD_ISSET(network.DNS_UDPConnections[i].sock, &readfds))
						{
							if (gdnmess(&dnsr, i))
							{
								if (scanloc(&dnsr))
								{
									if (dnsr.dnsPacket->header.answersCount)
									{
										if (verbatim || config.dnsLogLevel >= 2)
										{
											if (dnsr.dnsType == DNS_TYPE_SOA)
												sprintf(logBuff, "SOA Sent for zone %s", dnsr.query);
											else if (dnsr.dnsType == DNS_TYPE_NS)
												sprintf(logBuff, "NS Sent for zone %s", dnsr.query);
											else if (dnsr.cType == CTYPE_CACHED)
												sprintf(logBuff, "%s resolved from Cache to %s", strquery(&dnsr), getResult(&dnsr));
											else
												sprintf(logBuff, "%s resolved Locally to %s", strquery(&dnsr), getResult(&dnsr));

											logDNSMessage(&dnsr, logBuff, 2);
										}
									}
 									else if (dnsr.dnsPacket->header.responseCode == RCODE_NOERROR)
 									{
										dnsr.dnsPacket->header.responseCode = RCODE_NAMEERROR;

										if (verbatim || config.dnsLogLevel >= 2)
										{
											sprintf(logBuff, "%s not found", strquery(&dnsr));
											logDNSMessage(&dnsr, logBuff, 2);
										}
									}
									sdnmess(&dnsr);
								}
								else if (!fdnmess(&dnsr))
								{
									if (!dnsr.dnsPacket->header.answersCount && (dnsr.dnsPacket->header.responseCode == RCODE_NOERROR || dnsr.dnsPacket->header.responseCode == RCODE_NAMEERROR))
									{
										dnsr.dnsPacket->header.responseCode = RCODE_NAMEERROR;

										if (verbatim || config.dnsLogLevel >= 2)
										{
											sprintf(logBuff, "%s not found", strquery(&dnsr));
											logDNSMessage(&dnsr, logBuff, 2);
										}
									}
									sdnmess(&dnsr);
								}
							}
							else if (dnsr.dnsPacket)
								sdnmess(&dnsr);
						}
					}

					for (int i = 0; i < MAX_SERVERS && network.DNS_TCPConnections[i].ready; i++)
					{
						if (FD_ISSET(network.DNS_TCPConnections[i].sock, &readfds))
						{
							dnsr.sockInd = i;
							dnsr.sockLen = sizeof(dnsr.remote);
							errno = 0;
							dnsr.sock = accept(network.DNS_TCPConnections[i].sock, (sockaddr*)&dnsr.remote, &dnsr.sockLen);
							errno = WSAGetLastError();

							if (dnsr.sock == INVALID_SOCKET || errno)
							{
								if (verbatim || config.dnsLogLevel)
								{
									sprintf(logBuff, "Accept Failed, WSAError=%u", errno);
									logDNSMessage(logBuff, 1);
								}
							}
							else
								processTCP(&dnsr);
						}
					}

					if (network.forwConn.ready && FD_ISSET(network.forwConn.sock, &readfds))
					{
						if (frdnmess(&dnsr))
						{
							sdnmess(&dnsr);

							if (verbatim || config.dnsLogLevel >= 2)
							{
								if (dnsr.dnsIndex < MAX_SERVERS)
								{
									if (dnsr.dnsPacket->header.answersCount)
									{
										if (getResult(&dnsr))
											sprintf(logBuff, "%s resolved from Forwarding Server as %s", strquery(&dnsr), dnsr.tempname);
										else
											sprintf(logBuff, "%s resolved from Forwarding Server", strquery(&dnsr));
									}
									else
										sprintf(logBuff, "%s not found by Forwarding Server", strquery(&dnsr));
								}
								else
								{
									if (dnsr.dnsPacket->header.answersCount)
									{
										if (getResult(&dnsr))
											sprintf(logBuff, "%s resolved from Conditional Forwarder as %s", strquery(&dnsr), dnsr.tempname);
										else
											sprintf(logBuff, "%s resolved from Conditional Forwarder", strquery(&dnsr));
									}
									else
										sprintf(logBuff, "%s not found by Conditional Forwarder", strquery(&dnsr));
								}

								logDNSMessage(&dnsr, logBuff, 2);
							}
						}
					}
				}
			}
			else
				t = time(NULL);

			if (magin.done)
			{
				currentInd = magin.currentInd;
				magin.done = false;
				//sprintf(logBuff, "New Index=%u", currentInd);
				//logMessage(logBuff, 2);
			}
			else
				checkSize();
		}
		while (WaitForSingleObject(stopServiceEvent, 0) == WAIT_TIMEOUT);

		serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		//serviceStatus.dwCheckPoint = 2;
		//serviceStatus.dwWaitHint = 1000;
		SetServiceStatus(serviceStatusHandle, &serviceStatus);
		sprintf(logBuff, "Closing Network Connections...");
		logMessage(logBuff, 1);
		closeConn();

        if (config.dhcpReplConn.ready)
            closesocket(config.dhcpReplConn.sock);

		sprintf(logBuff, "Dual Server Stopped !\n");
		logMessage(logBuff, 1);

		Sleep(2000);

		WSACleanup();

		serviceStatus.dwControlsAccepted &= ~(SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
		serviceStatus.dwCurrentState = SERVICE_STOPPED;
		SetServiceStatus(serviceStatusHandle, &serviceStatus);

		CloseHandle(stopServiceEvent);
		stopServiceEvent = 0;
	}
}

void closeConn()
{
    if (dhcpService)
    {
		if (network.HTTPConnection.ready)
			closesocket(network.HTTPConnection.sock);
			closesocket(network.APIConnection.sock);

        for (int i = 0; i < MAX_SERVERS && network.dhcpConn[i].loaded; i++)
        	if (network.dhcpConn[i].ready)
            	closesocket(network.dhcpConn[i].sock);
    }

    if (DNSService)
    {
        for (int i = 0; i < MAX_SERVERS && network.DNS_UDPConnections[i].loaded; i++)
        	if (network.DNS_UDPConnections[i].ready)
           		closesocket(network.DNS_UDPConnections[i].sock);

        for (int i = 0; i < MAX_SERVERS && network.DNS_TCPConnections[i].loaded; i++)
        	if (network.DNS_TCPConnections[i].ready)
            	closesocket(network.DNS_TCPConnections[i].sock);

        if (network.forwConn.ready)
        	closesocket(network.forwConn.sock);
    }
}

/*
void closeConn()
{
    if (dhcpService)
    {
		if (network.HTTPConnection.ready)
		{
			closesocket(network.HTTPConnection.sock);
			sprintf(logBuff, "HTTPConnection %s:%u closed", IP2String(ipbuff, network.HTTPConnection.server), network.HTTPConnection.port);
			logMessage(logBuff, 1);
		}

        for (int i = 0; i < MAX_SERVERS && network.dhcpConn[i].loaded; i++)
        	if (network.dhcpConn[i].ready)
        	{
            	closesocket(network.dhcpConn[i].sock);
				sprintf(logBuff, "dhcpConn[%u] %s:%u closed", i, IP2String(ipbuff, network.dhcpConn[i].server), network.dhcpConn[i].port);
				logMessage(logBuff, 1);
			}
    }

    if (DNSService)
    {
        for (int i = 0; i < MAX_SERVERS && network.DNS_UDPConnections[i].loaded; i++)
        	if (network.DNS_UDPConnections[i].ready)
        	{
           		closesocket(network.DNS_UDPConnections[i].sock);
				sprintf(logBuff, "DNS_UDPConnections %s:%u closed", IP2String(ipbuff, network.DNS_UDPConnections[i].server), network.DNS_UDPConnections[i].port);
				logMessage(logBuff, 1);
			}

        for (int i = 0; i < MAX_SERVERS && network.DNS_TCPConnections[i].loaded; i++)
        	if (network.DNS_TCPConnections[i].ready)
        	{
            	closesocket(network.DNS_TCPConnections[i].sock);
				sprintf(logBuff, "DNS_TCPConnections %s:%u closed", IP2String(ipbuff, network.DNS_TCPConnections[i].server), network.DNS_TCPConnections[i].port);
				logMessage(logBuff, 1);
			}

        if (network.forwConn.ready)
        {
        	closesocket(network.forwConn.sock);
			sprintf(logBuff, "forwConn %s:%u closed", IP2String(ipbuff, network.forwConn.server), network.forwConn.port);
			logMessage(logBuff, 1);
		}
    }
}
*/

void runService()
{
	SERVICE_TABLE_ENTRY serviceTable[] =
	    {
	        {serviceName, ServiceMain},
	        {0, 0}
	    };

	StartServiceCtrlDispatcher(serviceTable);
}

void showError(_DWord enumber)
{
	LPTSTR lpMsgBuf;
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		enumber,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		(LPTSTR)&lpMsgBuf,
		0,
		NULL
	);
	printf("%s\n", lpMsgBuf);
}

bool stopService(SC_HANDLE service)
{
	if (service)
	{
		SERVICE_STATUS serviceStatus;
		QueryServiceStatus(service, &serviceStatus);
		if (serviceStatus.dwCurrentState != SERVICE_STOPPED)
		{
			ControlService(service, SERVICE_CONTROL_STOP, &serviceStatus);
			printf("Stopping Service.");
			for (int i = 0; i < 100; i++)
			{
				QueryServiceStatus(service, &serviceStatus);
				if (serviceStatus.dwCurrentState == SERVICE_STOPPED)
				{
					printf("Stopped\n");
					return true;
				}
				else
				{
					Sleep(500);
					printf(".");
				}
			}
			printf("Failed\n");
			return false;
		}
	}
	return true;
}

void installService()
{
	SC_HANDLE serviceControlManager = OpenSCManager(0, 0, SC_MANAGER_CREATE_SERVICE | SERVICE_START);

	if (serviceControlManager)
	{
		TCHAR path[ _MAX_PATH + 1 ];
		if (GetModuleFileName(0, path, sizeof(path) / sizeof(path[0])) > 0)
		{
			SC_HANDLE service = CreateService(serviceControlManager,
											  serviceName, displayName,
											  SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
											  SERVICE_AUTO_START, SERVICE_ERROR_IGNORE, path,
											  0, 0, 0, 0, 0);
			if (service)
			{
				printf("Successfully installed.. !\n");
				StartService(service, 0, NULL);
				CloseServiceHandle(service);
			}
			else
			{
				showError(GetLastError());
			}
		}
		CloseServiceHandle(serviceControlManager);
	}
}

void uninstallService()
{
	SC_HANDLE serviceControlManager = OpenSCManager(0, 0, SC_MANAGER_CONNECT);

	if (serviceControlManager)
	{
		SC_HANDLE service = OpenService(serviceControlManager,
		                                serviceName, SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE);
		if (service)
		{
			if (stopService(service))
			{
				if (DeleteService(service))
					printf("Successfully Removed !\n");
				else
					showError(GetLastError());
			}
			else
				printf("Failed to Stop Service..\n");

			CloseServiceHandle(service);
		}
		else
			printf("Service Not Found..\n");

		CloseServiceHandle(serviceControlManager);
	}
}

int main(int argc, TCHAR* argv[])
{
	OSVERSIONINFO osvi;
	osvi.dwOSVersionInfoSize = sizeof(osvi);
	bool result = GetVersionEx(&osvi);

	if (result && osvi.dwPlatformId >= VER_PLATFORM_WIN32_NT)
	{
		if (argc > 1 && lstrcmpi(argv[1], TEXT("-i")) == 0)
		{
			installService();
		}
		else if (argc > 1 && lstrcmpi(argv[1], TEXT("-u")) == 0)
		{
			uninstallService();
		}
		else if (argc > 1 && lstrcmpi(argv[1], TEXT("-v")) == 0)
		{
			SC_HANDLE serviceControlManager = OpenSCManager(0, 0, SC_MANAGER_CONNECT);
			bool serviceStopped = true;

			if (serviceControlManager)
			{
				SC_HANDLE service = OpenService(serviceControlManager, serviceName, SERVICE_QUERY_STATUS | SERVICE_STOP);

				if (service)
				{
					serviceStopped = stopService(service);
					CloseServiceHandle(service);
				}
				CloseServiceHandle(serviceControlManager);
			}

			if (serviceStopped)
			{
				verbatim = true;
				runProg();
			}
			else
				printf("Failed to Stop Service\n");
		}
		else
			runService();
	}
	else if (argc == 1 || lstrcmpi(argv[1], TEXT("-v")) == 0)
	{
		verbatim = true;
		runProg();
	}
	else
		printf("This option is not available on Windows95/98/ME\n");

	return 0;
}

void runProg()
{
	//printf("%i\n",t);
	//printf("%i\n",sizeof(CachedData));
	//printf("%d\n",dnsCache[currentInd].max_size());

	char logBuff[512];

	if (_beginthread(init, 0, 0) == 0)
	{
		if (verbatim || config.dnsLogLevel || config.dhcpLogLevel)
		{
			sprintf(logBuff, "Thread Creation Failed");
			logMessage(logBuff, 1);
		}
		exit(-1);
	}

	tv.tv_sec = 20;
	tv.tv_usec = 0;

	do
	{
		FD_ZERO(&readfds);

		if (!network.ready)
		{
			Sleep(1000);
			network.busy = false;
			continue;
		}

		if (!network.dhcpConn[0].ready && !network.DNS_UDPConnections[0].ready)
		{
			Sleep(1000);
			network.busy = false;
			continue;
		}

		network.busy = true;

		if (dhcpService)
		{
			if (network.HTTPConnection.ready)
				FD_SET(network.HTTPConnection.sock, &readfds);

			for (int i = 0; i < MAX_SERVERS && network.dhcpConn[i].ready; i++)
				FD_SET(network.dhcpConn[i].sock, &readfds);

			if (config.dhcpReplConn.ready)
				FD_SET(config.dhcpReplConn.sock, &readfds);
		}

		if (DNSService)
		{
			for (int i = 0; i < MAX_SERVERS && network.DNS_UDPConnections[i].ready; i++)
				FD_SET(network.DNS_UDPConnections[i].sock, &readfds);

			for (int i = 0; i < MAX_SERVERS && network.DNS_TCPConnections[i].ready; i++)
				FD_SET(network.DNS_TCPConnections[i].sock, &readfds);

			if (network.forwConn.ready)
				FD_SET(network.forwConn.sock, &readfds);
		}

		if (select(network.maxFD, &readfds, NULL, NULL, &tv))
		{
			t = time(NULL);

			if (dhcpService)
			{
				if (network.HTTPConnection.ready && FD_ISSET(network.HTTPConnection.sock, &readfds))
				{
					SocketRequest *req = (SocketRequest*)calloc(1, sizeof(SocketRequest));

					if (req)
					{
						req->sockLen = sizeof(req->remote);
						req->sock = accept(network.HTTPConnection.sock, (sockaddr*)&req->remote, &req->sockLen);
						errno = WSAGetLastError();

						if (errno || req->sock == INVALID_SOCKET)
						{
							sprintf(logBuff, "Accept Failed, WSAError %u", errno);
							logDHCPMessage(logBuff, 1);
							free(req);
						}
						else
							processHTTP(req);
					}
					else
					{
						sprintf(logBuff, "Memory Error");
						logDHCPMessage(logBuff, 1);
					}
				}

				if (config.dhcpReplConn.ready && FD_ISSET(config.dhcpReplConn.sock, &readfds))
				{
					errno = 0;
					dhcpRequest.sockLen = sizeof(dhcpRequest.remote);

					dhcpRequest.bytes = recvfrom(config.dhcpReplConn.sock,
										   dhcpRequest.raw,
										   sizeof(dhcpRequest.raw),
										   0,
										   (sockaddr*)&dhcpRequest.remote,
										   &dhcpRequest.sockLen);

					errno = WSAGetLastError();

					if (errno || dhcpRequest.bytes <= 0)
						config.dhcpRepl = 0;
				}

				for (int i = 0; i < MAX_SERVERS && network.dhcpConn[i].ready; i++)
				{
					if (FD_ISSET(network.dhcpConn[i].sock, &readfds) && gdmess(&dhcpRequest, i) && sdmess(&dhcpRequest))
						alad(&dhcpRequest);
				}
			}

			if (DNSService)
			{
				for (int i = 0; i < MAX_SERVERS && network.DNS_UDPConnections[i].ready; i++)
				{
					if (FD_ISSET(network.DNS_UDPConnections[i].sock, &readfds))
					{
						if (gdnmess(&dnsr, i))
						{
							if (scanloc(&dnsr))
							{
								if (dnsr.dnsPacket->header.answersCount)
								{
									if (verbatim || config.dnsLogLevel >= 2)
									{
										if (dnsr.dnsType == DNS_TYPE_SOA)
											sprintf(logBuff, "SOA Sent for zone %s", dnsr.query);
										else if (dnsr.dnsType == DNS_TYPE_NS)
											sprintf(logBuff, "NS Sent for zone %s", dnsr.query);
										else if (dnsr.cType == CTYPE_CACHED)
											sprintf(logBuff, "%s resolved from Cache to %s", strquery(&dnsr), getResult(&dnsr));
										else
											sprintf(logBuff, "%s resolved Locally to %s", strquery(&dnsr), getResult(&dnsr));

										logDNSMessage(&dnsr, logBuff, 2);
									}
								}
								else if (dnsr.dnsPacket->header.responseCode == RCODE_NOERROR)
								{
									dnsr.dnsPacket->header.responseCode = RCODE_NAMEERROR;

									if (verbatim || config.dnsLogLevel >= 2)
									{
										sprintf(logBuff, "%s not found", strquery(&dnsr));
										logDNSMessage(&dnsr, logBuff, 2);
									}
								}
								sdnmess(&dnsr);
							}
							else if (!fdnmess(&dnsr))
							{
								if (!dnsr.dnsPacket->header.answersCount && (dnsr.dnsPacket->header.responseCode == RCODE_NOERROR || dnsr.dnsPacket->header.responseCode == RCODE_NAMEERROR))
								{
									dnsr.dnsPacket->header.responseCode = RCODE_NAMEERROR;

									if (verbatim || config.dnsLogLevel >= 2)
									{
										sprintf(logBuff, "%s not found", strquery(&dnsr));
										logDNSMessage(&dnsr, logBuff, 2);
									}
								}
								sdnmess(&dnsr);
							}
						}
						else if (dnsr.dnsPacket)
							sdnmess(&dnsr);
					}
				}

				for (int i = 0; i < MAX_SERVERS && network.DNS_TCPConnections[i].ready; i++)
				{
					if (FD_ISSET(network.DNS_TCPConnections[i].sock, &readfds))
					{
						dnsr.sockInd = i;
						dnsr.sockLen = sizeof(dnsr.remote);
						errno = 0;
						dnsr.sock = accept(network.DNS_TCPConnections[i].sock, (sockaddr*)&dnsr.remote, &dnsr.sockLen);
						errno = WSAGetLastError();

						if (dnsr.sock == INVALID_SOCKET || errno)
						{
							if (verbatim || config.dnsLogLevel)
							{
								sprintf(logBuff, "Accept Failed, WSAError=%u", errno);
								logDNSMessage(logBuff, 1);
							}
						}
						else
							processTCP(&dnsr);
					}
				}

				if (network.forwConn.ready && FD_ISSET(network.forwConn.sock, &readfds))
				{
					if (frdnmess(&dnsr))
					{
						sdnmess(&dnsr);

						if (verbatim || config.dnsLogLevel >= 2)
						{
							if (dnsr.dnsIndex < MAX_SERVERS)
							{
								if (dnsr.dnsPacket->header.answersCount)
								{
									if (getResult(&dnsr))
										sprintf(logBuff, "%s resolved from Forwarding Server as %s", strquery(&dnsr), dnsr.tempname);
									else
										sprintf(logBuff, "%s resolved from Forwarding Server", strquery(&dnsr));
								}
								else
									sprintf(logBuff, "%s not found by Forwarding Server", strquery(&dnsr));
							}
							else
							{
								if (dnsr.dnsPacket->header.answersCount)
								{
									if (getResult(&dnsr))
										sprintf(logBuff, "%s resolved from Conditional Forwarder as %s", strquery(&dnsr), dnsr.tempname);
									else
										sprintf(logBuff, "%s resolved from Conditional Forwarder", strquery(&dnsr));
								}
								else
									sprintf(logBuff, "%s not found by Conditional Forwarder", strquery(&dnsr));
							}

							logDNSMessage(&dnsr, logBuff, 2);
						}
					}
				}
			}
		}
		else
			t = time(NULL);

		if (magin.done)
		{
			currentInd = magin.currentInd;
			magin.done = false;
			//sprintf(logBuff, "New Index=%u", currentInd);
			//logMessage(logBuff, 2);
		}
		else
			checkSize();
	}
	while (kRunning);

	kRunning = false;
    sprintf(logBuff, "Closing Network Connections...");
    logMessage(logBuff, 1);
	closeConn();

	if (config.dhcpReplConn.ready)
		closesocket(config.dhcpReplConn.sock);

    sprintf(logBuff, "Dual Server Stopped !\n");
    logMessage(logBuff, 1);

	WSACleanup();
}

bool checkQueue(char *query)
{
	if (strlen(query) >= UCHAR_MAX)
		return 0;

	while (true)
	{
		char *dp = strchr(query, '.');
		if (dp)
		{
			_Word size = dp - query;
			if (size >= 64)
				return 0;
			query += (size + 1);
		}
		else if (strlen(query) >= 64)
			return 0;
		else
			return 1;
	}
}

_Word fQu(char *query, DNSPacket *mess, char *raw)
{
	_Byte *xname = (_Byte*)query;
	_Byte *xraw = (_Byte*)raw;
	_Word retvalue = 0;
	bool goneout = false;

	while (true)
	{
		_Word size = *xraw;
		xraw++;

		if (!size)
			break;
		else if (size <= 63)
		{
			if (!goneout)
				retvalue += (size + 1);

			memcpy(xname, xraw, size);
			xname += size;
			xraw += size;

			if (!*xraw)
				break;

			*xname = '.';
			xname++;
		}
		else
		{
			if (!goneout)
				retvalue += 2;

			goneout = true;
			size %= 128;
			size %= 64;
			size *= 256;
			size += *xraw;
			xraw = (_Byte*)mess + size;
		}
	}

	*xname = 0;

	if (!goneout)
		retvalue++;

	return retvalue;
}

_Word qLen(char *query)
{
	_Word fullsize = 1;
	while (true)
	{
		char *dp = strchr(query, '.');

		if (dp != NULL)
		{
			int size = dp - query;
			query += (size + 1);
			fullsize += (size + 1);
		}
		else
		{
			int size = strlen(query);

			if (size)
				fullsize += (size + 1);

			break;
		}
	}
	//printf("%i\n",fullsize);
	return fullsize;
}

_Word pQu(char *raw, char *query)
{
	_Word fullsize = 1;
	while (true)
	{
		char *i = strchr(query, '.');

		if (i != NULL)
		{
			int size = i - query;
			*raw = size;
			raw++;
			memcpy(raw, query, size);
			raw += size;
			query += (size + 1);
			fullsize += (size + 1);
		}
		else
		{
			int size = strlen(query);
			if (size)
			{
				*raw = size;
				raw++;
				strcpy(raw, query);
				fullsize += (size + 1);
			}
			break;
		}
	}
	//printf("%i\n",fullsize);
	return fullsize;
}

_Word fUShort(void *raw)
{
	return ntohs(*((_Word*)raw));
}

_DWord fULong(void *raw)
{
	return ntohl(*((_DWord*)raw));
}

_DWord fIP(void *raw)
{
	return(*((_DWord*)raw));
}

_Byte pUShort(void *raw, _Word data)
{
	*((_Word*)raw) = htons(data);
	return sizeof(_Word);
}

_Byte pULong(void *raw, _DWord data)
{
	*((_DWord*)raw) = htonl(data);
	return sizeof(_DWord);
}

_Byte pIP(void *raw, _DWord data)
{
	*((_DWord*)raw) = data;
	return sizeof(_DWord);
}

void addRREmpty(DNSRequest *req)
{
	req->dnsPacket->header.recursionAvailable = 0;
	req->dnsPacket->header.authenticDataFromNamed = 0;
	req->dnsPacket->header.authoritativeAnswer = 0;
	req->dnsPacket->header.responseFlag = 1;
	req->dnsPacket->header.questionsCount = 0;
	req->dnsPacket->header.answersCount = 0;
	req->dnsPacket->header.authoritiesCount = 0;
	req->dnsPacket->header.additionalsCount = 0;
	req->dp = &req->dnsPacket->data;
}

void addRRError(DNSRequest *req, _Byte rcode)
{
	req->dnsPacket->header.responseFlag = 1;
	req->dp = req->raw + req->bytes;
	req->dnsPacket->header.responseCode = rcode;
}

void addRRNone(DNSRequest *req)
{
	if (network.DNS[0])
		req->dnsPacket->header.recursionAvailable = 1;
	else
		req->dnsPacket->header.recursionAvailable = 0;

	req->dnsPacket->header.authenticDataFromNamed = 0;
	req->dnsPacket->header.authoritativeAnswer = 0;

	req->dnsPacket->header.responseFlag = 1;
	req->dnsPacket->header.answersCount = 0;
	req->dnsPacket->header.authoritiesCount = 0;
	req->dnsPacket->header.additionalsCount = 0;
}

void addRRExt(DNSRequest *req)
{
	char tempbuff[512];
	char temp[2048];
	//char logBuff[512];
	//sprintf(logBuff, "%s=%s=%i\n", req->cname, req->query, req->bytes);
	//logMessage(logBuff, 2);

	if (strcasecmp(req->cname, req->query))
	{
		memcpy(temp, req->raw, req->bytes);
		DNSPacket *input = (DNSPacket*)temp;
		req->dnsPacket = (DNSPacket*)req->raw;

		req->dnsPacket->header.authoritativeAnswer = 0;
		req->dnsPacket->header.authenticDataFromNamed = 0;
		req->dnsPacket->header.questionsCount = htons(1);
		req->dnsPacket->header.answersCount = htons(1);

		//manuplate the response
		req->dp = &req->dnsPacket->data;
		req->dp += pQu(req->dp, req->query);
		req->dp += pUShort(req->dp, DNS_TYPE_A);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pQu(req->dp, req->query);
		req->dp += pUShort(req->dp, DNS_TYPE_CNAME);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, config.lease);
		req->dp += pUShort(req->dp, qLen(req->cname));
		req->dp += pQu(req->dp, req->cname);

		char *indp = &input->data;

		for (int i = 1; i <= ntohs(input->header.questionsCount); i++)
		{
			indp += fQu(tempbuff, input, indp);
			indp += 4;
		}

		for (int i = 1; i <= ntohs(input->header.answersCount); i++)
		{
			indp += fQu(tempbuff, input, indp);
			_Word type = fUShort(indp);
			req->dp += pQu(req->dp, tempbuff);
			memcpy(req->dp, indp, 8);
			req->dp += 8;
			indp += 8;
			//indp += 2; //type
			//indp += 2; //class
			//indp += 4; //ttl
			_Word zLen = fUShort(indp);
			indp += 2; //datalength

			switch (type)
			{
				case DNS_TYPE_A:
					req->dp += pUShort(req->dp, zLen);
					req->dp += pIP(req->dp, fIP(indp));
					break;
				case DNS_TYPE_CNAME:
					fQu(tempbuff, input, indp);
					_Word dl = pQu(req->dp + 2, tempbuff);
					req->dp += pUShort(req->dp, dl);
					req->dp += dl;
					break;
			}

			indp += zLen;
			req->dnsPacket->header.answersCount = htons(htons(req->dnsPacket->header.answersCount) + 1);
		}
	}
	else
	{
		req->dnsPacket = (DNSPacket*)req->raw;
		req->dp = req->raw + req->bytes;
	}
}

void addRRCache(DNSRequest *req, CachedData *cache)
{
	char tempbuff[512];

	if (req->dnsType == DNS_TYPE_A)
	{
		//manuplate the response
		//printf("%s=%s\n", req->cname, req->query);
		DNSPacket *input = (DNSPacket*)cache->response;
		char *indp = &input->data;
		req->dnsPacket = (DNSPacket*)req->raw;
		req->dp = &req->dnsPacket->data;

		req->dnsPacket->header.authoritativeAnswer = 0;
		req->dnsPacket->header.authenticDataFromNamed = 0;
		req->dnsPacket->header.answersCount = 0;
		req->dnsPacket->header.questionsCount = htons(1);

		req->dp = &req->dnsPacket->data;
		req->dp += pQu(req->dp, req->query);
		req->dp += pUShort(req->dp, req->dnsType);
		req->dp += pUShort(req->dp, req->qclass);

		if(strcasecmp(req->cname, req->query))
		{
			req->dp += pQu(req->dp, req->query);
			req->dp += pUShort(req->dp, DNS_TYPE_CNAME);
			req->dp += pUShort(req->dp, DNS_CLASS_IN);
			req->dp += pULong(req->dp, config.lease);
			req->dp += pUShort(req->dp, qLen(req->cname));
			req->dp += pQu(req->dp, req->cname);
			req->dnsPacket->header.answersCount = htons(1);
		}

		for (int i = 1; i <= ntohs(input->header.questionsCount); i++)
		{
			indp += fQu(tempbuff, input, indp);
			indp += 4;
		}

		for (int i = 1; i <= ntohs(input->header.answersCount); i++)
		{
			indp += fQu(tempbuff, input, indp);
			_Word type = fUShort(indp);

			if (!strcasecmp(tempbuff, req->query))
				strcpy(tempbuff, req->query);

			req->dp += pQu(req->dp, tempbuff);
			memcpy(req->dp, indp, 8);
			req->dp += 8;
			indp += 8;
			//indp += 2; //type
			//indp += 2; //class
			//indp += 4; //ttl
			_Word zLen = fUShort(indp);
			indp += 2; //datalength

			switch (type)
			{
				case DNS_TYPE_A:
					req->dp += pUShort(req->dp, zLen);
					req->dp += pIP(req->dp, fIP(indp));
					break;
				case DNS_TYPE_CNAME:
					fQu(tempbuff, input, indp);
					_Word dl = pQu(req->dp + 2, tempbuff);
					req->dp += pUShort(req->dp, dl);
					req->dp += dl;
					break;
			}

			indp += zLen;
			req->dnsPacket->header.answersCount = htons(htons(req->dnsPacket->header.answersCount) + 1);
		}
	}
	else if (req->dnsType == DNS_TYPE_PTR || req->dnsType == DNS_TYPE_ANY || req->dnsType == DNS_TYPE_AAAA)
	{
		req->dnsPacket = (DNSPacket*)req->raw;
		_Word xid = req->dnsPacket->header.queryID;
		memcpy(req->raw, cache->response, cache->bytes);
		req->dp = req->raw + cache->bytes;
		req->dnsPacket->header.queryID = xid;
	}
}

void addRRA(DNSRequest *req)
{
	if (req->qType == QTYPE_A_BARE && req->cType != CTYPE_NONE)
		sprintf(req->cname, "%s.%s", req->query, config.zone);

	if (strcasecmp(req->query, req->cname))
	{
		req->dnsPacket->header.answersCount = htons(htons(req->dnsPacket->header.answersCount) + 1);
		req->dp += pQu(req->dp, req->query);
		req->dp += pUShort(req->dp, DNS_TYPE_CNAME);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, config.lease);
		req->dp += pUShort(req->dp, qLen(req->cname));
		req->dp += pQu(req->dp, req->cname);
	}

	for (; req->iterBegin != dnsCache[currentInd].end(); req->iterBegin++)
	{
		CachedData *cache = req->iterBegin->second;

		if (strcasecmp(cache->name, req->mapname))
			break;

		if (cache->ip)
		{
			req->dnsPacket->header.answersCount = htons(htons(req->dnsPacket->header.answersCount) + 1);
			req->dp += pQu(req->dp, req->cname);
			req->dp += pUShort(req->dp, DNS_TYPE_A);
			req->dp += pUShort(req->dp, DNS_CLASS_IN);
			req->dp += pULong(req->dp, config.lease);
			req->dp += pUShort(req->dp, 4);
			req->dp += pIP(req->dp, cache->ip);
		}
	}
	//req->bytes = req->dp - req->raw;
}

void addRRPtr(DNSRequest *req)
{
	for (; req->iterBegin != dnsCache[currentInd].end(); req->iterBegin++)
	{
		if (CachedData *cache = req->iterBegin->second)
		{
			if (strcasecmp(cache->name, req->mapname))
				break;

			req->dp += pQu(req->dp, req->query);
			req->dp += pUShort(req->dp, DNS_TYPE_PTR);
			req->dp += pUShort(req->dp, DNS_CLASS_IN);
			req->dnsPacket->header.answersCount = htons(htons(req->dnsPacket->header.answersCount) + 1);
			req->dp += pULong(req->dp, config.lease);

			if (!cache->hostname[0])
				strcpy(req->cname, config.zone);
			else if (!strchr(cache->hostname, '.'))
				sprintf(req->cname, "%s.%s", cache->hostname, config.zone);
			else
				strcpy(req->cname, cache->hostname);

			req->dp += pUShort(req->dp, qLen(req->cname));
			req->dp += pQu(req->dp, req->cname);
		}
	}
	//req->bytes = req->dp - req->raw;
}

void addRRServerA(DNSRequest *req)
{
	if (req->qType == QTYPE_A_BARE)
		sprintf(req->cname, "%s.%s", req->query, config.zone);

	if (strcasecmp(req->query, req->cname))
	{
		req->dnsPacket->header.answersCount = htons(htons(req->dnsPacket->header.answersCount) + 1);
		req->dp += pQu(req->dp, req->query);
		req->dp += pUShort(req->dp, DNS_TYPE_CNAME);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, config.lease);
		req->dp += pUShort(req->dp, qLen(req->cname));
		req->dp += pQu(req->dp, req->cname);
	}

	hostMap::iterator it = req->iterBegin;

	for (;it != dnsCache[currentInd].end(); it++)
	{
		if (CachedData *cache = it->second)
		{
			if (strcasecmp(cache->name, req->mapname))
				break;

			if (cache->ip && cache->ip == network.DNS_UDPConnections[req->sockInd].server)
			{
				req->dnsPacket->header.answersCount = htons(htons(req->dnsPacket->header.answersCount) + 1);
				req->dp += pQu(req->dp, req->cname);
				req->dp += pUShort(req->dp, DNS_TYPE_A);
				req->dp += pUShort(req->dp, DNS_CLASS_IN);
				req->dp += pULong(req->dp, config.lease);
				req->dp += pUShort(req->dp, 4);
				req->dp += pIP(req->dp, cache->ip);
			}
		}
	}

	for (;req->iterBegin != dnsCache[currentInd].end(); req->iterBegin++)
	{
		if (CachedData *cache = req->iterBegin->second)
		{
			if (strcasecmp(cache->name, req->mapname))
				break;

			if (cache->ip && cache->ip != network.DNS_UDPConnections[req->sockInd].server)
			{
				req->dnsPacket->header.answersCount = htons(htons(req->dnsPacket->header.answersCount) + 1);
				req->dp += pQu(req->dp, req->cname);
				req->dp += pUShort(req->dp, DNS_TYPE_A);
				req->dp += pUShort(req->dp, DNS_CLASS_IN);
				req->dp += pULong(req->dp, config.lease);
				req->dp += pUShort(req->dp, 4);
				req->dp += pIP(req->dp, cache->ip);
			}
		}
	}
	//req->bytes = req->dp - req->raw;
}

void addRRAny(DNSRequest *req)
{
	if (req->qType == QTYPE_A_BARE || req->qType == QTYPE_A_LOCAL || req->qType == QTYPE_A_ZONE)
		req->iterBegin = dnsCache[currentInd].find(setMapName(req->tempname, req->mapname, DNS_TYPE_A));
	else if (req->qType == QTYPE_P_LOCAL || req->qType == QTYPE_P_ZONE)
		req->iterBegin = dnsCache[currentInd].find(setMapName(req->tempname, req->mapname, DNS_TYPE_PTR));
	else
		return;

	addRRNone(req);

	for (; req->iterBegin != dnsCache[currentInd].end(); req->iterBegin++)
	{
		if (CachedData *cache = req->iterBegin->second)
		{
			if (strcasecmp(cache->name, req->mapname))
				break;

			if (cache->expiry < t)
				continue;

			switch (cache->cType)
			{
				case CTYPE_LOCAL_A:
				case CTYPE_SERVER_A_AUTH:
				case CTYPE_STATIC_A_AUTH:
					req->dp += pQu(req->dp, req->cname);
					req->dp += pUShort(req->dp, DNS_TYPE_A);
					req->dp += pUShort(req->dp, DNS_CLASS_IN);
					req->dp += pULong(req->dp, config.lease);
					req->dp += pUShort(req->dp, 4);
					req->dp += pIP(req->dp, cache->ip);
					req->dnsPacket->header.answersCount = htons(htons(req->dnsPacket->header.answersCount) + 1);
					break;

				case CTYPE_EXT_CNAME:
					req->dp += pQu(req->dp, req->cname);
					req->dp += pUShort(req->dp, DNS_TYPE_CNAME);
					req->dp += pUShort(req->dp, DNS_CLASS_IN);
					req->dp += pULong(req->dp, config.lease);
					req->dp += pUShort(req->dp, qLen(cache->hostname));
					req->dp += pQu(req->dp, cache->hostname);
					req->dnsPacket->header.answersCount = htons(htons(req->dnsPacket->header.answersCount) + 1);
					break;

				case CTYPE_LOCAL_CNAME:
					req->dp += pQu(req->dp, req->cname);
					req->dp += pUShort(req->dp, DNS_TYPE_CNAME);
					req->dp += pUShort(req->dp, DNS_CLASS_IN);
					req->dp += pULong(req->dp, config.lease);
					sprintf(req->cname, "%s.%s", cache->hostname, config.zone);
					req->dp += pUShort(req->dp, qLen(req->cname));
					req->dp += pQu(req->dp, req->cname);
					req->dnsPacket->header.answersCount = htons(htons(req->dnsPacket->header.answersCount) + 1);
					break;

				case CTYPE_LOCAL_PTR_AUTH:
				case CTYPE_LOCAL_PTR_NAUTH:
				case CTYPE_STATIC_PTR_AUTH:
				case CTYPE_STATIC_PTR_NAUTH:
				case CTYPE_SERVER_PTR_AUTH:
				case CTYPE_SERVER_PTR_NAUTH:
					req->dp += pQu(req->dp, req->cname);
					req->dp += pUShort(req->dp, DNS_TYPE_PTR);
					req->dp += pUShort(req->dp, DNS_CLASS_IN);
					req->dp += pULong(req->dp, config.lease);

					if (!cache->hostname[0])
						strcpy(req->extbuff, config.zone);
					else if (!strchr(cache->hostname, '.'))
						strcpy(req->extbuff, cache->hostname);
					else
						sprintf(req->extbuff, "%s.%s", cache->hostname, config.zone);

					req->dp += pUShort(req->dp, qLen(req->extbuff));
					req->dp += pQu(req->dp, req->extbuff);
					req->dnsPacket->header.answersCount = htons(htons(req->dnsPacket->header.answersCount) + 1);
					break;
			}
		}
	}

	if (req->qType == QTYPE_A_ZONE)
	{
		addRRMX(req);
		addRRNS(req);
		addRRSOA(req);
	}
	else if (req->qType == QTYPE_P_ZONE)
	{
		addRRNS(req);
		addRRSOA(req);
	}
}

void addRRWildA(DNSRequest *req, _DWord ip)
{
	req->dnsPacket->header.answersCount = htons(htons(req->dnsPacket->header.answersCount) + 1);
	req->dp += pQu(req->dp, req->query);
	req->dp += pUShort(req->dp, DNS_TYPE_A);
	req->dp += pUShort(req->dp, DNS_CLASS_IN);
	req->dp += pULong(req->dp, config.lease);
	req->dp += pUShort(req->dp, 4);
	req->dp += pIP(req->dp, ip);
	//req->bytes = req->dp - req->raw;
}

void addRRLocalhostA(DNSRequest *req, CachedData *cache)
{
	if (strcasecmp(req->query, req->mapname))
	{
		req->dnsPacket->header.answersCount = htons(htons(req->dnsPacket->header.answersCount) + 1);
		req->dp += pQu(req->dp, req->query);
		req->dp += pUShort(req->dp, DNS_TYPE_CNAME);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, config.lease);
		req->dp += pUShort(req->dp, qLen(req->mapname));
		req->dp += pQu(req->dp, req->mapname);
	}

	req->dnsPacket->header.answersCount = htons(htons(req->dnsPacket->header.answersCount) + 1);
	req->dp += pQu(req->dp, req->mapname);
	req->dp += pUShort(req->dp, DNS_TYPE_A);
	req->dp += pUShort(req->dp, DNS_CLASS_IN);
	req->dp += pULong(req->dp, config.lease);
	req->dp += pUShort(req->dp, 4);
	req->dp += pIP(req->dp, cache->ip);
	//req->bytes = req->dp - req->raw;
}

void addRRLocalhostPtr(DNSRequest *req, CachedData *cache)
{
	req->dnsPacket->header.answersCount = htons(htons(req->dnsPacket->header.answersCount) + 1);
	req->dp += pQu(req->dp, req->query);
	req->dp += pUShort(req->dp, DNS_TYPE_PTR);
	req->dp += pUShort(req->dp, DNS_CLASS_IN);
	req->dp += pULong(req->dp, config.lease);
	req->dp += pUShort(req->dp, qLen(cache->hostname));
	req->dp += pQu(req->dp, cache->hostname);
	//req->bytes = req->dp - req->raw;
}

void addRRMX(DNSRequest *req)
{
	if (config.mxCount[currentInd])
	{
		for (int m = 0; m < config.mxCount[currentInd]; m++)
			addRRMXOne(req, m);
	}

	//req->bytes = req->dp - req->raw;
}

void addRRSOA(DNSRequest *req)
{
	if (config.authorized && config.expireTime > t)
	{
		req->dnsPacket->header.authenticDataFromNamed = 1;
		req->dnsPacket->header.authoritativeAnswer = 1;

		if (req->qType == QTYPE_A_BARE || req->qType == QTYPE_A_LOCAL || req->qType == QTYPE_A_ZONE)
			req->dp += pQu(req->dp, config.zone);
		else if (req->qType == QTYPE_P_LOCAL || req->qType == QTYPE_P_ZONE)
			req->dp += pQu(req->dp, config.authority);
		else
			return;

		if ((req->dnsType == DNS_TYPE_ANY || req->dnsType == DNS_TYPE_NS || req->dnsType == DNS_TYPE_SOA || req->dnsType == DNS_TYPE_AXFR) && (req->qType == QTYPE_A_ZONE || req->qType == QTYPE_P_ZONE))
			req->dnsPacket->header.answersCount = htons(htons(req->dnsPacket->header.answersCount) + 1);
		else
			req->dnsPacket->header.authoritiesCount = htons(htons(req->dnsPacket->header.authoritiesCount) + 1);

		req->dp += pUShort(req->dp, DNS_TYPE_SOA);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, config.lease);
		char *data = req->dp;
		req->dp += 2;
		req->dp += pQu(req->dp, config.nsP);
		sprintf(req->extbuff, "hostmaster.%s", config.zone);
		req->dp += pQu(req->dp, req->extbuff);

		if (req->qType == QTYPE_P_LOCAL || req->qType == QTYPE_P_EXT || req->qType == QTYPE_P_ZONE)
			req->dp += pULong(req->dp, config.serial2);
		else
			req->dp += pULong(req->dp, config.serial1);

		req->dp += pULong(req->dp, config.refresh);
		req->dp += pULong(req->dp, config.retry);
		req->dp += pULong(req->dp, config.expire);
		req->dp += pULong(req->dp, config.minimum);
		pUShort(data, (req->dp - data) - 2);
	}
	//req->bytes = req->dp - req->raw;
}

void addRRNS(DNSRequest *req)
{
	//printf("%s=%u\n", config.ns, config.expireTime);
	if (config.authorized && config.expireTime > t)
	{
		req->dnsPacket->header.authenticDataFromNamed = 1;
		req->dnsPacket->header.authoritativeAnswer = 1;

		if (config.nsP[0] && (config.replication != 2 || config.dnsRepl > t))
		{
			if (req->qType == QTYPE_A_BARE || req->qType == QTYPE_A_LOCAL || req->qType == QTYPE_A_ZONE)
				req->dp += pQu(req->dp, config.zone);
			else if (req->qType == QTYPE_P_LOCAL || req->qType == QTYPE_P_ZONE)
				req->dp += pQu(req->dp, config.authority);
			else
				return;

			if ((req->dnsType == DNS_TYPE_ANY || req->dnsType == DNS_TYPE_NS || req->dnsType == DNS_TYPE_SOA || req->dnsType == DNS_TYPE_AXFR) && (req->qType == QTYPE_A_ZONE || req->qType == QTYPE_P_ZONE))
				req->dnsPacket->header.answersCount = htons(htons(req->dnsPacket->header.answersCount) + 1);
			else
				req->dnsPacket->header.authoritiesCount = htons(htons(req->dnsPacket->header.authoritiesCount) + 1);

			req->dp += pUShort(req->dp, DNS_TYPE_NS);
			req->dp += pUShort(req->dp, DNS_CLASS_IN);
			req->dp += pULong(req->dp, config.expire);
			req->dp += pUShort(req->dp, qLen(config.nsP));
			req->dp += pQu(req->dp, config.nsP);
		}

		if (config.nsS[0] && (config.replication == 2 || config.dnsRepl > t))
		{
			if (req->qType == QTYPE_A_BARE || req->qType == QTYPE_A_LOCAL || req->qType == QTYPE_A_ZONE)
				req->dp += pQu(req->dp, config.zone);
			else if (req->qType == QTYPE_P_LOCAL || req->qType == QTYPE_P_ZONE)
				req->dp += pQu(req->dp, config.authority);
			else
				return;

			if ((req->dnsType == DNS_TYPE_ANY || req->dnsType == DNS_TYPE_NS || req->dnsType == DNS_TYPE_SOA || req->dnsType == DNS_TYPE_AXFR) && (req->qType == QTYPE_A_ZONE || req->qType == QTYPE_P_ZONE))
				req->dnsPacket->header.answersCount = htons(htons(req->dnsPacket->header.answersCount) + 1);
			else
				req->dnsPacket->header.authoritiesCount = htons(htons(req->dnsPacket->header.authoritiesCount) + 1);

			req->dp += pUShort(req->dp, DNS_TYPE_NS);
			req->dp += pUShort(req->dp, DNS_CLASS_IN);
			req->dp += pULong(req->dp, config.expire);
			req->dp += pUShort(req->dp, qLen(config.nsS));
			req->dp += pQu(req->dp, config.nsS);
		}
	}
	//req->bytes = req->dp - req->raw;
}

void addRRAd(DNSRequest *req)
{
	//printf("%s=%u\n", config.ns, config.expireTime);
	if (config.authorized && config.expireTime > t)
	{
		if (config.nsP[0] && (config.replication != 2 || config.dnsRepl > t))
		{
			req->dnsPacket->header.additionalsCount = htons(htons(req->dnsPacket->header.additionalsCount) + 1);
			req->dp += pQu(req->dp, config.nsP);

			req->dp += pUShort(req->dp, DNS_TYPE_A);
			req->dp += pUShort(req->dp, DNS_CLASS_IN);
			req->dp += pULong(req->dp, config.lease);
			req->dp += pUShort(req->dp, 4);

			if (config.replication)
				req->dp += pIP(req->dp, config.zoneServers[0]);
			else
				req->dp += pIP(req->dp, network.listenServers[req->sockInd]);
		}

		if (config.nsS[0] && (config.replication == 2 || config.dnsRepl > t))
		{
			req->dnsPacket->header.additionalsCount = htons(htons(req->dnsPacket->header.additionalsCount) + 1);
			req->dp += pQu(req->dp, config.nsS);
			req->dp += pUShort(req->dp, DNS_TYPE_A);
			req->dp += pUShort(req->dp, DNS_CLASS_IN);
			req->dp += pULong(req->dp, config.lease);
			req->dp += pUShort(req->dp, 4);
			req->dp += pIP(req->dp, config.zoneServers[1]);
		}
	}
	//req->bytes = req->dp - req->raw;
}

void addRRAOne(DNSRequest *req)
{
	if (CachedData *cache = req->iterBegin->second)
	{
		req->dnsPacket->header.answersCount = htons(htons(req->dnsPacket->header.answersCount) + 1);

		if (!cache->name[0])
			strcpy(req->cname, config.zone);
		else if (!strchr(cache->name, '.'))
			sprintf(req->cname, "%s.%s", cache->name, config.zone);
		else
			strcpy(req->cname, cache->name);

		req->dp += pQu(req->dp, req->cname);
		req->dp += pUShort(req->dp, DNS_TYPE_A);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, config.lease);
		req->dp += pUShort(req->dp, 4);
		req->dp += pIP(req->dp, cache->ip);
		//req->bytes = req->dp - req->raw;
	}
}

void addRRPtrOne(DNSRequest *req)
{
	if (CachedData *cache = req->iterBegin->second)
	{
		req->dnsPacket->header.answersCount = htons(htons(req->dnsPacket->header.answersCount) + 1);
		sprintf(req->cname, "%s%s", cache->name, arpa);
		req->dp += pQu(req->dp, req->cname);
		req->dp += pUShort(req->dp, DNS_TYPE_PTR);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, config.lease);

		if (!cache->hostname[0])
			strcpy(req->cname, config.zone);
		else if (!strchr(cache->hostname, '.'))
			sprintf(req->cname, "%s.%s", cache->hostname, config.zone);
		else
			strcpy(req->cname, cache->hostname);

		req->dp += pUShort(req->dp, qLen(req->cname));
		req->dp += pQu(req->dp, req->cname);
	}

	//req->bytes = req->dp - req->raw;
}

void addRRSTAOne(DNSRequest *req)
{
	if (CachedData *cache = req->iterBegin->second)
	{
		req->dnsPacket->header.answersCount = htons(htons(req->dnsPacket->header.answersCount) + 1);

		if (!cache->name[0])
			strcpy(req->cname, config.zone);
		else if (!strchr(cache->name, '.'))
			sprintf(req->cname, "%s.%s", cache->name, config.zone);
		else
			strcpy(req->cname, cache->name);

		req->dp += pQu(req->dp, req->cname);
		req->dp += pUShort(req->dp, DNS_TYPE_A);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, config.lease);
		req->dp += pUShort(req->dp, 4);
		req->dp += pIP(req->dp, cache->ip);
	}
	//req->bytes = req->dp - req->raw;
}

void addRRCNOne(DNSRequest *req)
{
	if (CachedData *cache = req->iterBegin->second)
	{
		req->dnsPacket->header.answersCount = htons(htons(req->dnsPacket->header.answersCount) + 1);

		if (!cache->name[0])
			strcpy(req->cname, config.zone);
		else if (strchr(cache->name, '.'))
			strcpy(req->cname, cache->name);
		else
			sprintf(req->cname, "%s.%s", cache->name, config.zone);

		req->dp += pQu(req->dp, req->cname);
		req->dp += pUShort(req->dp, DNS_TYPE_CNAME);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, config.lease);

		if (!cache->hostname[0])
			strcpy(req->cname, config.zone);
		else if (strchr(cache->hostname, '.'))
			strcpy(req->cname, cache->hostname);
		else
			sprintf(req->cname, "%s.%s", cache->hostname, config.zone);

		req->dp += pUShort(req->dp, qLen(req->cname));
		req->dp += pQu(req->dp, req->cname);
	}
	//req->bytes = req->dp - req->raw;
}

void addRRMXOne(DNSRequest *req, _Byte m)
{
	//req->dp += pQu(req->dp, req->query);
	req->dnsPacket->header.answersCount = htons(htons(req->dnsPacket->header.answersCount) + 1);
	req->dp += pQu(req->dp, config.zone);
	req->dp += pUShort(req->dp, DNS_TYPE_MX);
	req->dp += pUShort(req->dp, DNS_CLASS_IN);
	req->dp += pULong(req->dp, config.lease);
	req->dp += pUShort(req->dp, strlen(config.mxServers[currentInd][m].hostname) + 4);
	req->dp += pUShort(req->dp, config.mxServers[currentInd][m].pref);
	req->dp += pQu(req->dp, config.mxServers[currentInd][m].hostname);
	//req->bytes = req->dp - req->raw;
}

void processHTTP(SocketRequest *req)
{
	//debug("processHTTP");
	char logBuff[512];
	char tempbuff[512];
	req->ling.l_onoff = 1; //0 = off (l_linger ignored), nonzero = on
	req->ling.l_linger = 30; //0 = discard data, nonzero = wait for data sent
	setsockopt(req->sock, SOL_SOCKET, SO_LINGER, (const char*)&req->ling, sizeof(req->ling));

	timeval tv1;
	fd_set readfds1;
	FD_ZERO(&readfds1);
	tv1.tv_sec = 1;
	tv1.tv_usec = 0;
	FD_SET(req->sock, &readfds1);

	if (!select((req->sock + 1), &readfds1, NULL, NULL, &tv1))
	{
		sprintf(logBuff, "Client %s, HTTP Message Receive failed", IP2String(tempbuff, req->remote.sin_addr.s_addr));
		logDHCPMessage(logBuff, 1);
		closesocket(req->sock);
		free(req);
		return;
	}

	errno = 0;
	char buffer[1024];
	req->bytes = recv(req->sock, buffer, sizeof(buffer), 0);
	errno = WSAGetLastError();

	if (errno || req->bytes <= 0)
	{
		sprintf(logBuff, "Client %s, HTTP Message Receive failed, WSAError %d", IP2String(tempbuff, req->remote.sin_addr.s_addr), errno);
		logDHCPMessage(logBuff, 1);
		closesocket(req->sock);
		free(req);
		return;
	}
	else if (verbatim || config.dhcpLogLevel >= 2)
	{
		sprintf(logBuff, "Client %s, HTTP Request Received", IP2String(tempbuff, req->remote.sin_addr.s_addr));
		logDHCPMessage(logBuff, 2);
		//printf("%s\n", buffer);
	}

	if (config.HTTPClients[0] && !findServer(config.HTTPClients, 8, req->remote.sin_addr.s_addr))
	{
		if (verbatim || config.dhcpLogLevel >= 2)
		{
			sprintf(logBuff, "Client %s, HTTP Access Denied", IP2String(tempbuff, req->remote.sin_addr.s_addr));
			logDHCPMessage(logBuff, 2);
		}

		req->dp = (char*)calloc(1, sizeof(send403));
		req->memSize = sizeof(send403);
		req->bytes = sprintf(req->dp, send403);
		_beginthread(sendHTTP, 0, (void*)req);
		return;
	}

	buffer[sizeof(buffer) - 1] = 0;
	char *fp = NULL;
	char *end = strchr(buffer, '\n');

	if (end && end > buffer && (*(end - 1) == '\r'))
	{
		*(end - 1) = 0;

		if (myTokenize(buffer, buffer, " ", true) > 1)
			fp = myGetToken(buffer, 1);
	}

	if (fp && !strcasecmp(fp, "/"))
		sendStatus(req);
//	else if (fp && !strcasecmp(fp, "/scopestatus"))
//		sendScopeStatus(req);
	else
	{
		if (fp && (verbatim || config.dhcpLogLevel >= 2))
		{
			sprintf(logBuff, "Client %s, %s not found", IP2String(tempbuff, req->remote.sin_addr.s_addr), fp);
			logDHCPMessage(logBuff, 2);
		}
		else if (verbatim || config.dhcpLogLevel >= 2)
		{
			sprintf(logBuff, "Client %s, Invalid http request", IP2String(tempbuff, req->remote.sin_addr.s_addr));
			logDHCPMessage(logBuff, 2);
		}

		req->dp = (char*)calloc(1, sizeof(send404));
		req->bytes = sprintf(req->dp, send404);
		req->memSize = sizeof(send404);
		_beginthread(sendHTTP, 0, (void*)req);
		return;
	}
}

void sendStatus(SocketRequest *req)
{
	//debug("sendStatus");
	char ipbuff[16];
	char logBuff[512];
	char tempbuff[512];

	dhcpMap::iterator p;
	_DWord iip = 0;
	CachedData *dhcpEntry = NULL;
	//CachedData *cache = NULL;
	//printf("%d=%d\n", dhcpCache.size(), config.dhcpSize);
	req->memSize = 2048 + (135 * dhcpCache.size()) + (config.dhcpSize * 26);
	req->dp = (char*)calloc(1, req->memSize);

	if (!req->dp)
	{
		sprintf(logBuff, "Memory Error");
		logDHCPMessage(logBuff, 1);
		closesocket(req->sock);
		free(req);
		return;
	}

	char *fp = req->dp;
	char *maxData = req->dp + (req->memSize - 512);
	tm *ttm = gmtime(&t);
	strftime(tempbuff, sizeof(tempbuff), "%a, %d %b %Y %H:%M:%S GMT", ttm);
	fp += sprintf(fp, send200JSON, tempbuff, tempbuff);
	char *contentStart = fp;
	fp += sprintf(fp, "%s", "\"{\n\tleases: [\n");
	for (p = dhcpCache.begin(); kRunning && p != dhcpCache.end() && fp < maxData; p++)
	{
	    if ((dhcpEntry = p->second) && dhcpEntry->display && dhcpEntry->expiry >= t)
        {
            fp += sprintf(fp, "%s", "\t\t");
            fp += sprintf(fp, "%s", "{ ");
            fp += sprintf(fp, "MAC_Address: \"%s\", ", dhcpEntry->mapname);
            fp += sprintf(fp, "IP_Address: \"%s\", ", IP2String(tempbuff, dhcpEntry->ip));
	 		if (dhcpEntry->expiry >= INT_MAX)
	 			fp += sprintf(fp, "Expires: \"%s\"", "Infinity");
	 		else
	 		{
	 			tm *ttm = localtime(&dhcpEntry->expiry);
	 			strftime(tempbuff, sizeof(tempbuff), "%d-%b-%y %X", ttm);
	 			fp += sprintf(fp, "Expires: \"%s\"", tempbuff);
	 		}

	 		if (dhcpEntry->hostname[0])
	 		{
	 			strcpy(tempbuff, dhcpEntry->hostname);
	 			tempbuff[20] = 0;
	 			fp += sprintf(fp, ", Hostname: \"%s\"", tempbuff);
	 		}
	 		else {
                fp += sprintf(fp, "%s", ",");
	 		}
            fp += sprintf(fp, "%s", " }");
            if (std::distance(p, dhcpCache.end()) != 1) {
                fp += sprintf(fp, "%s", ",");
            }
            fp += sprintf(fp, "%s", "\n");
        }
	}
	fp += sprintf(fp, "%s", "\t]\n}\"");



	// fp += sprintf(fp, send200, tempbuff, tempbuff);
	// char *contentStart = fp;
	// fp += sprintf(fp, htmlStart, htmlTitle);
	// fp += sprintf(fp, bodyStart, sVersion);
	// fp += sprintf(fp, "<table border=\"1\" cellpadding=\"1\" width=\"640\" bgcolor=\"#b8b8b8\">\n");
	//
	// if (config.dhcpRepl > t)
	// {
	// 	fp += sprintf(fp, "<tr><th colspan=\"5\"><font size=\"5\"><i>Active Leases</i></font></th></tr>\n");
	// 	fp += sprintf(fp, "<tr><th>Mac Address</th><th>IP</th><th>Lease Expiry</th><th>Hostname (first 20 chars)</th><th>Server</th></tr>\n");
	// }
	// else
	// {
	// 	fp += sprintf(fp, "<tr><th colspan=\"4\"><font size=\"5\"><i>Active Leases</i></font></th></tr>\n");
	// 	fp += sprintf(fp, "<tr><th>Mac Address</th><th>IP</th><th>Lease Expiry</th><th>Hostname (first 20 chars)</th></tr>\n");
	// }
	//
	// for (p = dhcpCache.begin(); kRunning && p != dhcpCache.end() && fp < maxData; p++)
	// {
	// 	if ((dhcpEntry = p->second) && dhcpEntry->display && dhcpEntry->expiry >= t)
	// 	{
	// 		fp += sprintf(fp, "<tr>");
	// 		fp += sprintf(fp, td200, dhcpEntry->mapname);
	// 		fp += sprintf(fp, td200, IP2String(tempbuff, dhcpEntry->ip));
	//
	// 		if (dhcpEntry->expiry >= INT_MAX)
	// 			fp += sprintf(fp, td200, "Infinity");
	// 		else
	// 		{
	// 			tm *ttm = localtime(&dhcpEntry->expiry);
	// 			strftime(tempbuff, sizeof(tempbuff), "%d-%b-%y %X", ttm);
	// 			fp += sprintf(fp, td200, tempbuff);
	// 		}
	//
	// 		if (dhcpEntry->hostname[0])
	// 		{
	// 			strcpy(tempbuff, dhcpEntry->hostname);
	// 			tempbuff[20] = 0;
	// 			fp += sprintf(fp, td200, tempbuff);
	// 		}
	// 		else
	// 			fp += sprintf(fp, td200, "&nbsp;");
	//
	// 		if (config.dhcpRepl > t)
	// 		{
	// 			if (dhcpEntry->local && config.replication == 1)
	// 				fp += sprintf(fp, td200, "Primary");
	// 			else if (dhcpEntry->local && config.replication == 2)
	// 				fp += sprintf(fp, td200, "Secondary");
	// 			else if (config.replication == 1)
	// 				fp += sprintf(fp, td200, "Secondary");
	// 			else
	// 				fp += sprintf(fp, td200, "Primary");
	// 		}
	//
	// 		fp += sprintf(fp, "</tr>\n");
	// 	}
	// }

/*
	fp += sprintf(fp, "</table>\n<br>\n<table border=\"1\" width=\"640\" cellpadding=\"1\" bgcolor=\"#b8b8b8\">\n");
	fp += sprintf(fp, "<tr><th colspan=\"5\"><font size=\"5\"><i>Free Dynamic Leases</i></font></th></tr>\n");
	_Byte colNum = 0;

	for (char rangeInd = 0; kRunning && rangeInd < config.rangeCount && fp < maxData; rangeInd++)
	{
		for (_DWord ind = 0, iip = config.dhcpRanges[rangeInd].rangeStart; kRunning && iip <= config.dhcpRanges[rangeInd].rangeEnd; iip++, ind++)
		{
			if (config.dhcpRanges[rangeInd].expiry[ind] < t)
			{
				if (!colNum)
				{
					fp += sprintf(fp, "<tr>");
					colNum = 1;
				}
				else if (colNum < 5)
					colNum++;
				else
				{
					fp += sprintf(fp, "</tr>\n<tr>");
					colNum = 1;
				}

				fp += sprintf(fp, td200, IP2String(tempbuff, htonl(iip)));
			}
		}
	}

	if (colNum)
		fp += sprintf(fp, "</tr>\n");
*/
	// fp += sprintf(fp, "</table>\n<br>\n<table border=\"1\" cellpadding=\"1\" width=\"640\" bgcolor=\"#b8b8b8\">\n");
	// fp += sprintf(fp, "<tr><th colspan=\"4\"><font size=\"5\"><i>Free Dynamic Leases</i></font></th></tr>\n");
	// fp += sprintf(fp, "<tr><td><b>DHCP Range</b></td><td align=\"right\"><b>Available Leases</b></td><td align=\"right\"><b>Free Leases</b></td></tr>\n");
	//
	// for (char rangeInd = 0; kRunning && rangeInd < config.rangeCount && fp < maxData; rangeInd++)
	// {
	// 	float ipused = 0;
	// 	float ipfree = 0;
	// 	int ind = 0;
	//
	// 	for (_DWord iip = config.dhcpRanges[rangeInd].rangeStart; iip <= config.dhcpRanges[rangeInd].rangeEnd; iip++, ind++)
	// 	{
	// 		if (config.dhcpRanges[rangeInd].expiry[ind] < t)
	// 			ipfree++;
	// 		else if (config.dhcpRanges[rangeInd].dhcpEntry[ind] && !(config.dhcpRanges[rangeInd].dhcpEntry[ind]->fixed))
	// 			ipused++;
	// 	}
	//
	// 	IP2String(tempbuff, ntohl(config.dhcpRanges[rangeInd].rangeStart));
	// 	IP2String(ipbuff, ntohl(config.dhcpRanges[rangeInd].rangeEnd));
	// 	fp += sprintf(fp, "<tr><td>%s - %s</td><td align=\"right\">%5.0f</td><td align=\"right\">%5.0f</td></tr>\n", tempbuff, ipbuff, (ipused + ipfree), ipfree);
	// }
	//
	// fp += sprintf(fp, "</table>\n<br>\n<table border=\"1\" width=\"640\" cellpadding=\"1\" bgcolor=\"#b8b8b8\">\n");
	// fp += sprintf(fp, "<tr><th colspan=\"4\"><font size=\"5\"><i>Free Static Leases</i></font></th></tr>\n");
	// fp += sprintf(fp, "<tr><th>Mac Address</th><th>IP</th><th>Mac Address</th><th>IP</th></tr>\n");
	//
	// _Byte colNum = 0;
	//
	// for (p = dhcpCache.begin(); kRunning && p != dhcpCache.end() && fp < maxData; p++)
	// {
	// 	if ((dhcpEntry = p->second) && dhcpEntry->fixed && dhcpEntry->expiry < t)
	// 	{
	// 		if (!colNum)
	// 		{
	// 			fp += sprintf(fp, "<tr>");
	// 			colNum = 1;
	// 		}
	// 		else if (colNum == 1)
	// 		{
	// 			colNum = 2;
	// 		}
	// 		else if (colNum == 2)
	// 		{
	// 			fp += sprintf(fp, "</tr>\n<tr>");
	// 			colNum = 1;
	// 		}
	//
	// 		fp += sprintf(fp, td200, dhcpEntry->mapname);
	// 		fp += sprintf(fp, td200, IP2String(tempbuff, dhcpEntry->ip));
	// 	}
	// }
	//
	// if (colNum)
	// 	fp += sprintf(fp, "</tr>\n");
	//
	// fp += sprintf(fp, "</table>\n</body>\n</html>");
	_Byte x = sprintf(tempbuff, "%u", (fp - contentStart));
	memcpy((contentStart - 12), tempbuff, x);
	req->bytes = fp - req->dp;

	_beginthread(sendHTTP, 0, (void*)req);
	return;
}

/*
void sendScopeStatus(SocketRequest *req)
{
	//debug("sendScopeStatus");

	_Byte rangeCount = 0;
	req->memSize = 1536 + (150 * config.rangeCount);
	req->dp = (char*)calloc(1, req->memSize);

	if (!req->dp)
	{
		sprintf(logBuff, "Memory Error");
		logDHCPMessage(logBuff, 1);
		closesocket(req->sock);
		free(req);
		return;
	}

	char *fp = req->dp;
	char *maxData = req->dp + (req->memSize - 512);
	tm *ttm = gmtime(&t);
	strftime(tempbuff, sizeof(tempbuff), "%a, %d %b %Y %H:%M:%S GMT", ttm);
	fp += sprintf(fp, send200, tempbuff, tempbuff);
	char *contentStart = fp;
	fp += sprintf(fp, htmlStart, htmlTitle);
	fp += sprintf(fp, bodyStart, sVersion);
	fp += sprintf(fp, "<table border=\"1\" cellpadding=\"1\" width=\"640\" bgcolor=\"#b8b8b8\">\n");
	fp += sprintf(fp, "<tr><th colspan=\"4\"><font size=\"5\"><i>Scope Status</i></font></th></tr>\n");
	fp += sprintf(fp, "<tr><td><b>DHCP Range</b></td><td align=\"right\"><b>IPs Used</b></td><td align=\"right\"><b>IPs Free</b></td><td align=\"right\"><b>%% Free</b></td></tr>\n");
	_Byte colNum = 0;

	for (char rangeInd = 0; kRunning && rangeInd < config.rangeCount && fp < maxData; rangeInd++)
	{
		float ipused = 0;
		float ipfree = 0;
		int ind = 0;

		for (_DWord iip = config.dhcpRanges[rangeInd].rangeStart; iip <= config.dhcpRanges[rangeInd].rangeEnd; iip++, ind++)
		{
			if (config.dhcpRanges[rangeInd].expiry[ind] > t)
				ipused++;
			else
				ipfree++;
		}

		IP2String(tempbuff, ntohl(config.dhcpRanges[rangeInd].rangeStart));
		IP2String(req->extbuff, ntohl(config.dhcpRanges[rangeInd].rangeEnd));
		fp += sprintf(fp, "<tr><td>%s - %s</td><td align=\"right\">%5.0f</td><td align=\"right\">%5.0f</td><td align=\"right\">%2.2f</td></tr>\n", tempbuff, req->extbuff, ipused, ipfree, ((ipfree * 100)/(ipused + ipfree)));
	}

	fp += sprintf(fp, "</table>\n</body>\n</html>");
	memcpy((contentStart - 12), tempbuff, sprintf(tempbuff, "%u", (fp - contentStart)));
	req->bytes = fp - req->dp;

	_beginthread(sendHTTP, 0, (void*)req);
	return;
}
*/

void __cdecl sendHTTP(void *lpParam)
{
	SocketRequest *req = (SocketRequest*)lpParam;

	//sprintf(logBuff, "sendHTTP memsize=%d bytes=%d", req->memSize, req->bytes);
	//(logBuff);

	char *dp = req->dp;
	timeval tv1;
	fd_set writefds1;
	int sent = 0;

	while (kRunning && req->bytes > 0)
	{
		tv1.tv_sec = 5;
		tv1.tv_usec = 0;
		FD_ZERO(&writefds1);
		FD_SET(req->sock, &writefds1);

		if (select((req->sock + 1), NULL, &writefds1, NULL, &tv1))
		{
			if (req->bytes > 1024)
				sent  = send(req->sock, dp, 1024, 0);
			else
				sent  = send(req->sock, dp, req->bytes, 0);

			errno = WSAGetLastError();

			if (errno || sent < 0)
				break;

			dp += sent;
			req->bytes -= sent;
		}
		else
			break;
	}

	closesocket(req->sock);
	free(req->dp);
	free(req);
	_endthread();
	return;
}

void processTCP(DNSRequest *req)
{
	//debug("processTCP");

	char logBuff[512];
	req->ling.l_onoff = 1; //0 = off (l_linger ignored), nonzero = on
	req->ling.l_linger = 10; //0 = discard data, nonzero = wait for data sent
	setsockopt(req->sock, SOL_SOCKET, SO_LINGER, (const char*)&req->ling, sizeof(req->ling));

	errno = 0;
	req->bytes = recvTcpDnsMess(req->raw, req->sock, sizeof(req->raw));
	//printf("%u\n",req->bytes);

	if (req->bytes < 2)
	{
		sprintf(logBuff, "Error Getting TCP DNS Message");
		logDNSMessage(logBuff, 1);
		closesocket(req->sock);
		return;
	}

	_Word pktSize = fUShort(req->raw);
	req->dp = req->raw + 2;
	req->dnsPacket = (DNSPacket*)(req->dp);

	if (req->dnsPacket->header.responseFlag)
		return;

	req->dp = &req->dnsPacket->data;
	_DWord clientIP = req->remote.sin_addr.s_addr;

	if (!findServer(network.allServers, MAX_SERVERS, clientIP) && !findServer(config.zoneServers, MAX_TCP_CLIENTS, clientIP) && !findServer(&config.zoneServers[2], MAX_TCP_CLIENTS - 2, clientIP))
	{
		sprintf(logBuff, "DNS TCP Query, Access Denied");
		logTCPMessage(req, logBuff, 1);
		addRRError(req, RCODE_REFUSED);
		sendTCPMessage(req);
		closesocket(req->sock);
		return;
	}

	if (ntohs(req->dnsPacket->header.questionsCount) != 1 || ntohs(req->dnsPacket->header.answersCount))
	{
		sprintf(logBuff, "DNS Query Format Error");
		logTCPMessage(req, logBuff, 1);
		addRRError(req, RCODE_FORMATERROR);
		sendTCPMessage(req);
		closesocket(req->sock);
		return;
	}

	if (req->dnsPacket->header.optionCode != OPCODE_STANDARD_QUERY)
	{
		switch (req->dnsPacket->header.optionCode)
		{
			case OPCODE_INVERSE_QUERY:
				sprintf(logBuff, "Inverse query not supported");
				break;

			case OPCODE_SRVR_STAT_REQ:
				sprintf(logBuff, "Server Status Request not supported");
				break;

			case OPCODE_NOTIFY:
				sprintf(logBuff, "Notify not supported");
				break;

			case OPCODE_DYNAMIC_UPDATE:
				sprintf(logBuff, "Dynamic Update not needed/supported by Dual Server");
				break;

			default:
				sprintf(logBuff, "OpCode %u not supported", req->dnsPacket->header.optionCode);
		}

		logTCPMessage(req, logBuff, 1);
		addRRError(req, RCODE_NOTIMPL);
		sendTCPMessage(req);
		closesocket(req->sock);
		return;
	}

	for (int i = 1; i <= ntohs(req->dnsPacket->header.questionsCount); i++)
	{
		req->dp += fQu(req->query, req->dnsPacket, req->dp);
		req->dnsType = fUShort(req->dp);
		req->dp += 2;
		req->qclass = fUShort(req->dp);
		req->dp += 2;
	}

	if (req->qclass != DNS_CLASS_IN)
	{
		sprintf(logBuff, "DNS Class %u not supported", req->qclass);
		logTCPMessage(req, logBuff, 1);
		addRRError(req, RCODE_NOTIMPL);
		sendTCPMessage(req);
		closesocket(req->sock);
		return;
	}

	if (!req->dnsType)
	{
		sprintf(logBuff, "missing query type");
		logTCPMessage(req, logBuff, 1);
		addRRError(req, RCODE_FORMATERROR);
		sendTCPMessage(req);
		closesocket(req->sock);
		return;
	}

	strcpy(req->cname, req->query);
	strcpy(req->mapname, req->query);
	myLower(req->mapname);
	req->qLen = strlen(req->cname);
	req->qType = makeLocal(req->mapname);

	if (req->qType == QTYPE_A_EXT && req->qLen > config.zLen)
	{
		char *dp = req->cname + (req->qLen - config.zLen);

		if (!strcasecmp(dp, config.zone))
			req->qType = QTYPE_CHILDZONE;
	}

	if (req->dnsType != DNS_TYPE_NS && req->dnsType != DNS_TYPE_SOA && req->dnsType != DNS_TYPE_AXFR && req->dnsType != DNS_TYPE_IXFR)
	{
		addRRError(req, RCODE_NOTIMPL);
		sendTCPMessage(req);
		sprintf(logBuff, "%s,  Query Type not supported", strquery(req));
		logTCPMessage(req, logBuff, 1);
		closesocket(req->sock);
		return;
	}
	else if (!config.authorized || (req->qType != QTYPE_A_ZONE && req->qType != QTYPE_A_LOCAL && req->qType != QTYPE_P_ZONE && req->qType != QTYPE_P_LOCAL))
	{
		addRRError(req, RCODE_NOTAUTH);
		sendTCPMessage(req);
		sprintf(logBuff, "Server is not authority for zone %s", req->query);
		logTCPMessage(req, logBuff, 1);
	}
	else if (config.expireTime < t)
	{
		addRRError(req, RCODE_NOTZONE);
		sendTCPMessage(req);
		sprintf(logBuff, "Zone %s expired", req->query);
		logTCPMessage(req, logBuff, 1);
	}
	else
	{
		switch (req->dnsType)
		{
			case DNS_TYPE_SOA:
				addRRNone(req);
				addRRSOA(req);
				sendTCPMessage(req);

				if (req->dnsPacket->header.answersCount)
					sprintf(logBuff, "SOA Sent for zone %s", req->query);
				else
					sprintf(logBuff, "%s not found", strquery(req));

				logTCPMessage(req, logBuff, 2);
				break;

			case DNS_TYPE_NS:
				addRRNone(req);
				addRRNS(req);
				addRRAd(req);
				sendTCPMessage(req);

				if (req->dnsPacket->header.answersCount)
					sprintf(logBuff, "NS Sent for zone %s", req->query);
				else
					sprintf(logBuff, "%s not found", strquery(req));

				logTCPMessage(req, logBuff, 2);
				break;

			case DNS_TYPE_AXFR:
			case DNS_TYPE_IXFR:

				if (req->qType == QTYPE_A_ZONE)
				{
					_Word records = 0;

					addRREmpty(req);
					addRRSOA(req);

					if (!sendTCPMessage(req))
					{
						closesocket(req->sock);
						return;
					}
					else
						records++;

					addRREmpty(req);
					addRRNS(req);

					if (!sendTCPMessage(req))
					{
						closesocket(req->sock);
						return;
					}
					else
						records++;

					req->iterBegin = dnsCache[currentInd].begin();

					for (; req->iterBegin != dnsCache[currentInd].end(); req->iterBegin++)
					{
						addRREmpty(req);

						if (req->iterBegin->second->expiry > t)
						{
							//printf("%s=%d=%d\n",req->iterBegin->second->mapname, req->iterBegin->second->qType, req->iterBegin->second->expiry);

							switch (req->iterBegin->second->cType)
							{
								case CTYPE_LOCAL_A:
									addRRAOne(req);
									break;

								case CTYPE_SERVER_A_AUTH:
								case CTYPE_STATIC_A_AUTH:
									addRRSTAOne(req);
									break;

								case CTYPE_LOCAL_CNAME:
								case CTYPE_EXT_CNAME:
									addRRCNOne(req);
									break;

								default:
									continue;
							}

							if (!sendTCPMessage(req))
							{
								closesocket(req->sock);
								return;
							}
							else
								records++;
						}
					}

					for (int m = 0; m < config.mxCount[currentInd]; m++)
					{
						addRREmpty(req);
						addRRMXOne(req, m);

						if (!sendTCPMessage(req))
						{
							closesocket(req->sock);
							return;
						}
						else
							records++;
					}

					addRREmpty(req);
					addRRSOA(req);

					if (sendTCPMessage(req))
					{
						records++;
						sprintf(logBuff, "Zone %s with %d RRs Sent", req->query, records);
						logTCPMessage(req, logBuff, 2);
					}
				}
				else if (req->qType == QTYPE_P_ZONE)
				{
					_Word records = 0;

					addRREmpty(req);
					addRRSOA(req);

					if (!sendTCPMessage(req))
					{
						closesocket(req->sock);
						return;
					}
					else
						records++;

					addRREmpty(req);
					addRRNS(req);

					if (!sendTCPMessage(req))
					{
						closesocket(req->sock);
						return;
					}
					else
						records++;

					req->iterBegin = dnsCache[currentInd].begin();

					for (; req->iterBegin != dnsCache[currentInd].end(); req->iterBegin++)
					{
						addRREmpty(req);

						if (req->iterBegin->second->expiry > t)
						{
							switch (req->iterBegin->second->cType)
							{
								case CTYPE_LOCAL_PTR_AUTH:
								case CTYPE_STATIC_PTR_AUTH:
								case CTYPE_SERVER_PTR_AUTH:
									addRRPtrOne(req);
									break;

								default:
									continue;
							}

							if (!sendTCPMessage(req))
							{
								closesocket(req->sock);
								return;
							}
							else
								records++;

						}
					}

					addRREmpty(req);
					addRRSOA(req);

					if (sendTCPMessage(req))
					{
						records++;
						sprintf(logBuff, "Zone %s with %d RRs Sent", req->query, records);
						logTCPMessage(req, logBuff, 2);
					}
				}
				else
				{
					addRRNone(req);
					req->dnsPacket->header.responseCode = RCODE_NOTAUTH;
					sendTCPMessage(req);
					sprintf(logBuff, "Server is not authority for zone %s", req->query);
					logTCPMessage(req, logBuff, 1);
				}
				break;

				default:
					sprintf(logBuff, "%s Query type not supported", strquery(req));
					logTCPMessage(req, logBuff, 1);
					addRRError(req, RCODE_NOTIMPL);
					sendTCPMessage(req);
		}
	}

	closesocket(req->sock);
}

_Word sendTCPMessage(DNSRequest *req)
{
	char logBuff[256];
	timeval tv1;
	fd_set writefds;

	FD_ZERO(&writefds);
	FD_SET(req->sock, &writefds);
	tv1.tv_sec = 5;
	tv1.tv_usec = 0;

	if (select((req->sock + 1), NULL, &writefds, NULL, &tv1) > 0)
	{
		errno = 0;
		req->dnsPacket->header.recursionAvailable = 0;
		req->bytes = req->dp - req->raw;
		pUShort(req->raw, req->bytes - 2);

		if (req->bytes == send(req->sock, req->raw, req->bytes, 0) && !WSAGetLastError())
			return 1;
	}

	if (verbatim || config.dnsLogLevel >= 1)
	{
		sprintf(logBuff, "Failed to send %s", strquery(req));
		logTCPMessage(req, logBuff, 1);
	}

	return 0;
}

_Word gdnmess(DNSRequest *req, _Byte sockInd)
{
	//debug("gdnmess");
	char logBuff[512];
	memset(req, 0, sizeof(DNSRequest));
	req->sockLen = sizeof(req->remote);
	errno = 0;

	req->bytes = recvfrom(network.DNS_UDPConnections[sockInd].sock,
	                      req->raw,
	                      sizeof(req->raw),
	                      0,
	                      (sockaddr*)&req->remote,
	                      &req->sockLen);

	errno = WSAGetLastError();

	if (errno || req->bytes <= 0)
		return 0;

	req->sockInd = sockInd;
	req->dnsPacket = (DNSPacket*)req->raw;

/*
	if (req->dnsPacket->header.responseFlag && req->dnsPacket->header.optionCode == OPCODE_DYNAMIC_UPDATE && config.replication == 1 && dhcpService && req->remote.sin_addr.s_addr == config.zoneServers[1])
	{
		char localBuff[256];

		if (ntohs(req->dnsPacket->header.zonesCount) == 1 && ntohs(req->dnsPacket->header.prerequisitesCount) == 1 && !req->dnsPacket->header.updatesCount && !req->dnsPacket->header.othersCount)
		{
			char *dp = &req->dnsPacket->data;
			dp += fQu(localBuff, req->dnsPacket, dp);
			dp += 4; //type and class

			if (!strcasecmp(localBuff, config.zone))
			{
				dp += fQu(localBuff, req->dnsPacket, dp);
				_Word dnsType = fUShort(dp);
				dp += 4; //type and class
				dp += 4; //ttl
				dp += 2; //datalength
				_DWord ip = fIP(dp);

				if (dnsType == DNS_TYPE_A && ip == config.zoneServers[1] && makeLocal(localBuff) == QTYPE_A_LOCAL)
				{
					if (config.refresh > (_DWord)(INT_MAX - t))
						config.dnsRepl = INT_MAX;
					else
						config.dnsRepl = t + config.refresh + config.retry + config.retry;

					sprintf(config.nsS, "%s.%s", localBuff, config.zone);

					if (isLocal(ip))
						add2Cache(localBuff, ip, INT_MAX, CTYPE_SERVER_A_AUTH, CTYPE_SERVER_PTR_AUTH);
					else
						add2Cache(localBuff, ip, INT_MAX, CTYPE_SERVER_A_AUTH, CTYPE_SERVER_PTR_NAUTH);

					addRRError(req, RCODE_NOERROR);
					return 0;
				}
			}
		}
	}
*/

	if (req->dnsPacket->header.responseFlag)
		return 0;

	if (req->dnsPacket->header.optionCode != OPCODE_STANDARD_QUERY)
	{
		if (verbatim || config.dnsLogLevel >= 1)
		{
			switch (req->dnsPacket->header.optionCode)
			{
				case OPCODE_INVERSE_QUERY:
					sprintf(logBuff, "Inverse query not supported");
					break;

				case OPCODE_SRVR_STAT_REQ:
					sprintf(logBuff, "Server Status Request not supported");
					break;

				case OPCODE_NOTIFY:
					sprintf(logBuff, "Notify not supported");
					break;

				case OPCODE_DYNAMIC_UPDATE:
					sprintf(logBuff, "Dynamic Update not needed/supported by Dual Server");
					break;

				default:
					sprintf(logBuff, "OpCode %d not supported", req->dnsPacket->header.optionCode);
			}

			logDNSMessage(req, logBuff, 1);
		}

		addRRError(req, RCODE_NOTIMPL);
		return 0;
	}

	if (ntohs(req->dnsPacket->header.questionsCount) != 1 || ntohs(req->dnsPacket->header.answersCount))
	{
		if (verbatim || config.dnsLogLevel >= 1)
		{
			sprintf(logBuff, "DNS Query Format Error");
			logDNSMessage(req, logBuff, 1);
		}

		addRRError(req, RCODE_FORMATERROR);
		return 0;
	}

	req->dp = &req->dnsPacket->data;

	for (int i = 1; i <= ntohs(req->dnsPacket->header.questionsCount); i++)
	{
		req->dp += fQu(req->query, req->dnsPacket, req->dp);
		req->dnsType = fUShort(req->dp);
		req->dp += 2;
		req->qclass = fUShort(req->dp);
		req->dp += 2;
	}

	//debug(req->query);

	if (req->qclass != DNS_CLASS_IN)
	{
		if (verbatim || config.dnsLogLevel >= 1)
		{
			sprintf(logBuff, "DNS Class %d not supported", req->qclass);
			logDNSMessage(req, logBuff, 1);
		}
		addRRError(req, RCODE_NOTIMPL);
		return 0;
	}

	if (!req->dnsType)
	{
		if (verbatim || config.dnsLogLevel >= 1)
		{
			sprintf(logBuff, "missing query type");
			logDNSMessage(req, logBuff, 1);
		}

		addRRError(req, RCODE_FORMATERROR);
		return 0;
	}

	_DWord ip = req->remote.sin_addr.s_addr;
	_DWord iip = ntohl(ip);

	for (int i = 0; i < MAX_DNS_RANGES && config.dnsRanges[i].rangeStart; i++)
	{
		if (iip >= config.dnsRanges[i].rangeStart && iip <= config.dnsRanges[i].rangeEnd)
			return req->bytes;
	}

	if (isLocal(ip))
		return req->bytes;

	if (getRangeInd(ip) >= 0)
		return req->bytes;

	if (findEntry(IP2String(req->cname, iip), DNS_TYPE_PTR, CTYPE_LOCAL_PTR_NAUTH))
		return req->bytes;

	if (findServer(network.allServers, MAX_SERVERS, ip))
		return req->bytes;

	if (verbatim || config.dnsLogLevel >= 1)
	{
		sprintf(logBuff, "DNS UDP Query, Access Denied");
		logDNSMessage(req, logBuff, 1);
	}

	addRRError(req, RCODE_REFUSED);
	return 0;
}

_Word scanloc(DNSRequest *req)
{
	//debug("scanloc");
	char logBuff[512];

	if (!req->query[0])
		return 0;

	strcpy(req->cname, req->query);
	strcpy(req->mapname, req->query);
	myLower(req->mapname);
	req->qType = makeLocal(req->mapname);
	//_DWord ip = req->remote.sin_addr.s_addr;
	//sprintf(logBuff, "qType=%u dnsType=%u query=%s mapname=%s", req->qType, req->dnsType, req->query, req->mapname);
	//logMessage(logBuff, 2);

	switch (req->qType)
	{
		case QTYPE_P_EXT:
		case QTYPE_A_EXT:

			break;

		case QTYPE_A_BARE:
		case QTYPE_P_LOCAL:
		case QTYPE_A_LOCAL:
		case QTYPE_A_ZONE:
		case QTYPE_P_ZONE:

			switch (req->dnsType)
			{
				case DNS_TYPE_A:
				case DNS_TYPE_PTR:
					break;

				case DNS_TYPE_MX:
				{
					if (!strcasecmp(req->query, config.zone) && (config.authorized || config.mxServers[currentInd][0].hostname[0]))
					{
						addRRNone(req);
						addRRMX(req);
						addRRNS(req);
						addRRAd(req);
						return 1;
					}
					break;
				}
				case DNS_TYPE_NS:
				{
					if (config.authorized && (req->qType == QTYPE_A_ZONE || req->qType == QTYPE_P_ZONE || req->qType == QTYPE_A_BARE))
					{
						addRRNone(req);
						addRRNS(req);
						addRRAd(req);
						return 1;
					}
					break;
				}
				case DNS_TYPE_SOA:
				{
					if (config.authorized)
					{
						if (req->qType == QTYPE_P_ZONE)
						{
							if (config.replication == 1 && req->remote.sin_addr.s_addr == config.zoneServers[1] && (t - config.dnsCheck) < 2)
							{
								if (config.refresh > (_DWord)(INT_MAX - t))
									config.dnsRepl = INT_MAX;
								else
									config.dnsRepl = t + config.refresh + config.retry + config.retry;
							}

							config.dnsCheck = 0;
							addRRNone(req);
							addRRSOA(req);
							return 1;
						}
						else if (req->qType == QTYPE_A_ZONE)
						{
							config.dnsCheck = t;
							addRRNone(req);
							addRRSOA(req);
							return 1;
						}
						else if (req->qType == QTYPE_A_BARE)
						{
							addRRNone(req);
							addRRSOA(req);
							return 1;
						}
					}
					break;
				}
				case DNS_TYPE_ANY:
				{
					addRRAny(req);
					return 1;
				}
				default:
				{
					if (config.authorized)
					{
						if (verbatim || config.dnsLogLevel)
						{
							sprintf(logBuff, "%s, DNS Query Type not supported", strquery(req));
							logDNSMessage(req, logBuff, 1);
						}
						addRRNone(req);
						addRRNS(req);
						addRRAd(req);
						req->dnsPacket->header.responseCode = RCODE_NOTIMPL;
						return 1;
					}
					else
						return 0;

					break;
				}
			}
	}

	for (int m = 0; m < 3; m++)
	{
		req->iterBegin = dnsCache[currentInd].find(setMapName(req->tempname, req->mapname, req->dnsType));

		if (req->iterBegin == dnsCache[currentInd].end())
			break;

		CachedData *cache = req->iterBegin->second;

		if (cache->expiry < t && cache->cType != CTYPE_CACHED)
			break;

		req->cType = cache->cType;

		switch (req->cType)
		{
			case CTYPE_LOCAL_A:
			case CTYPE_STATIC_A_AUTH:
				addRRNone(req);
				addRRA(req);
				addRRNS(req);
				addRRAd(req);
				return 1;

			case CTYPE_LOCAL_PTR_AUTH:
			case CTYPE_STATIC_PTR_AUTH:
			case CTYPE_SERVER_PTR_AUTH:
				addRRNone(req);
				addRRPtr(req);
				addRRNS(req);
				addRRAd(req);
				return 1;

			case CTYPE_LOCALHOST_A:
				addRRNone(req);
				addRRLocalhostA(req, cache);
				return 1;

			case CTYPE_LOCALHOST_PTR:
				addRRNone(req);
				addRRLocalhostPtr(req, cache);
				return 1;

			case CTYPE_STATIC_A_NAUTH:
				addRRNone(req);
				addRRA(req);
				return 1;

			case CTYPE_LOCAL_PTR_NAUTH:
			case CTYPE_SERVER_PTR_NAUTH:
			case CTYPE_STATIC_PTR_NAUTH:
				addRRNone(req);
				addRRPtr(req);
				return 1;

			case CTYPE_SERVER_A_AUTH:
				addRRNone(req);
				addRRServerA(req);
				addRRNS(req);
				addRRAd(req);
				return 1;

			case CTYPE_CACHED:
				addRRNone(req);
				addRRCache(req, cache);
				return 1;

			case CTYPE_LOCAL_CNAME:
			case CTYPE_EXT_CNAME:

				if (!cache->hostname[0])
					strcpy(req->cname, config.zone);
				else if (strchr(cache->hostname, '.'))
					strcpy(req->cname, cache->hostname);
				else
					sprintf(req->cname, "%s.%s", cache->hostname, config.zone);

				//sprintf(logBuff, "cType=%u, name=%s, hostname=%s", cache->cType, cache->name, cache->hostname);
				//logMessage(logBuff, 2);

				strcpy(req->mapname, cache->hostname);
				myLower(req->mapname);
				continue;

			default:
				break;
		}
	}

	//sprintf(logBuff, "cType=%u,dnsType=%u,query=%s,cname=%s", req->cType, req->dnsType, req->query, req->cname);
	//logMessage(logBuff, 2);

	if (req->dnsType == DNS_TYPE_A && config.wildcardHosts[0].wildcard[0])
	{
		for (_Byte i = 0; i < MAX_WILDCARD_HOSTS && config.wildcardHosts[i].wildcard[0]; i++)
		{
			if (wildcmp(req->mapname, config.wildcardHosts[i].wildcard))
			{
				addRRNone(req);

				if (config.wildcardHosts[i].ip)
					addRRWildA(req, config.wildcardHosts[i].ip);

				return 1;
			}
		}
	}

	if (req->cType == CTYPE_EXT_CNAME)
	{
		//debug(req->cname);
		req->qType = makeLocal(req->cname);
		req->dp = &req->dnsPacket->data;
		req->dp += pQu(req->dp, req->cname);
		req->dp += pUShort(req->dp, DNS_TYPE_A);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->bytes = req->dp - req->raw;
		return 0;
	}
	else if (req->qType == QTYPE_A_BARE || req->qType == QTYPE_A_ZONE || req->qType == QTYPE_P_ZONE)
	{
		addRRNone(req);
		addRRA(req);
		addRRNS(req);
		addRRAd(req);
		return 1;
	}

	return 0;
}

_Word fdnmess(DNSRequest *req)
{
	//debug("fdnmess");
	//debug(req->cname);
	//printf("before qType=%d %d\n", req->qType, QTYPE_A_SUBZONE);
	char ipbuff[32];
	char logBuff[512];
	req->qLen = strlen(req->cname);
	_Byte zoneDNS;
	int nRet = -1;

	char mapname[8];
	sprintf(mapname, "%u", req->dnsPacket->header.queryID);
	CachedData *queue = findQueue(mapname);

	for (zoneDNS = 0; zoneDNS < MAX_COND_FORW && config.dnsRoutes[zoneDNS].zLen; zoneDNS++)
	{
		if (req->qLen == config.dnsRoutes[zoneDNS].zLen && !strcasecmp(req->cname, config.dnsRoutes[zoneDNS].zone))
			req->qType = QTYPE_CHILDZONE;
		else if (req->qLen > config.dnsRoutes[zoneDNS].zLen)
		{
			char *dp = req->cname + (req->qLen - config.dnsRoutes[zoneDNS].zLen - 1);

			if (*dp == '.' && !strcasecmp(dp + 1, config.dnsRoutes[zoneDNS].zone))
				req->qType = QTYPE_CHILDZONE;
		}

		if (req->qType == QTYPE_CHILDZONE)
		{
			if (queue && config.dnsRoutes[zoneDNS].DNS[1])
				config.dnsRoutes[zoneDNS].currentDNS = 1 - config.dnsRoutes[zoneDNS].currentDNS;

			if (req->remote.sin_addr.s_addr != config.dnsRoutes[zoneDNS].DNS[config.dnsRoutes[zoneDNS].currentDNS])
			{
				req->addr.sin_family = AF_INET;
				req->addr.sin_addr.s_addr = config.dnsRoutes[zoneDNS].DNS[config.dnsRoutes[zoneDNS].currentDNS];
				req->addr.sin_port = htons(IPPORT_DNS);
				errno = 0;

				nRet = sendto(network.forwConn.sock,
							  req->raw,
							  req->bytes,
							  0,
							  (sockaddr*)&req->addr,
							  sizeof(req->addr));

				errno = WSAGetLastError();

				if (errno || nRet <= 0)
				{
					if (verbatim || config.dnsLogLevel)
					{
						sprintf(logBuff, "Error Forwarding UDP DNS Message to Conditional Forwarder %s", IP2String(ipbuff, req->addr.sin_addr.s_addr));
						logDNSMessage(req, logBuff, 1);
						addRRNone(req);
						req->dnsPacket->header.responseCode = RCODE_SERVERFAIL;
					}

					if (config.dnsRoutes[zoneDNS].DNS[1])
						config.dnsRoutes[zoneDNS].currentDNS = 1 - config.dnsRoutes[zoneDNS].currentDNS;

					return 0;
				}
				else
				{
					if (verbatim || config.dnsLogLevel >= 2)
					{
						sprintf(logBuff, "%s forwarded to Conditional Forwarder %s", strquery(req), IP2String(ipbuff, config.dnsRoutes[zoneDNS].DNS[config.dnsRoutes[zoneDNS].currentDNS]));
						logDNSMessage(req, logBuff, 2);
					}
				}
			}

			break;
		}
	}

	if (req->qType != QTYPE_CHILDZONE)
	{
		//sprintf(logBuff, "after qType=%d %d", req->qType, QTYPE_CHILDZONE);
		//logMessage(logBuff, 2);

		if (config.authorized && (req->qType == QTYPE_A_LOCAL || req->qType == QTYPE_P_LOCAL))
		{
			switch (req->dnsType)
			{
				case DNS_TYPE_A:
					addRRNone(req);
					addRRA(req);
					addRRNS(req);
					addRRAd(req);
					return 0;

				case DNS_TYPE_SOA:
					addRRNone(req);
					addRRSOA(req);
					return 0;

				default:
					addRRNone(req);
					addRRNS(req);
					addRRAd(req);
					return 0;
			}
		}

		if (!req->dnsPacket->header.recursionDesired)
		{
			addRRNone(req);
			if (verbatim || config.dnsLogLevel)
			{
				sprintf(logBuff, "%s is not found (recursion not desired)", strquery(req));
				logDNSMessage(req, logBuff, 2);
			}
			return 0;
		}

		if (!network.DNS[0])
		{
			addRRNone(req);
			req->dnsPacket->header.recursionAvailable = 0;
			if (verbatim || config.dnsLogLevel)
			{
				sprintf(logBuff, "%s not found (recursion not available)", strquery(req));
				logDNSMessage(req, logBuff, 2);
			}
			return 0;
		}

		if (queue && network.DNS[1] && queue->dnsIndex < MAX_SERVERS && network.currentDNS == queue->dnsIndex)
		{
			network.currentDNS++;

			if (network.currentDNS >= MAX_SERVERS || !network.DNS[network.currentDNS])
				network.currentDNS = 0;
		}

		if (req->remote.sin_addr.s_addr != network.DNS[network.currentDNS])
		{
			req->addr.sin_family = AF_INET;
			req->addr.sin_addr.s_addr = network.DNS[network.currentDNS];
			req->addr.sin_port = htons(IPPORT_DNS);
			errno = 0;

			nRet = sendto(network.forwConn.sock,
						  req->raw,
						  req->bytes,
						  0,
						  (sockaddr*)&req->addr,
						  sizeof(req->addr));

			errno = WSAGetLastError();

			if (errno || nRet <= 0)
			{
				if (verbatim || config.dnsLogLevel)
				{
					sprintf(logBuff, "Error forwarding UDP DNS Message to Forwarding Server %s", IP2String(ipbuff, network.DNS[network.currentDNS]));
					logDNSMessage(req, logBuff, 1);
					addRRNone(req);
					req->dnsPacket->header.responseCode = RCODE_SERVERFAIL;
				}

				if (network.DNS[1])
				{
					network.currentDNS++;

					if (network.currentDNS >= MAX_SERVERS || !network.DNS[network.currentDNS])
						network.currentDNS = 0;
				}

				return 0;
			}
			else
			{
				if (verbatim || config.dnsLogLevel >= 2)
				{
					sprintf(logBuff, "%s forwarded to Forwarding Server %s", strquery(req), IP2String(ipbuff, network.DNS[network.currentDNS]));
					logDNSMessage(req, logBuff, 2);
				}
			}
		}
	}

	if (!queue)
	{
		memset(&lump, 0, sizeof(Lump));
		lump.dnsType = req->dnsType;
		lump.cType = CTYPE_QUEUE;
		lump.mapname = mapname;
		lump.addr = &req->remote;
		lump.query = req->query;
		queue = createCache(&lump);

		if (queue)
		{
			queue->expiry = 2 + t;
			addEntry(queue);
		}
		else
			return 0;
	}
	else
	{
		queue->expiry = 2 + t;
		memcpy(queue->addr, &req->remote, sizeof(req->remote));
	}

	queue->sockInd = req->sockInd;

	if (req->qType == QTYPE_CHILDZONE)
		queue->dnsIndex = 128 + (2 * zoneDNS) + config.dnsRoutes[zoneDNS].currentDNS;
	else
		queue->dnsIndex = network.currentDNS;

	//sprintf(logBuff, "queue created for %s", req->query);
	//debug(logBuff);

	return (nRet);
}

_Word frdnmess(DNSRequest *req)
{
	//debug("frdnmess");
	char tempbuff[512];
	memset(req, 0, sizeof(DNSRequest));
	req->sockLen = sizeof(req->remote);
	errno = 0;
	_Byte dnsType = 0;

	req->bytes = recvfrom(network.forwConn.sock,
	                      req->raw,
	                      sizeof(req->raw),
	                      0,
	                      (sockaddr*)&req->remote,
	                      &req->sockLen);

	errno = WSAGetLastError();

	if (errno || req->bytes <= 0)
		return 0;

	req->dnsPacket = (DNSPacket*)req->raw;
	req->dp = &req->dnsPacket->data;

	for (int i = 1; i <= ntohs(req->dnsPacket->header.questionsCount); i++)
	{
		req->dp += fQu(req->cname, req->dnsPacket, req->dp);
		strcpy(req->mapname, req->cname);
		dnsType = fUShort(req->dp);
		req->dp += 4; //type and class

		if (dnsType == DNS_TYPE_PTR)
		{
			myLower(req->mapname);
			char *dp = strstr(req->mapname, arpa);

			if (dp && !strcasecmp(dp, arpa))
				*dp = 0;
		}
		else
		{
			strcpy(req->mapname, req->cname);
			myLower(req->mapname);
		}
	}

	if ((dnsType == DNS_TYPE_A || dnsType == DNS_TYPE_ANY || dnsType == DNS_TYPE_AAAA || dnsType == DNS_TYPE_PTR) && !req->dnsPacket->header.responseCode && !req->dnsPacket->header.truncatedMessage && req->dnsPacket->header.answersCount)
	{
		time_t expiry = 0;
		bool resultFound = false;

		for (int i = 1; i <= ntohs(req->dnsPacket->header.answersCount); i++)
		{
			resultFound = true;
			req->dp += fQu(tempbuff, req->dnsPacket, req->dp);
			//dnsType = fUShort(req->dp);

			//logDNSMessage(tempbuff, 2);
			req->dp += 4; //type and class

			if (!expiry || fULong(req->dp) < (_DWord)expiry)
				expiry = fULong(req->dp);

			req->dp += 4; //ttl
			int zLen = fUShort(req->dp);
			req->dp += 2; //datalength
			req->dp += zLen;
		}

		if (resultFound)
		{
			_Word cacheSize = req->dp - req->raw;

			if (config.minCache && expiry < config.minCache)
				expiry = config.minCache;

			if (config.maxCache && expiry > config.maxCache)
				expiry = config.maxCache;

			if (expiry < INT_MAX - t)
				expiry += t;
			else
				expiry = INT_MAX;

			memset(&lump, 0, sizeof(Lump));
			lump.cType = CTYPE_CACHED;
			lump.dnsType = dnsType;
			lump.mapname = req->mapname;
			lump.bytes = req->bytes;
			lump.response = (_Byte*)req->dnsPacket;
			CachedData* cache = createCache(&lump);

			if (cache)
			{
				cache->expiry = expiry;
				addEntry(cache);
			}
		}
	}

	char mapname[8];
	sprintf(mapname, "%u", req->dnsPacket->header.queryID);
	CachedData *queue = findQueue(mapname);

	if (queue && queue->expiry)
	{
		queue->expiry = 0;

		if (queue->dnsIndex < MAX_SERVERS)
		{
			if (req->remote.sin_addr.s_addr != network.DNS[network.currentDNS])
			{
				for (_Byte i = 0; i < MAX_SERVERS && network.DNS[i]; i++)
				{
					if (network.DNS[i] == req->remote.sin_addr.s_addr)
					{
						network.currentDNS = i;
						break;
					}
				}
			}
		}
		else if (queue->dnsIndex >= 128 && queue->dnsIndex < 192)
		{
			_Byte rid = (queue->dnsIndex - 128) / 2;
			DNSRoute *dnsRoute = &config.dnsRoutes[rid];

			if (dnsRoute->DNS[0] == req->remote.sin_addr.s_addr)
				dnsRoute->currentDNS = 0;
			else if (dnsRoute->DNS[1] == req->remote.sin_addr.s_addr)
				dnsRoute->currentDNS = 1;
		}

		memcpy(&req->remote, queue->addr, sizeof(req->remote));
		strcpy(req->query, queue->query);
		req->sockInd = queue->sockInd;
		req->dnsIndex = queue->dnsIndex;
		req->dnsType = queue->dnsType;
		addRRExt(req);
		return 1;
	}

	return 0;
}

_Word sdnmess(DNSRequest *req)
{
	//debug("sdnmess");

	errno = 0;
	req->bytes = req->dp - req->raw;
	req->bytes = sendto(network.DNS_UDPConnections[req->sockInd].sock,
	                    req->raw,
	                    req->bytes,
	                    0,
	                    (sockaddr*)&req->remote,
	                    sizeof(req->remote));

	errno = WSAGetLastError();

	if (errno || req->bytes <= 0)
		return 0;
	else
		return req->bytes;
}

void add2Cache(char *hostname, _DWord ip, time_t expiry, _Byte aType, _Byte pType)
{
	//sprintf(logBuff, "Adding %s=%s %u", hostname,IP2String(ipbuff, ip), expiry - t);
	//logMessage(logBuff, 1);

	//memset(&lump, 0, sizeof(Lump));

	char tempbuff[512];

	if (!hostname || !ip)
		return;

	CachedData *cache = NULL;
	hostMap::iterator p;

	if (pType)
	{
		IP2String(tempbuff, htonl(ip), DNS_TYPE_PTR);
		p = dnsCache[currentInd].find(tempbuff);

		for (; p != dnsCache[currentInd].end(); p++)
		{
			if (strcasecmp(p->second->mapname, tempbuff))
				break;

			if (!strcasecmp(p->second->hostname, hostname))
			{
				cache = p->second;
				break;
			}
		}

		if (!cache)
		{
			memset(&lump, 0, sizeof(Lump));
			lump.cType = pType;
			lump.dnsType = DNS_TYPE_PTR;
			lump.mapname = IP2String(tempbuff, htonl(ip));
			lump.hostname = hostname;
			cache = createCache(&lump);
/*
			cache = (CachedData*)calloc(1, sizeof(CachedData));

			if (cache)
			{
				cache->mapname = cloneString(tempbuff);
				cache->hostname = cloneString(hostname);

				if (!cache->mapname || !cache->hostname)
				{
					if (cache->mapname)
						free(cache->mapname);

					if (cache->hostname)
						free(cache->hostname);

					free(cache);

					sprintf(logBuff, "Memory Allocation Error");
					logDNSMessage(logBuff, 1);
					return;
				}

				cache->cType = pType;
				cache->expiry = expiry;
				addEntry(cache);
*/
			if (cache)
			{
				cache->expiry = expiry;
				addEntry(cache);

				if (config.replication != 2 && (pType == CTYPE_LOCAL_PTR_AUTH || pType == CTYPE_SERVER_PTR_AUTH))
					config.serial2 = t;
			}
		}
		else if (cache->expiry < expiry)
		{
			cache->cType = pType;
			cache->expiry = expiry;
		}
		//printf("Added %s=%s\n", IP2String(ipbuff, ip), hostname);
	}

	if (aType)
	{
		cache = NULL;
		setMapName(tempbuff, hostname, DNS_TYPE_A);

		p = dnsCache[currentInd].find(tempbuff);

		for (; p != dnsCache[currentInd].end(); p++)
		{
			if (strcasecmp(p->second->mapname, tempbuff))
				break;

			if (p->second->ip == ip)
			{
				cache = p->second;
				break;
			}
		}

		if (!cache)
		{
			memset(&lump, 0, sizeof(Lump));
			lump.cType = aType;
			lump.dnsType = DNS_TYPE_A;
			lump.mapname = hostname;
			cache = createCache(&lump);
/*
			cache = (CachedData*)calloc(1, sizeof(CachedData));

			if (cache)
			{
				cache->mapname = cloneString(tempbuff);

				if (!cache->mapname)
				{
					sprintf(logBuff, "Memory Allocation Error");
					logDNSMessage(logBuff, 1);
					free(cache);
					return;
				}

				cache->ip = ip;
				cache->cType = aType;
				cache->expiry = expiry;
				addEntry(cache);
			}
*/
			if (cache)
			{
				cache->ip = ip;
				cache->expiry = expiry;
				addEntry(cache);

				if (config.replication != 2 && (aType == CTYPE_LOCAL_A || aType == CTYPE_SERVER_A_AUTH))
					config.serial1 = t;
			}

		}
		else if (cache->expiry < expiry)
		{
			cache->cType = aType;
			cache->expiry = expiry;
		}
	}
}

void expireEntry(_DWord ip)
{
	char ipbuff[32];

	if (!ip)
		return;

	IP2String(ipbuff, htonl(ip));
	CachedData *cache = findEntry(ipbuff, DNS_TYPE_PTR, CTYPE_LOCAL_PTR_AUTH);

	if (!cache)
		cache = findEntry(ipbuff, DNS_TYPE_PTR, CTYPE_LOCAL_PTR_NAUTH);

	if (cache && cache->hostname[0] && cache->expiry < INT_MAX)
	{
		CachedData *cache1 = findEntry(cache->hostname, DNS_TYPE_A, CTYPE_LOCAL_A);

		if (cache1 && cache1->ip == ip && cache1->expiry < INT_MAX)
		{
			cache->expiry = 0;
			cache1->expiry = 0;
		}
	}
}

void addHostNotFound(char *hostname)
{
	memset(&lump, 0, sizeof(Lump));
	lump.cType = CTYPE_STATIC_A_NAUTH;
	lump.dnsType = DNS_TYPE_A;
	lump.mapname = hostname;
	CachedData *cache = createCache(&lump);
/*
	CachedData *cache = (CachedData*)calloc(1, sizeof(CachedData));

	if (cache)
	{
		cache->mapname = myLower(cloneString(hostname));

		if (!cache->mapname)
		{
			sprintf(logBuff, "Memory Allocation Error");
			free(cache);
			logDNSMessage(logBuff, 1);
			return;
		}

		cache->ip = 0;
		cache->cType = CTYPE_STATIC_A_NAUTH;
		cache->expiry = INT_MAX;
		addEntry(cache);
	}
*/
	if (cache)
	{
		cache->ip = 0;
		cache->cType = CTYPE_STATIC_A_NAUTH;
		cache->expiry = INT_MAX;
		addEntry(cache);
	}
}

char* getResult(DNSRequest *req)
{
	char buff[256];

	req->tempname[0] = 0;
	char *raw = &req->dnsPacket->data;
	_Word queueIndex;

	for (int i = 1; i <= ntohs(req->dnsPacket->header.questionsCount); i++)
	{
		raw += fQu(buff, req->dnsPacket, raw);
		raw += 4;
	}

	for (int i = 1; i <= ntohs(req->dnsPacket->header.answersCount); i++)
	{
		raw += fQu(buff, req->dnsPacket, raw);
		int type = fUShort(raw);
		raw += 2; //type
		raw += 2; //class
		raw += 4; //ttl
		int zLen = fUShort(raw);
		raw += 2; //datalength

		if (type == DNS_TYPE_A)
			return IP2String(req->tempname, fIP(raw));
		else if (type == DNS_TYPE_AAAA)
			return IP62String(req->tempname, (_Byte*)raw);
		else if (type == DNS_TYPE_PTR)
		{
			fQu(req->tempname, req->dnsPacket, raw);
			return req->tempname;
		}
		else if (type == DNS_TYPE_MX)
			fQu(req->tempname, req->dnsPacket, (raw + 2));
		else if (type == DNS_TYPE_CNAME)
			fQu(req->tempname, req->dnsPacket, raw);
		else if (type == DNS_TYPE_NS)
			fQu(req->tempname, req->dnsPacket, raw);

		raw += zLen;
	}

	if (req->tempname[0])
		return req->tempname;
	else
		return NULL;
}


bool checkRange(RangeData *rangeData, char rangeInd)
{
	//debug("checkRange");

	if (!config.hasFilter)
		return true;

	_Byte rangeSetInd = config.dhcpRanges[rangeInd].rangeSetInd;
	RangeSet *rangeSet = &config.rangeSet[rangeSetInd];
	//printf("checkRange entering, rangeInd=%i rangeSetInd=%i\n", rangeInd, rangeSetInd);
	//printf("checkRange entered, macFound=%i vendFound=%i userFound=%i\n", macFound, vendFound, userFound);

	if((!rangeData->macFound && !rangeSet->macSize[0]) || (rangeData->macFound && rangeData->macArray[rangeSetInd]))
		if((!rangeData->vendFound && !rangeSet->vendClassSize[0]) || (rangeData->vendFound && rangeData->vendArray[rangeSetInd]))
			if((!rangeData->userFound && !rangeSet->userClassSize[0]) || (rangeData->userFound && rangeData->userArray[rangeSetInd]))
				if((!rangeData->subnetFound && !rangeSet->subnetIP[0]) || (rangeData->subnetFound && rangeData->subnetArray[rangeSetInd]))
					return true;

	//printf("checkRange, returning false rangeInd=%i rangeSetInd=%i\n", rangeInd, rangeSetInd);
	return false;
}

_DWord resad(DHCPRequest *req)
{
	//debug("resad");
	char logBuff[512];
	char tempbuff[512];
	_DWord minRange = 0;
	_DWord maxRange = 0;

	if (req->DHCPPacket.header.bp_giaddr)
	{
		lockIP(req->DHCPPacket.header.bp_giaddr);
		lockIP(req->remote.sin_addr.s_addr);
	}

	req->dhcpEntry = findDHCPEntry(req->chaddr);

	if (req->dhcpEntry && req->dhcpEntry->fixed)
	{
		if (req->dhcpEntry->ip)
		{
			setTempLease(req->dhcpEntry);
			return req->dhcpEntry->ip;
		}
		else
		{
			if (verbatim || config.dhcpLogLevel)
			{
				sprintf(logBuff, "Static DHCP Host %s (%s) has No IP, DHCPDISCOVER ignored", req->chaddr, req->hostname);
				logDHCPMessage(logBuff, 1);
			}
			return 0;
		}
	}

	_DWord iipNew = 0;
	_DWord iipExp = 0;
	_DWord rangeStart = 0;
	_DWord rangeEnd = 0;
	char rangeInd = -1;
	bool rangeFound = false;
	RangeData rangeData;
	memset(&rangeData, 0, sizeof(RangeData));

	if (config.hasFilter)
	{
		for (_Byte rangeSetInd = 0; rangeSetInd < MAX_RANGE_SETS && config.rangeSet[rangeSetInd].active; rangeSetInd++)
		{
			RangeSet *rangeSet = &config.rangeSet[rangeSetInd];

			for (_Byte i = 0; i < MAX_RANGE_FILTERS && rangeSet->macSize[i]; i++)
			{
				//printf("%s\n", hex2String(tempbuff, rangeSet->macStart[i], rangeSet->macSize[i]));
				//printf("%s\n", hex2String(tempbuff, rangeSet->macEnd[i], rangeSet->macSize[i]));

				if(memcmp(req->DHCPPacket.header.bp_chaddr, rangeSet->macStart[i], rangeSet->macSize[i]) >= 0 && memcmp(req->DHCPPacket.header.bp_chaddr, rangeSet->macEnd[i], rangeSet->macSize[i]) <= 0)
				{
					rangeData.macArray[rangeSetInd] = 1;
					rangeData.macFound = true;
					//printf("mac Found, rangeSetInd=%i\n", rangeSetInd);
					break;
				}
			}

			for (_Byte i = 0; i < MAX_RANGE_FILTERS && req->vendClass.size && rangeSet->vendClassSize[i]; i++)
			{
				if(rangeSet->vendClassSize[i] == req->vendClass.size && !memcmp(req->vendClass.value, rangeSet->vendClass[i], rangeSet->vendClassSize[i]))
				{
					rangeData.vendArray[rangeSetInd] = 1;
					rangeData.vendFound = true;
					//printf("vend Found, rangeSetInd=%i\n", rangeSetInd);
					break;
				}
			}

			for (_Byte i = 0; i < MAX_RANGE_FILTERS && req->userClass.size && rangeSet->userClassSize[i]; i++)
			{
				if(rangeSet->userClassSize[i] == req->userClass.size && !memcmp(req->userClass.value, rangeSet->userClass[i], rangeSet->userClassSize[i]))
				{
					rangeData.userArray[rangeSetInd] = 1;
					rangeData.userFound = true;
					//printf("user Found, rangeSetInd=%i\n", rangeSetInd);
					break;
				}
			}

			for (_Byte i = 0; i < MAX_RANGE_FILTERS && req->subnetIP && rangeSet->subnetIP[i]; i++)
			{
				if(req->subnetIP == rangeSet->subnetIP[i])
				{
					rangeData.subnetArray[rangeSetInd] = 1;
					rangeData.subnetFound = true;
					//printf("subnet Found, rangeSetInd=%i\n", rangeSetInd);
					break;
				}
			}
		}

	}

//	printArray("macArray", (char*)config.macArray);
//	printArray("vendArray", (char*)config.vendArray);
//	printArray("userArray", (char*)config.userArray);

	if (req->dhcpEntry)
	{
		req->dhcpEntry->rangeInd = getRangeInd(req->dhcpEntry->ip);

		if (req->dhcpEntry->rangeInd >= 0)
		{
			int ind = getIndex(req->dhcpEntry->rangeInd, req->dhcpEntry->ip);

			if (config.dhcpRanges[req->dhcpEntry->rangeInd].dhcpEntry[ind] == req->dhcpEntry && checkRange(&rangeData, req->dhcpEntry->rangeInd))
			{
				_Byte rangeSetInd = config.dhcpRanges[req->dhcpEntry->rangeInd].rangeSetInd;

				if (!config.rangeSet[rangeSetInd].subnetIP[0])
				{
					_DWord mask = config.dhcpRanges[req->dhcpEntry->rangeInd].mask;
					calcRangeLimits(req->subnetIP, mask, &minRange, &maxRange);

					if (htonl(req->dhcpEntry->ip) >= minRange && htonl(req->dhcpEntry->ip) <= maxRange)
					{
						setTempLease(req->dhcpEntry);
						return req->dhcpEntry->ip;
					}
				}
				else
				{
					setTempLease(req->dhcpEntry);
					return req->dhcpEntry->ip;
				}
			}
		}
	}

	if (DNSService && req->hostname[0])
	{
		char hostname[128];
		strcpy(hostname, req->hostname);
		myLower(hostname);
		hostMap::iterator it = dnsCache[currentInd].find(hostname);

		for (; it != dnsCache[currentInd].end(); it++)
		{
			CachedData *cache = it->second;

			//printf("%u\n", cache->mapname);

			if (strcasecmp(cache->mapname, hostname))
				break;

			if (cache && cache->ip)
			{
				char k = getRangeInd(cache->ip);

				if (k >= 0)
				{
					if (checkRange(&rangeData, k))
					{
						DHCPRange *range = &config.dhcpRanges[k];
						int ind = getIndex(k, cache->ip);

						if (ind >= 0 && range->expiry[ind] <= t)
						{
							_DWord iip = htonl(cache->ip);

							if (!config.rangeSet[range->rangeSetInd].subnetIP[0])
							{
								calcRangeLimits(req->subnetIP, range->mask, &minRange, &maxRange);

								if (iip >= minRange && iip <= maxRange)
								{
									iipNew = iip;
									rangeInd = k;
									break;
								}
							}
							else
							{
								iipNew = iip;
								rangeInd = k;
								break;
							}
						}
					}
				}
			}
		}
	}

	if (!iipNew && req->requestIP)
	{
		char k = getRangeInd(req->requestIP);

		if (k >= 0)
		{
			if (checkRange(&rangeData, k))
			{
				DHCPRange *range = &config.dhcpRanges[k];
				int ind = getIndex(k, req->requestIP);

				if (range->expiry[ind] <= t)
				{
					if (!config.rangeSet[range->rangeSetInd].subnetIP[0])
					{
						calcRangeLimits(req->subnetIP, range->mask, &minRange, &maxRange);
						_DWord iip = htonl(req->requestIP);

						if (iip >= minRange && iip <= maxRange)
						{
							iipNew = iip;
							rangeInd = k;
						}
					}
					else
					{
						_DWord iip = htonl(req->requestIP);
						iipNew = iip;
						rangeInd = k;
					}
				}
			}
		}
	}


	for (char k = 0; !iipNew && k < config.rangeCount; k++)
	{
		if (checkRange(&rangeData, k))
		{
			DHCPRange *range = &config.dhcpRanges[k];
			rangeStart = range->rangeStart;
			rangeEnd = range->rangeEnd;

			if (!config.rangeSet[range->rangeSetInd].subnetIP[0])
			{
				calcRangeLimits(req->subnetIP, range->mask, &minRange, &maxRange);

				if (rangeStart < minRange)
					rangeStart = minRange;

				if (rangeEnd > maxRange)
					rangeEnd = maxRange;
			}

			if (rangeStart <= rangeEnd)
			{
				rangeFound = true;

				if (config.replication == 2)
				{
					for (_DWord m = rangeEnd; m >= rangeStart; m--)
					{
						int ind = m - range->rangeStart;

						if (!range->expiry[ind])
						{
							iipNew = m;
							rangeInd = k;
							break;
						}
						else if (!iipExp && range->expiry[ind] < t)
						{
							iipExp = m;
							rangeInd = k;
						}
					}
				}
				else
				{
					for (_DWord m = rangeStart; m <= rangeEnd; m++)
					{
						int ind = m - range->rangeStart;

						if (!range->expiry[ind])
						{
							iipNew = m;
							rangeInd = k;
							break;
						}
						else if (!iipExp && range->expiry[ind] < t)
						{
							iipExp = m;
							rangeInd = k;
						}
					}
				}
			}
		}
	}


	if (!iipNew && iipExp)
			iipNew = iipExp;

	if (iipNew)
	{
		if (!req->dhcpEntry)
		{
			memset(&lump, 0, sizeof(Lump));
			lump.cType = CTYPE_DHCP_ENTRY;
			lump.mapname = req->chaddr;
			lump.hostname = req->hostname;
			req->dhcpEntry = createCache(&lump);

			if (!req->dhcpEntry)
				return 0;

/*
			req->dhcpEntry = (CachedData*)calloc(1, sizeof(CachedData));

			if (!req->dhcpEntry)
			{
				sprintf(logBuff, "Memory Allocation Error");
				logDHCPMessage(logBuff, 1);
				return 0;
			}

			req->dhcpEntry->mapname = cloneString(req->chaddr);

			if (!req->dhcpEntry->mapname)
			{
				sprintf(logBuff, "Memory Allocation Error");
				logDHCPMessage(logBuff, 1);
				return 0;
			}
*/

			dhcpCache[req->dhcpEntry->mapname] = req->dhcpEntry;
		}

		req->dhcpEntry->ip = htonl(iipNew);
		req->dhcpEntry->rangeInd = rangeInd;
		setTempLease(req->dhcpEntry);
		return req->dhcpEntry->ip;
	}

	if (verbatim || config.dhcpLogLevel)
	{
		if (rangeFound)
		{
			if (req->DHCPPacket.header.bp_giaddr)
				sprintf(logBuff, "No free leases for DHCPDISCOVER for %s (%s) from RelayAgent %s", req->chaddr, req->hostname, IP2String(tempbuff, req->DHCPPacket.header.bp_giaddr));
			else
				sprintf(logBuff, "No free leases for DHCPDISCOVER for %s (%s) from interface %s", req->chaddr, req->hostname, IP2String(tempbuff, network.dhcpConn[req->sockInd].server));
		}
		else
		{
			if (req->DHCPPacket.header.bp_giaddr)
				sprintf(logBuff, "No Matching DHCP Range for DHCPDISCOVER for %s (%s) from RelayAgent %s", req->chaddr, req->hostname, IP2String(tempbuff, req->DHCPPacket.header.bp_giaddr));
			else
				sprintf(logBuff, "No Matching DHCP Range for DHCPDISCOVER for %s (%s) from interface %s", req->chaddr, req->hostname, IP2String(tempbuff, network.dhcpConn[req->sockInd].server));
		}
		logDHCPMessage(logBuff, 1);
	}
	return 0;
}

_DWord chad(DHCPRequest *req)
{
	req->dhcpEntry = findDHCPEntry(req->chaddr);
	//printf("dhcpEntry=%d\n", req->dhcpEntry);

	if (req->dhcpEntry && req->dhcpEntry->ip)
		return req->dhcpEntry->ip;
	else
		return 0;
}

_DWord sdmess(DHCPRequest *req)
{
	//sprintf(logBuff, "sdmess, Request Type = %u",req->req_type);
	//debug(logBuff);
	char logBuff[512];
	char tempbuff[512];

	if (req->req_type == DHCP_MESS_NONE)
	{
		req->DHCPPacket.header.bp_yiaddr = chad(req);

		if (!req->DHCPPacket.header.bp_yiaddr)
		{
			if (verbatim || config.dhcpLogLevel)
			{
				sprintf(logBuff, "No Static Entry found for BOOTPREQUEST from Host %s", req->chaddr);
				logDHCPMessage(logBuff, 1);
			}

			return 0;
		}
	}
	else if (req->req_type == DHCP_MESS_DECLINE)
	{
		if (req->DHCPPacket.header.bp_ciaddr && chad(req) == req->DHCPPacket.header.bp_ciaddr)
		{
			lockIP(req->DHCPPacket.header.bp_ciaddr);

			req->dhcpEntry->ip = 0;
			req->dhcpEntry->expiry = INT_MAX;
			req->dhcpEntry->display = false;
			req->dhcpEntry->local = false;

			if (verbatim || config.dhcpLogLevel)
			{
				sprintf(logBuff, "IP Address %s declined by Host %s (%s), locked", IP2String(tempbuff, req->DHCPPacket.header.bp_ciaddr), req->chaddr, req->hostname);
				logDHCPMessage(logBuff, 1);
			}
		}

		return 0;
	}
	else if (req->req_type == DHCP_MESS_RELEASE)
	{
		if (req->DHCPPacket.header.bp_ciaddr && chad(req) == req->DHCPPacket.header.bp_ciaddr)
		{
			req->dhcpEntry->display = false;
			req->dhcpEntry->local = false;
			req->lease = 0;
			setLeaseExpiry(req->dhcpEntry, 0);
			_beginthread(updateStateFile, 0, (void*)req->dhcpEntry);

			if (DNSService && config.replication != 2)
				expireEntry(req->dhcpEntry->ip);

			if (verbatim || config.dhcpLogLevel)
			{
				sprintf(logBuff, "IP Address %s released by Host %s (%s)", IP2String(tempbuff, req->DHCPPacket.header.bp_ciaddr), req->chaddr, req->hostname);
				logDHCPMessage(logBuff, 1);
			}
		}

		return 0;
	}
	else if (req->req_type == DHCP_MESS_INFORM)
	{
		//printf("repl0=%s\n", IP2String(tempbuff, config.zoneServers[0]));
		//printf("repl1=%s\n", IP2String(tempbuff, config.zoneServers[1]));
		//printf("IP=%s bytes=%u replication=%i\n", IP2String(tempbuff, req->remote.sin_addr.s_addr), req->bytes, config.replication);

		if ((config.replication == 1 && req->remote.sin_addr.s_addr == config.zoneServers[1]) || (config.replication == 2 && req->remote.sin_addr.s_addr == config.zoneServers[0]))
			recvRepl(req);

		return 0;
	}
	else if (req->req_type == DHCP_MESS_DISCOVER && strcasecmp(req->hostname, config.servername))
	{
		req->DHCPPacket.header.bp_yiaddr = resad(req);

		if (!req->DHCPPacket.header.bp_yiaddr)
			return 0;

		req->resp_type = DHCP_MESS_OFFER;
	}
	else if (req->req_type == DHCP_MESS_REQUEST)
	{
		//printf("%s\n", IP2String(tempbuff, req->DHCPPacket.header.bp_ciaddr));

		if (req->server)
		{
			if (req->server == network.dhcpConn[req->sockInd].server)
			{
				if (req->requestIP && req->requestIP == chad(req) && req->dhcpEntry->expiry > t)
				{
					req->resp_type = DHCP_MESS_ACK;
					req->DHCPPacket.header.bp_yiaddr = req->requestIP;
				}
				else if (req->DHCPPacket.header.bp_ciaddr && req->DHCPPacket.header.bp_ciaddr == chad(req) && req->dhcpEntry->expiry > t)
				{
					req->resp_type = DHCP_MESS_ACK;
					req->DHCPPacket.header.bp_yiaddr = req->DHCPPacket.header.bp_ciaddr;
				}
				else
				{
					req->resp_type = DHCP_MESS_NAK;
					req->DHCPPacket.header.bp_yiaddr = 0;

					if (verbatim || config.dhcpLogLevel)
					{
						sprintf(logBuff, "DHCPREQUEST from Host %s (%s) without Discover, NAKed", req->chaddr, req->hostname);
						logDHCPMessage(logBuff, 1);
					}
				}
			}
			else
				return 0;
		}
		else if (req->DHCPPacket.header.bp_ciaddr && req->DHCPPacket.header.bp_ciaddr == chad(req) && req->dhcpEntry->expiry > t)
		{
			req->resp_type = DHCP_MESS_ACK;
			req->DHCPPacket.header.bp_yiaddr = req->DHCPPacket.header.bp_ciaddr;
		}
		else if (req->requestIP && req->requestIP == chad(req) && req->dhcpEntry->expiry > t)
		{
			req->resp_type = DHCP_MESS_ACK;
			req->DHCPPacket.header.bp_yiaddr = req->requestIP;
		}
		else
		{
			req->resp_type = DHCP_MESS_NAK;
			req->DHCPPacket.header.bp_yiaddr = 0;

			if (verbatim || config.dhcpLogLevel)
			{
				sprintf(logBuff, "DHCPREQUEST from Host %s (%s) without Discover, NAKed", req->chaddr, req->hostname);
				logDHCPMessage(logBuff, 1);
			}
		}
	}
	else
		return 0;

	addOptions(req);
	int packSize = req->vp - (_Byte*)&req->DHCPPacket;
	packSize++;

	if (req->req_type == DHCP_MESS_NONE)
		packSize = req->messsize;

	if ((req->DHCPPacket.header.bp_giaddr || !req->remote.sin_addr.s_addr) && req->dhcpEntry && req->dhcpEntry->rangeInd >= 0)
	{
		_Byte rangeSetInd = config.dhcpRanges[req->dhcpEntry->rangeInd].rangeSetInd;
		req->targetIP = config.rangeSet[rangeSetInd].targetIP;
	}

	if (req->targetIP)
	{
		req->remote.sin_port = htons(IPPORT_DHCPS);
		req->remote.sin_addr.s_addr = req->targetIP;
	}
	else if (req->DHCPPacket.header.bp_giaddr)
	{
		req->remote.sin_port = htons(IPPORT_DHCPS);
		req->remote.sin_addr.s_addr = req->DHCPPacket.header.bp_giaddr;
	}
	//else if (req->DHCPPacket.header.bp_broadcast || !req->remote.sin_addr.s_addr || req->requestIP)
	else if (req->DHCPPacket.header.bp_broadcast || !req->remote.sin_addr.s_addr)
	{
		req->remote.sin_port = htons(IPPORT_DHCPC);
		req->remote.sin_addr.s_addr = INADDR_BROADCAST;
	}
	else
	{
		req->remote.sin_port = htons(IPPORT_DHCPC);
	}

	req->DHCPPacket.header.bp_op = BOOTP_REPLY;
	errno = 0;

	if (req->req_type == DHCP_MESS_DISCOVER && !req->DHCPPacket.header.bp_giaddr)
	{
		req->bytes = sendto(network.dhcpConn[req->sockInd].sock,
							req->raw,
							packSize,
							MSG_DONTROUTE,
							(sockaddr*)&req->remote,
							sizeof(req->remote));
	}
	else
	{
		req->bytes = sendto(network.dhcpConn[req->sockInd].sock,
							req->raw,
							packSize,
							0,
							(sockaddr*)&req->remote,
							sizeof(req->remote));
	}

	if (errno || req->bytes <= 0)
		return 0;

	//printf("goes=%s %i\n",IP2String(tempbuff, req->DHCPPacket.header.bp_yiaddr),req->sockInd);
	return req->DHCPPacket.header.bp_yiaddr;
}

_DWord alad(DHCPRequest *req)
{
	//debug("alad");
	//printf("in alad hostname=%s\n", req->hostname);
	char logBuff[512];
	char tempbuff[512];

	if (req->dhcpEntry && (req->req_type == DHCP_MESS_NONE || req->resp_type == DHCP_MESS_ACK))
	{
		_DWord hangTime = req->lease;

		if (req->rebind > req->lease)
			hangTime = req->rebind;

		req->dhcpEntry->display = true;
		req->dhcpEntry->local = true;
		setLeaseExpiry(req->dhcpEntry, hangTime);

		_beginthread(updateStateFile, 0, (void*)req->dhcpEntry);

		if (DNSService && config.replication != 2)
			updateDNS(req);

		if (verbatim || config.dhcpLogLevel >= 1)
		{
			if (req->lease && req->requestIP)
			{
				sprintf(logBuff, "Host %s (%s) allotted %s for %u seconds", req->chaddr, req->hostname, IP2String(tempbuff, req->DHCPPacket.header.bp_yiaddr), req->lease);
			}
			else if (req->req_type)
			{
				sprintf(logBuff, "Host %s (%s) renewed %s for %u seconds", req->chaddr, req->hostname, IP2String(tempbuff, req->DHCPPacket.header.bp_yiaddr), req->lease);
			}
			else
			{
				sprintf(logBuff, "BOOTP Host %s (%s) allotted %s", req->chaddr, req->hostname, IP2String(tempbuff, req->DHCPPacket.header.bp_yiaddr));
			}
			logDHCPMessage(logBuff, 1);
		}

		if (config.replication && config.dhcpRepl > t)
			sendRepl(req);

		return req->dhcpEntry->ip;
	}
	else if ((verbatim || config.dhcpLogLevel >= 2) && req->resp_type == DHCP_MESS_OFFER)
	{
		sprintf(logBuff, "Host %s (%s) offered %s", req->chaddr, req->hostname, IP2String(tempbuff, req->DHCPPacket.header.bp_yiaddr));
		logDHCPMessage(logBuff, 2);
	}
	//printf("%u=out\n", req->resp_type);
	return 0;
}

void addOptions(DHCPRequest *req)
{
	//debug("addOptions");

	data3 op;
	int i;

	if (req->req_type && req->resp_type)
	{
		op.opt_code = DHCP_OPTION_MESSAGETYPE;
		op.size = 1;
		op.value[0] = req->resp_type;
		pvdata(req, &op);
	}

	if (req->dhcpEntry && req->resp_type != DHCP_MESS_DECLINE && req->resp_type != DHCP_MESS_NAK)
	{
		strcpy(req->DHCPPacket.header.bp_sname, config.servername);

		if (req->dhcpEntry->fixed)
		{
			//printf("%u,%u\n", req->dhcpEntry->options, *req->dhcpEntry->options);
			_Byte *opPointer = req->dhcpEntry->options;

			if (opPointer)
			{
				_Byte requestedOnly = *opPointer;
				opPointer++;

				while (*opPointer && *opPointer != DHCP_OPTION_END)
				{
					op.opt_code = *opPointer;
					opPointer++;
					op.size = *opPointer;
					opPointer++;

					if (!requestedOnly || req->paramreqlist[*opPointer])
					{
						memcpy(op.value, opPointer, op.size);
						pvdata(req, &op);
					}
					opPointer += op.size;
				}
			}
		}

		if (req->req_type && req->resp_type)
		{
			if (req->dhcpEntry->rangeInd >= 0)
			{
				_Byte *opPointer = config.dhcpRanges[req->dhcpEntry->rangeInd].options;
				//printf("Range=%i Pointer=%u\n", req->dhcpEntry->rangeInd,opPointer);

				if (opPointer)
				{
					_Byte requestedOnly = *opPointer;
					opPointer++;

					while (*opPointer && *opPointer != DHCP_OPTION_END)
					{
						op.opt_code = *opPointer;
						opPointer++;
						op.size = *opPointer;
						opPointer++;

						if (!requestedOnly || req->paramreqlist[*opPointer])
						{
							memcpy(op.value, opPointer, op.size);
							pvdata(req, &op);
						}
						opPointer += op.size;
					}
				}
			}

			_Byte *opPointer = config.options;

			if (opPointer)
			{
				_Byte requestedOnly = *opPointer;

				opPointer++;
				while (*opPointer && *opPointer != DHCP_OPTION_END)
				{
					op.opt_code = *opPointer;
					opPointer++;
					op.size = *opPointer;
					opPointer++;

					if (!requestedOnly || req->paramreqlist[*opPointer])
					{
						memcpy(op.value, opPointer, op.size);
						pvdata(req, &op);
					}
					opPointer += op.size;
				}
			}

			op.opt_code = DHCP_OPTION_SERVERID;
			op.size = 4;
			pIP(op.value, network.dhcpConn[req->sockInd].server);
			pvdata(req, &op);

			op.opt_code = DHCP_OPTION_DOMAINNAME;
			op.size = strlen(config.zone) + 1;
			memcpy(op.value, config.zone, op.size);
			pvdata(req, &op);

			if (!req->opAdded[DHCP_OPTION_IPADDRLEASE])
			{
				op.opt_code = DHCP_OPTION_IPADDRLEASE;
				op.size = 4;
				pULong(op.value, config.lease);
				pvdata(req, &op);
			}

			if (!req->opAdded[DHCP_OPTION_NETMASK])
			{
				op.opt_code = DHCP_OPTION_NETMASK;
				op.size = 4;

				if (req->dhcpEntry->rangeInd >= 0)
					pIP(op.value, config.dhcpRanges[req->dhcpEntry->rangeInd].mask);
				else
					pIP(op.value, config.mask);

				pvdata(req, &op);
			}

			if (!req->hostname[0])
				genHostName(req->hostname, req->DHCPPacket.header.bp_chaddr, req->DHCPPacket.header.bp_hlen);

			strcpy(req->dhcpEntry->hostname, req->hostname);
/*
			if (!req->opAdded[DHCP_OPTION_ROUTER])
			{
				op.opt_code = DHCP_OPTION_ROUTER;
				op.size = 4;
				pIP(op.value, network.dhcpConn[req->sockInd].server);
				pvdata(req, &op);
			}
*/
			if (!req->opAdded[DHCP_OPTION_DNS])
			{
				if (DNSService)
				{
					op.opt_code = DHCP_OPTION_DNS;

					if (config.dhcpRepl > t && config.dnsRepl > t)
					{
						if (config.replication == 1)
						{
							op.size = 8;
							pIP(op.value, config.zoneServers[0]);
							pIP(op.value + 4, config.zoneServers[1]);
							pvdata(req, &op);
						}
						else
						{
							op.size = 8;
							pIP(op.value, config.zoneServers[1]);
							pIP(op.value + 4, config.zoneServers[0]);
							pvdata(req, &op);
						}
					}
					else if (config.dnsRepl > t)
					{
						op.size = 8;
						pIP(op.value, config.zoneServers[1]);
						pIP(op.value + 4, config.zoneServers[0]);
						pvdata(req, &op);
					}
					else
					{
						op.size = 4;
						pIP(op.value, network.dhcpConn[req->sockInd].server);
						pvdata(req, &op);
					}
				}
				else if (config.dnsRepl > t && config.replication == 2)
				{
					op.opt_code = DHCP_OPTION_DNS;
					op.size = 4;
					pIP(op.value, config.zoneServers[0]);
					pvdata(req, &op);
				}
			}
/*
			if (req->clientId.opt_code == DHCP_OPTION_CLIENTID)
				pvdata(req, &req->clientId);
*/
			if (req->subnet.opt_code == DHCP_OPTION_SUBNETSELECTION)
				pvdata(req, &req->subnet);

			if (req->agentOption.opt_code == DHCP_OPTION_RELAYAGENTINFO)
				pvdata(req, &req->agentOption);
		}
	}

	*(req->vp) = DHCP_OPTION_END;
}

void pvdata(DHCPRequest *req, data3 *op)
{
	//debug("pvdata");

	if (!req->opAdded[op->opt_code] && ((req->vp - (_Byte*)&req->DHCPPacket) + op->size < req->messsize))
	{
		if (op->opt_code == DHCP_OPTION_NEXTSERVER)
			req->DHCPPacket.header.bp_siaddr = fIP(op->value);
		else if (op->opt_code == DHCP_OPTION_BP_FILE)
		{
			if (op->size <= 128)
				memcpy(req->DHCPPacket.header.bp_file, op->value, op->size);
		}
		else if(op->size)
		{
			if (op->opt_code == DHCP_OPTION_IPADDRLEASE)
			{
				if (!req->lease || req->lease > fULong(op->value))
					req->lease = fULong(op->value);

				if (req->lease >= INT_MAX)
					req->lease = UINT_MAX;

				pULong(op->value, req->lease);
			}
			else if (op->opt_code == DHCP_OPTION_REBINDINGTIME)
				req->rebind = fULong(op->value);
			else if (op->opt_code == DHCP_OPTION_HOSTNAME)
			{
				memcpy(req->hostname, op->value, op->size);
				req->hostname[op->size] = 0;
				req->hostname[64] = 0;

				if (char *ptr = strchr(req->hostname, '.'))
					*ptr = 0;

				op->size = strlen(req->hostname);
			}

			_Word tsize = op->size + 2;
			memcpy(req->vp, op, tsize);
			(req->vp) += tsize;
		}
		req->opAdded[op->opt_code] = true;
	}
}

void updateDNS(DHCPRequest *req)
{
	_DWord expiry = INT_MAX;

	if (req->lease < (_DWord)(INT_MAX - t))
		expiry = t + req->lease;

	if (req->dhcpEntry && config.replication != 2)
	{
		//printf("Update DNS t=%d exp=%d\n", t, req->dhcpEntry->expiry);
		if (isLocal(req->dhcpEntry->ip))
			add2Cache(req->hostname, req->dhcpEntry->ip, expiry, CTYPE_LOCAL_A, CTYPE_LOCAL_PTR_AUTH);
		else
			add2Cache(req->hostname, req->dhcpEntry->ip, expiry, CTYPE_LOCAL_A, CTYPE_LOCAL_PTR_NAUTH);
	}
}

void setTempLease(CachedData *dhcpEntry)
{
	if (dhcpEntry && dhcpEntry->ip)
	{
		dhcpEntry->display = false;
		dhcpEntry->local = false;
		dhcpEntry->expiry = t + 20;

		int ind = getIndex(dhcpEntry->rangeInd, dhcpEntry->ip);

		if (ind >= 0)
		{
			if (config.dhcpRanges[dhcpEntry->rangeInd].expiry[ind] != INT_MAX)
				config.dhcpRanges[dhcpEntry->rangeInd].expiry[ind] = dhcpEntry->expiry;

			config.dhcpRanges[dhcpEntry->rangeInd].dhcpEntry[ind] = dhcpEntry;
		}
	}
}

void setLeaseExpiry(CachedData *dhcpEntry, _DWord lease)
{
	//printf("%d=%d\n", t, lease);
	if (dhcpEntry && dhcpEntry->ip)
	{
		if (lease > (_DWord)(INT_MAX - t))
			dhcpEntry->expiry = INT_MAX;
		else
			dhcpEntry->expiry = t + lease;

		int ind = getIndex(dhcpEntry->rangeInd, dhcpEntry->ip);

		if (ind >= 0)
		{
			if (config.dhcpRanges[dhcpEntry->rangeInd].expiry[ind] != INT_MAX)
				config.dhcpRanges[dhcpEntry->rangeInd].expiry[ind] = dhcpEntry->expiry;

			config.dhcpRanges[dhcpEntry->rangeInd].dhcpEntry[ind] = dhcpEntry;
		}
	}
}

void setLeaseExpiry(CachedData *dhcpEntry)
{
	if (dhcpEntry && dhcpEntry->ip)
	{
		int ind = getIndex(dhcpEntry->rangeInd, dhcpEntry->ip);

		if (ind >= 0)
		{
			if (config.dhcpRanges[dhcpEntry->rangeInd].expiry[ind] != INT_MAX)
				config.dhcpRanges[dhcpEntry->rangeInd].expiry[ind] = dhcpEntry->expiry;

			config.dhcpRanges[dhcpEntry->rangeInd].dhcpEntry[ind] = dhcpEntry;
		}
	}
}


void lockIP(_DWord ip)
{
	if (dhcpService && ip)
	{
		_DWord iip = htonl(ip);

		for (char rangeInd = 0; rangeInd < config.rangeCount; rangeInd++)
		{
			if (iip >= config.dhcpRanges[rangeInd].rangeStart && iip <= config.dhcpRanges[rangeInd].rangeEnd)
			{
				int ind = iip - config.dhcpRanges[rangeInd].rangeStart;

				if (config.dhcpRanges[rangeInd].expiry[ind] != INT_MAX)
					config.dhcpRanges[rangeInd].expiry[ind] = INT_MAX;

				break;
			}
		}
	}
}

void holdIP(_DWord ip)
{
	if (dhcpService && ip)
	{
		_DWord iip = htonl(ip);

		for (char rangeInd = 0; rangeInd < config.rangeCount; rangeInd++)
		{
			if (iip >= config.dhcpRanges[rangeInd].rangeStart && iip <= config.dhcpRanges[rangeInd].rangeEnd)
			{
				int ind = iip - config.dhcpRanges[rangeInd].rangeStart;

				if (config.dhcpRanges[rangeInd].expiry[ind] == 0)
					config.dhcpRanges[rangeInd].expiry[ind] = 1;

				break;
			}
		}
	}
}

void __cdecl sendToken(void *lpParam)
{
	//debug("Send Token");
	Sleep(1000 * 10);

	while (kRunning)
	{
		errno = 0;

		sendto(config.dhcpReplConn.sock,
				token.raw,
				token.bytes,
				0,
				(sockaddr*)&token.remote,
				sizeof(token.remote));

//		errno = WSAGetLastError();
//
//		if (!errno && verbatim || config.dhcpLogLevel >= 2)
//		{
//			sprintf(logBuff, "Token Sent");
//			logDHCPMessage(logBuff, 2);
//		}

		Sleep(1000 * 300);
	}

	_endthread();
	return;
}


_DWord sendRepl(DHCPRequest *req)
{
	char logBuff[512];
	char ipbuff[32];
	data3 op;

	_Byte *opPointer = req->DHCPPacket.vend_data;

	while ((*opPointer) != DHCP_OPTION_END && opPointer < req->vp)
	{
		if ((*opPointer) == DHCP_OPTION_MESSAGETYPE)
		{
			*(opPointer + 2) = DHCP_MESS_INFORM;
			break;
		}
		opPointer = opPointer + *(opPointer + 1) + 2;
	}

	if (!req->opAdded[DHCP_OPTION_MESSAGETYPE])
	{
		op.opt_code = DHCP_OPTION_MESSAGETYPE;
		op.size = 1;
		op.value[0] = DHCP_MESS_INFORM;
		pvdata(req, &op);
	}

	if (req->hostname[0] && !req->opAdded[DHCP_OPTION_HOSTNAME])
	{
		op.opt_code = DHCP_OPTION_HOSTNAME;
		op.size = strlen(req->hostname);
		memcpy(op.value, req->hostname, op.size);
		pvdata(req, &op);
	}

//	op.opt_code = DHCP_OPTION_SERIAL;
//	op.size = 4;
//	pULong(op.value, config.serial1);
//	pvdata(req, &op);

	*(req->vp) = DHCP_OPTION_END;
	req->vp++;
	req->bytes = req->vp - (_Byte*)req->raw;

	req->DHCPPacket.header.bp_op = BOOTP_REQUEST;
	errno = 0;

	req->bytes = sendto(config.dhcpReplConn.sock,
	                    req->raw,
	                    req->bytes,
	                    0,
						(sockaddr*)&token.remote,
						sizeof(token.remote));

	errno = WSAGetLastError();

	if (errno || req->bytes <= 0)
	{
		config.dhcpRepl = 0;

		if (verbatim || config.dhcpLogLevel >= 1)
		{
			if (config.replication == 1)
				sprintf(logBuff, "WSAError %u Sending DHCP Update to Secondary Server", errno);
			else
				sprintf(logBuff, "WSAError %u Sending DHCP Update to Primary Server", errno);

			logDHCPMessage(logBuff, 1);
		}

		return 0;
	}
	else if (verbatim || config.dhcpLogLevel >= 2)
	{
		if (config.replication == 1)
			sprintf(logBuff, "DHCP Update for host %s (%s) sent to Secondary Server", req->dhcpEntry->mapname, IP2String(ipbuff, req->dhcpEntry->ip));
		else
			sprintf(logBuff, "DHCP Update for host %s (%s) sent to Primary Server", req->dhcpEntry->mapname, IP2String(ipbuff, req->dhcpEntry->ip));

		logDHCPMessage(logBuff, 2);
	}

	return req->DHCPPacket.header.bp_yiaddr;
}

/*
_DWord sendRepl(CachedData *dhcpEntry)
{
	DHCPRequest req;
	memset(&req, 0, sizeof(DHCPRequest));
	req.vp = req.DHCPPacket.vend_data;
	req.messsize = sizeof(DHCPPacket);
	req.dhcpEntry = dhcpEntry;

	req.DHCPPacket.header.bp_op = BOOTP_REQUEST;
	req.DHCPPacket.header.bp_xid = t;
	req.DHCPPacket.header.bp_ciaddr = dhcpEntry->ip;
	req.DHCPPacket.header.bp_yiaddr = dhcpEntry->ip;
	req.DHCPPacket.header.bp_hlen = 16;
	getHexValue(req.DHCPPacket.header.bp_chaddr, req.dhcpEntry->mapname, &(req.DHCPPacket.header.bp_hlen));
	req.DHCPPacket.header.bp_magic_num[0] = 99;
	req.DHCPPacket.header.bp_magic_num[1] = 130;
	req.DHCPPacket.header.bp_magic_num[2] = 83;
	req.DHCPPacket.header.bp_magic_num[3] = 99;
	strcpy(req.hostname, dhcpEntry->hostname);

	return sendRepl(&req);
}
*/

void recvRepl(DHCPRequest *req)
{
	char ipbuff[32];
	char logBuff[512];
	config.dhcpRepl = t + 650;

	_DWord ip = req->DHCPPacket.header.bp_yiaddr ? req->DHCPPacket.header.bp_yiaddr : req->DHCPPacket.header.bp_ciaddr;

	if (!ip || !req->DHCPPacket.header.bp_hlen)
	{
//		if (verbatim || config.dhcpLogLevel >= 2)
//		{
//			sprintf(logBuff, "Token Received");
//			logDHCPMessage(logBuff, 2);
//		}

		if (req->DNS)
			config.dnsRepl = t + 650;

		if (config.replication == 1)
		{
			if (req->DHCPPacket.header.bp_sname[0])
			{
				sprintf(config.nsS, "%s.%s", req->DHCPPacket.header.bp_sname, config.zone);

				if (isLocal(config.zoneServers[1]))
					add2Cache(req->DHCPPacket.header.bp_sname, config.zoneServers[1], INT_MAX, CTYPE_SERVER_A_AUTH, CTYPE_SERVER_PTR_AUTH);
				else
					add2Cache(req->DHCPPacket.header.bp_sname, config.zoneServers[1], INT_MAX, CTYPE_SERVER_A_AUTH, CTYPE_SERVER_PTR_NAUTH);
			}

			errno = 0;

			sendto(config.dhcpReplConn.sock,
					token.raw,
					token.bytes,
					0,
					(sockaddr*)&token.remote,
					sizeof(token.remote));

//			errno = WSAGetLastError();
//
//			if (!errno && (verbatim || config.dhcpLogLevel >= 2))
//			{
//				sprintf(logBuff, "Token Responded");
//				logDHCPMessage(logBuff, 2);
//			}
		}
		else if (config.replication == 2)
		{
			if (req->DHCPPacket.header.bp_sname[0])
				sprintf(config.nsP, "%s.%s", req->DHCPPacket.header.bp_sname, config.zone);
		}

		return;
	}

	char rInd = getRangeInd(ip);

	if (rInd >= 0)
	{
		int ind  = getIndex(rInd, ip);
		req->dhcpEntry = config.dhcpRanges[rInd].dhcpEntry[ind];

		if (req->dhcpEntry && !req->dhcpEntry->fixed && strcasecmp(req->dhcpEntry->mapname, req->chaddr))
			req->dhcpEntry->expiry = 0;
	}

	req->dhcpEntry = findDHCPEntry(req->chaddr);

	if (req->dhcpEntry && req->dhcpEntry->ip != ip)
	{
		if (req->dhcpEntry->fixed)
		{
			if (config.replication == 1)
				sprintf(logBuff, "DHCP Update ignored for %s (%s) from Secondary Server", req->chaddr, IP2String(ipbuff, ip));
			else
				sprintf(logBuff, "DHCP Update ignored for %s (%s) from Primary Server", req->chaddr, IP2String(ipbuff, ip));

			logDHCPMessage(logBuff, 1);
			return;
		}
		else if (req->dhcpEntry->rangeInd >= 0)
		{
			int ind  = getIndex(req->dhcpEntry->rangeInd, req->dhcpEntry->ip);

			if (ind >= 0)
				config.dhcpRanges[req->dhcpEntry->rangeInd].dhcpEntry[ind] = 0;
		}
	}

	if (!req->dhcpEntry && rInd >= 0)
	{
		memset(&lump, 0, sizeof(Lump));
		lump.cType = CTYPE_DHCP_ENTRY;
		lump.mapname = req->chaddr;
		lump.hostname = req->hostname;
		req->dhcpEntry = createCache(&lump);

		if (req->dhcpEntry)
			dhcpCache[req->dhcpEntry->mapname] = req->dhcpEntry;
/*
		req->dhcpEntry = (CachedData*)calloc(1, sizeof(CachedData));

		if (!req->dhcpEntry)
		{
			sprintf(logBuff, "Memory Allocation Error");
			logDHCPMessage(logBuff, 1);
			return;
		}

		req->dhcpEntry->mapname = cloneString(req->chaddr);

		if (!req->dhcpEntry->mapname)
		{
			sprintf(logBuff, "Memory Allocation Error");
			free(req->dhcpEntry);
			logDHCPMessage(logBuff, 1);
			return;
		}
*/
	}

	if (req->dhcpEntry)
	{
		req->dhcpEntry->ip = ip;
		req->dhcpEntry->rangeInd = rInd;
		req->dhcpEntry->display = true;
		req->dhcpEntry->local = false;

		_DWord hangTime = req->lease;

		if (req->rebind > req->lease)
			hangTime = req->rebind;

		setLeaseExpiry(req->dhcpEntry, hangTime);
		strcpy(req->dhcpEntry->hostname, req->hostname);

		_beginthread(updateStateFile, 0, (void*)req->dhcpEntry);

		if (DNSService && config.replication != 2)
		{
			if (req->lease)
				updateDNS(req);
			else
				expireEntry(req->dhcpEntry->ip);
		}

		if (verbatim || config.dhcpLogLevel >= 2)
		{
			if (config.replication == 1)
				sprintf(logBuff, "DHCP Update received for %s (%s) from Secondary Server", req->chaddr, IP2String(ipbuff, ip));
			else
				sprintf(logBuff, "DHCP Update received for %s (%s) from Primary Server", req->chaddr, IP2String(ipbuff, ip));

			logDHCPMessage(logBuff, 2);
		}
	}
	else
	{
		if (config.replication == 1)
			sprintf(logBuff, "DHCP Update ignored for %s (%s) from Secondary Server", req->chaddr, IP2String(ipbuff, ip));
		else
			sprintf(logBuff, "DHCP Update ignored for %s (%s) from Primary Server", req->chaddr, IP2String(ipbuff, ip));

		logDHCPMessage(logBuff, 1);
		return;
	}
}

char getRangeInd(_DWord ip)
{
	if (ip)
	{
		_DWord iip = htonl(ip);

		for (char k = 0; k < config.rangeCount; k++)
			if (iip >= config.dhcpRanges[k].rangeStart && iip <= config.dhcpRanges[k].rangeEnd)
				return k;
	}
	return -1;
}

int getIndex(char rangeInd, _DWord ip)
{
	if (ip && rangeInd >= 0 && rangeInd < config.rangeCount)
	{
		_DWord iip = htonl(ip);
		if (iip >= config.dhcpRanges[rangeInd].rangeStart && iip <= config.dhcpRanges[rangeInd].rangeEnd)
			return (iip - config.dhcpRanges[rangeInd].rangeStart);
	}
	return -1;
}

void loadOptions(FILE *f, const char *sectionName, OptionData *optionData)
{
	optionData->ip = 0;
	optionData->mask = 0;
	_Byte maxInd = sizeof(opData) / sizeof(data4);
	_Word buffsize = sizeof(DHCPPacket) - sizeof(DHCPHeader);
	_Byte *dp = optionData->options;
	_Byte op_specified[256];

	memset(op_specified, 0, 256);
	*dp = 0;
	dp++;

	char raw[512];
	char name[512];
	char value[512];
	char logBuff[512];

	while (readSection(raw, f))
	{
		_Byte *ddp = dp;
		_Byte hoption[256];
		_Byte valSize = sizeof(hoption) - 1;
		_Byte opTag = 0;
		_Byte opType = 0;
		_Byte valType = 0;
		bool tagFound = false;

		mySplit(name, value, raw, '=');

		//printf("%s=%s\n", name, value);

		if (!name[0])
		{
			sprintf(logBuff, "Warning: section [%s] invalid option %s ignored", sectionName, raw);
			logDHCPMessage(logBuff, 1);
			continue;
		}

		if (!strcasecmp(name, "DHCPRange"))
		{
			if (!strcasecmp(sectionName, RANGESET))
				addDHCPRange(value);
			else
			{
				sprintf(logBuff, "Warning: section [%s] option %s not allowed in this section, option ignored", sectionName, raw);
				logDHCPMessage(logBuff, 1);
			}
			continue;
		}
		else if (!strcasecmp(name, "IP"))
		{
			if (!strcasecmp(sectionName, GLOBALOPTIONS) || !strcasecmp(sectionName, RANGESET))
			{
				sprintf(logBuff, "Warning: section [%s] option %s not allowed in this section, option ignored", sectionName, raw);
				logDHCPMessage(logBuff, 1);
			}
			else if (!isIP(value) && strcasecmp(value, "0.0.0.0"))
			{
				sprintf(logBuff, "Warning: section [%s] option Invalid IP Addr %s option ignored", sectionName, value);
				logDHCPMessage(logBuff, 1);
			}
			else
				optionData->ip = inet_addr(value);

			continue;
		}
		else if (!strcasecmp(name, "FilterMacRange"))
		{
			if (!strcasecmp(sectionName, RANGESET))
				addMacRange(optionData->rangeSetInd, value);
			else
			{
				sprintf(logBuff, "Warning: section [%s] option %s not allowed in this section, option ignored", sectionName, raw);
				logDHCPMessage(logBuff, 1);
			}
			continue;
		}

		if (!value[0])
			valType = 9;
		else if (value[0] == '"' && value[strlen(value)-1] == '"')
		{
			valType = 2;
			value[0] = NBSP;
			value[strlen(value) - 1] = NBSP;
			myTrim(value, value);

			if (strlen(value) <= UCHAR_MAX)
				valSize = strlen(value);
			else
			{
				sprintf(logBuff, "Warning: section [%s] option %s value too big, option ignored", sectionName, raw);
				logDHCPMessage(logBuff, 1);
				continue;
			}
		}
		else if (strchr(value, ':'))
		{
			valType = 2;
			valSize = sizeof(hoption) - 1;
			char *errorPos = getHexValue(hoption, value, &valSize);

			if (errorPos)
			{
				valType = 1;
				valSize = strlen(value);
			}
			else
				memcpy(value, hoption, valSize);
		}
		else if (isInt(value) && atol(value) > USHRT_MAX)
			valType = 4;
		else if (isInt(value) && atoi(value) > UCHAR_MAX)
			valType = 5;
		else if (isInt(value))
			valType = 6;
//		else if ((strchr(value, '.') && (opType == 2 || opType == 3 || opType == 8 || opType == 0)) || (!strchr(value, '.') && strchr(value, ',')))
		else if (strchr(value, '.') || strchr(value, ','))
		{
			valType = 2;
			char buff[1024];
			int numbytes = myTokenize(buff, value, "/,.", true);

			if (numbytes > 255)
			{
				sprintf(logBuff, "Warning: section [%s] option %s, too many bytes, entry ignored", sectionName, raw);
				logDHCPMessage(logBuff, 1);
				continue;
			}
			else
			{
				char *ptr = buff;
				valSize = 0;

				for (; *ptr; ptr = myGetToken(ptr, 1))
				{
					//printf("%s:", ptr);
					if (isInt(ptr) && atoi(ptr) <= UCHAR_MAX)
					{
						hoption[valSize] = atoi(ptr);
						valSize++;
					}
					else
						break;
				}

				if (!(*ptr))
					memcpy(value, hoption, valSize);
				else
				{
					valType = 1;
					valSize = strlen(value);
				}
			}
		}
		else
		{
			if (strlen(value) <= UCHAR_MAX)
			{
				valSize = strlen(value);
				valType = 1;
			}
			else
			{
				sprintf(logBuff, "Warning: section [%s] option %s value too long, option ignored", sectionName, raw);
				logDHCPMessage(logBuff, 1);
				continue;
			}
		}

		if (!strcasecmp(name, "FilterVendorClass"))
		{
			if (!strcasecmp(sectionName, RANGESET))
				addVendClass(optionData->rangeSetInd, value, valSize);
			else
			{
				sprintf(logBuff, "Warning: section [%s] option %s not allowed in this section, option ignored", sectionName, raw);
				logDHCPMessage(logBuff, 1);
			}
			continue;
		}
		else if (!strcasecmp(name, "FilterUserClass"))
		{
			if (!strcasecmp(sectionName, RANGESET))
				addUserClass(optionData->rangeSetInd, value, valSize);
			else
			{
				sprintf(logBuff, "Warning: section [%s] option %s not allowed in this section, option ignored", sectionName, raw);
				logDHCPMessage(logBuff, 1);
			}
			continue;
		}
		else if (!strcasecmp(name, "FilterSubnetSelection"))
		{
			if (valSize != 4)
			{
				sprintf(logBuff, "Warning: section [%s] invalid value %s, option ignored", sectionName, raw);
				logDHCPMessage(logBuff, 1);
			}
			else if (!strcasecmp(sectionName, RANGESET))
			{
				addServer(config.rangeSet[optionData->rangeSetInd].subnetIP, MAX_RANGE_FILTERS, fIP(value));
				config.hasFilter = 1;
			}
			else
			{
				sprintf(logBuff, "Warning: section [%s] option %s not allowed in this section, option ignored", sectionName, raw);
				logDHCPMessage(logBuff, 1);
			}
			continue;
		}
		else if (!strcasecmp(name, "TargetRelayAgent"))
		{
			if (valSize != 4)
			{
				sprintf(logBuff, "Warning: section [%s] invalid value %s, option ignored", sectionName, raw);
				logDHCPMessage(logBuff, 1);
			}
			else if (!strcasecmp(sectionName, RANGESET))
			{
				config.rangeSet[optionData->rangeSetInd].targetIP = fIP(value);
				//printf("TARGET IP %s set RangeSetInd  %d\n", IP2String(ipbuff, config.rangeSet[optionData->rangeSetInd].targetIP), optionData->rangeSetInd);
			}
			else
			{
				sprintf(logBuff, "Warning: section [%s] option %s not allowed in this section, option ignored", sectionName, raw);
				logDHCPMessage(logBuff, 1);
			}
			continue;
		}

		opTag = 0;

		if (isInt(name))
		{
			if (atoi(name) < 1 || atoi(name) >= 254)
			{
				sprintf(logBuff, "Warning: section [%s] invalid option %s, ignored", sectionName, raw);
				logDHCPMessage(logBuff, 1);
				continue;
			}

			opTag = atoi(name);
			opType = 0;
		}

		for (_Byte i = 0; i < maxInd; i++)
			if (!strcasecmp(name, opData[i].opName) || (opTag && opTag == opData[i].opTag))
			{
				opTag = opData[i].opTag;
				opType = opData[i].opType;
				tagFound = true;
				break;
			}

		if (!opTag)
		{
			sprintf(logBuff, "Warning: section [%s] invalid option %s, ignored", sectionName, raw);
			logDHCPMessage(logBuff, 1);
			continue;
		}

		if (!opType)
			opType = valType;

		//sprintf(logBuff, "Tag %i ValType %i opType %i value=%s size=%u", opTag, valType, opType, value, valSize);
		//logDHCPMessage(logBuff, 1);

		if (op_specified[opTag])
		{
			sprintf(logBuff, "Warning: section [%s] duplicate option %s, ignored", sectionName, raw);
			logDHCPMessage(logBuff, 1);
			continue;
		}

		//printf("Option=%u opType=%u valueType=%u valSize=%u\n", opTag, opType, valType, valSize);

		op_specified[opTag] = true;

		if (valType == 9)
		{
			if (buffsize > 2)
			{
				*dp = opTag;
				dp++;
				*dp = 0;
				dp++;
				buffsize -= 2;
			}
			else
			{
				sprintf(logBuff, "Warning: section [%s] option %s, no more space for options", sectionName, raw);
				logDHCPMessage(logBuff, 1);
			}
			continue;
		}

		switch (opType)
		{
			case 1:
			{
				value[valSize] = 0;
				valSize++;

				if (valType != 1 && valType != 2)
				{
					sprintf(logBuff, "Warning: section [%s] option %s, need string value, option ignored", sectionName, raw);
					logDHCPMessage(logBuff, 1);
				}
				else if (opTag == DHCP_OPTION_DOMAINNAME)
				{
					sprintf(logBuff, "Warning: section [%s] option %u should be under [DOMAIN_NAME], ignored", sectionName, opTag);
					logDHCPMessage(logBuff, 1);
					continue;
				}
				else if (buffsize > valSize + 2)
				{
					*dp = opTag;
					dp++;
					*dp = valSize;
					dp++;
					memcpy(dp, value, valSize);
					dp += valSize;
					buffsize -= (valSize + 2);
				}
				else
				{
					sprintf(logBuff, "Warning: section [%s] option %s, no more space for options", sectionName, raw);
					logDHCPMessage(logBuff, 1);
				}
			}
			break;

			case 3:
			case 8:
			{
				if (valType == 2)
				{
					if (opType == 3 && valSize % 4)
					{
						sprintf(logBuff, "Warning: section [%s] option %s, missing/extra bytes/octates in IP, option ignored", sectionName, raw);
						logDHCPMessage(logBuff, 1);
						continue;
					}
					else if (opType == 8 && valSize % 8)
					{
						sprintf(logBuff, "Warning: section [%s] option %s, some values not in IP/Mask form, option ignored", sectionName, raw);
						logDHCPMessage(logBuff, 1);
						continue;
					}

					if (opTag == DHCP_OPTION_NETMASK)
					{
						if (valSize != 4 || !checkMask(fIP(value)))
						{
							sprintf(logBuff, "Warning: section [%s] Invalid subnetmask %s, option ignored", sectionName, raw);
							logDHCPMessage(logBuff, 1);
							continue;
						}
						else
							optionData->mask = fIP(value);
					}

					if (buffsize > valSize + 2)
					{
						*dp = opTag;
						dp++;
						*dp = valSize;
						dp++;
						memcpy(dp, value, valSize);
						dp += valSize;
						buffsize -= (valSize + 2);
					}
					else
					{
						sprintf(logBuff, "Warning: section [%s] option %s, no more space for options", sectionName, raw);
						logDHCPMessage(logBuff, 1);
					}
				}
				else
				{
					sprintf(logBuff, "Warning: section [%s] option %s, Invalid value, should be one or more IP/4 Bytes", sectionName, raw);
					logDHCPMessage(logBuff, 1);
				}
			}
			break;

			case 4:
			{
				_DWord j;

				if (valType == 2 && valSize == 4)
					j = fULong(value);
				else if (valType >= 4 && valType <= 6)
					j = atol(value);
				else
				{
					sprintf(logBuff, "Warning: section [%s] option %s, value should be integer between 0 & %u or 4 bytes, option ignored", sectionName, name, UINT_MAX);
					logDHCPMessage(logBuff, 1);
					continue;
				}

				if (opTag == DHCP_OPTION_IPADDRLEASE)
				{
					if (j == 0)
						j = UINT_MAX;

					if (!strcasecmp(sectionName, GLOBALOPTIONS))
					{
						sprintf(logBuff, "Warning: section [%s] option %s not allowed in this section, please set it in [TIMINGS] section", sectionName, raw);
						logDHCPMessage(logBuff, 1);
						continue;
					}
					else if (j < config.lease)
					{
						sprintf(logBuff, "Warning: section [%s] option %s value should be more then %u (Default Lease), ignored", sectionName, name, config.lease);
						logDHCPMessage(logBuff, 1);
						continue;
					}
				}

				if (buffsize > 6)
				{
					*dp = opTag;
					dp++;
					*dp = 4;
					dp++;
					dp += pULong(dp, j);
					buffsize -= 6;
					//printf("%s=%u=%u\n",opData[op_index].opName,opData[op_index].opType,htonl(j));
				}
				else
				{
					sprintf(logBuff, "Warning: section [%s] option %s, no more space for options", sectionName, raw);
					logDHCPMessage(logBuff, 1);
				}
			}
			break;

			case 5:
			{
				_Word j;

				if (valType == 2 && valSize == 2)
					j = fUShort(value);
				else if (valType == 5 || valType == 6)
					j = atol(value);
				else
				{
					sprintf(logBuff, "Warning: section [%s] option %s, value should be between 0 & %u or 2 bytes, option ignored", sectionName, name, USHRT_MAX);
					logDHCPMessage(logBuff, 1);
					continue;
				}

				if (buffsize > 4)
				{
					*dp = opTag;
					dp++;
					*dp = 2;
					dp++;
					dp += pUShort(dp, j);
					buffsize -= 4;
				}
				else
				{
					sprintf(logBuff, "Warning: section [%s] option %s, no more space for options", sectionName, raw);
					logDHCPMessage(logBuff, 1);
				}
			}
			break;

			case 6:
			{
				_Byte j;

				if (valType == 2 && valSize == 1)
					j = *value;
				else if (valType == 6)
					j = atol(value);
				else
				{
					sprintf(logBuff, "Warning: section [%s] option %s, value should be between 0 & %u or single byte, option ignored", sectionName, name, UCHAR_MAX);
					logDHCPMessage(logBuff, 1);
					continue;
				}

				if (buffsize > 3)
				{
					*dp = opTag;
					dp++;
					*dp = 1;
					dp++;
					*dp = j;
					dp++;
					buffsize -= 3;
				}
				else
				{
					sprintf(logBuff, "Warning: section [%s] option %s, no more space for options", sectionName, raw);
					logDHCPMessage(logBuff, 1);
				}
			}
			break;

			case 7:
			{
				_Byte j;

				if (valType == 2 && valSize == 1 && *value < 2)
					j = *value;
				else if (valType == 1 && (!strcasecmp(value, "yes") || !strcasecmp(value, "on") || !strcasecmp(value, "true")))
					j = 1;
				else if (valType == 1 && (!strcasecmp(value, "no") || !strcasecmp(value, "off") || !strcasecmp(value, "false")))
					j = 0;
				else if (valType == 6 && atoi(value) < 2)
					j = atoi(value);
				else
				{
					sprintf(logBuff, "Warning: section [%s] option %s, value should be yes/on/true/1 or no/off/false/0, option ignored", sectionName, raw);
					logDHCPMessage(logBuff, 1);
					continue;
				}

				if (buffsize > 3)
				{
					*dp = opTag;
					dp++;
					*dp = 1;
					dp++;
					*dp = j;
					dp++;
					buffsize -= 3;
				}
				else
				{
					sprintf(logBuff, "Warning: section [%s] option %s, no more space for options", sectionName, raw);
					logDHCPMessage(logBuff, 1);
				}
			}
			break;

			default:
			{
				if (valType == 6)
				{
					valType = 2;
					valSize = 1;
					*value = atoi(value);
				}

				if (opType == 2 && valType != 2)
				{
					sprintf(logBuff, "Warning: section [%s] option %s, value should be comma separated bytes or hex string, option ignored", sectionName, raw);
					logDHCPMessage(logBuff, 1);
					continue;
				}
				else if (buffsize > valSize + 2)
				{
					*dp = opTag;
					dp++;
					*dp = valSize;
					dp++;
					memcpy(dp, value, valSize);
					dp += valSize;
					buffsize -= (valSize + 2);
				}
				else
				{
					sprintf(logBuff, "Warning: section [%s] option %s, no more space for options", sectionName, raw);
					logDHCPMessage(logBuff, 1);
				}
			}
			break;
		}

		//printf("%s Option=%u opType=%u valType=%u  valSize=%u\n", raw, opTag, opType, valType, valSize);
		//printf("%s %s\n", name, hex2String(tempbuff, ddp, valSize+2, ':'));
	}

	//printf("%s=%s\n", sectionName, optionData->vendClass);

	*dp = DHCP_OPTION_END;
	dp++;
	optionData->optionSize = (dp - optionData->options);
	//printf("section=%s buffersize = %u option size=%u\n", sectionName, buffsize, optionData->optionSize);
}

void lockOptions(FILE *f)
{
	char raw[512];
	char name[512];
	char value[512];

	while (readSection(raw, f))
	{
		mySplit(name, value, raw, '=');

		if (!name[0] || !value[0])
			continue;

		int op_index;
		_Byte n = sizeof(opData) / sizeof(data4);

		for (op_index = 0; op_index < n; op_index++)
			if (!strcasecmp(name, opData[op_index].opName) || (opData[op_index].opTag && atoi(name) == opData[op_index].opTag))
				break;

		if (op_index >= n)
			continue;

		if (opData[op_index].opType == 3)
		{
			if (myTokenize(value, value, "/,.", true))
			{
				char *ptr = value;
				char hoption[256];
				_Byte valueSize = 0;

				for (; *ptr; ptr = myGetToken(ptr, 1))
				{
					if (valueSize >= UCHAR_MAX)
						break;
					else if (isInt(ptr) && atoi(ptr) <= UCHAR_MAX)
					{
						hoption[valueSize] = atoi(ptr);
						valueSize++;
					}
					else
						break;
				}

				if (*ptr)
					continue;

				if (valueSize % 4)
					continue;

				for (_Byte i = 0; i < valueSize; i += 4)
				{
					_DWord ip = *((_DWord*)&(hoption[i]));

					if (ip != INADDR_ANY && ip != INADDR_NONE)
						lockIP(ip);
				}
			}
		}
	}
}

void addDHCPRange(char *dp)
{
	char logBuff[512];
	_DWord rs = 0;
	_DWord re = 0;
	char name[512];
	char value[512];
	mySplit(name, value, dp, '-');

	if (isIP(name) && isIP(value))
	{
		rs = htonl(inet_addr(name));
		re = htonl(inet_addr(value));

		if (rs && re && rs <= re)
		{
			DHCPRange *range;
			_Byte m = 0;

			for (; m < MAX_DHCP_RANGES && config.dhcpRanges[m].rangeStart; m++)
			{
				range = &config.dhcpRanges[m];

				if ((rs >= range->rangeStart && rs <= range->rangeEnd)
						|| (re >= range->rangeStart && re <= range->rangeEnd)
						|| (range->rangeStart >= rs && range->rangeStart <= re)
						|| (range->rangeEnd >= rs && range->rangeEnd <= re))
				{
					sprintf(logBuff, "Warning: DHCP Range %s overlaps with another range, ignored", dp);
					logDHCPMessage(logBuff, 1);
					return;
				}
			}

			if (m < MAX_DHCP_RANGES)
			{
				config.dhcpSize += (re - rs + 1);
				range = &config.dhcpRanges[m];
				range->rangeStart = rs;
				range->rangeEnd = re;
				range->expiry = (time_t*)calloc((re - rs + 1), sizeof(time_t));
				range->dhcpEntry = (CachedData**)calloc((re - rs + 1), sizeof(CachedData*));

				if (!range->expiry || !range->dhcpEntry)
				{
					if (range->expiry)
						free(range->expiry);

					if (range->dhcpEntry)
						free(range->dhcpEntry);

					sprintf(logBuff, "DHCP Ranges Load, Memory Allocation Error");
					logDHCPMessage(logBuff, 1);
					return;
				}
			}
		}
		else
		{
			sprintf(logBuff, "Section [%s] Invalid DHCP range %s in ini file, ignored", RANGESET, dp);
			logDHCPMessage(logBuff, 1);
		}
	}
	else
	{
		sprintf(logBuff, "Section [%s] Invalid DHCP range %s in ini file, ignored", RANGESET, dp);
		logDHCPMessage(logBuff, 1);
	}
}

void addVendClass(_Byte rangeSetInd, char *vendClass, _Byte vendClassSize)
{
	char logBuff[512];
	RangeSet *rangeSet = &config.rangeSet[rangeSetInd];

	_Byte i = 0;

	for (; i <= MAX_RANGE_FILTERS && rangeSet->vendClassSize[i]; i++);

	if (i >= MAX_RANGE_FILTERS || !vendClassSize)
		return;

	rangeSet->vendClass[i] = (_Byte*)calloc(vendClassSize, 1);

	if(!rangeSet->vendClass[i])
	{
		sprintf(logBuff, "Vendor Class Load, Memory Allocation Error");
		logDHCPMessage(logBuff, 1);
	}
	else
	{
		config.hasFilter = true;
		rangeSet->vendClassSize[i] = vendClassSize;
		memcpy(rangeSet->vendClass[i], vendClass, vendClassSize);
		//printf("Loaded Vendor Class %s Size=%i rangeSetInd=%i Ind=%i\n", rangeSet->vendClass[i], rangeSet->vendClassSize[i], rangeSetInd, i);
		//printf("Loaded Vendor Class %s Size=%i rangeSetInd=%i Ind=%i\n", hex2String(tempbuff, rangeSet->vendClass[i], rangeSet->vendClassSize[i], ':'), rangeSet->vendClassSize[i], rangeSetInd, i);
	}
}

void addUserClass(_Byte rangeSetInd, char *userClass, _Byte userClassSize)
{
	char logBuff[512];
	RangeSet *rangeSet = &config.rangeSet[rangeSetInd];

	_Byte i = 0;

	for (; i <= MAX_RANGE_FILTERS && rangeSet->userClassSize[i]; i++);

	if (i >= MAX_RANGE_FILTERS || !userClassSize)
		return;

	rangeSet->userClass[i] = (_Byte*)calloc(userClassSize, 1);

	if(!rangeSet->userClass[i])
	{
		sprintf(logBuff, "Vendor Class Load, Memory Allocation Error");
		logDHCPMessage(logBuff, 1);
	}
	else
	{
		config.hasFilter = true;
		rangeSet->userClassSize[i] = userClassSize;
		memcpy(rangeSet->userClass[i], userClass, userClassSize);
		//printf("Loaded User Class %s Size=%i rangeSetInd=%i Ind=%i\n", hex2String(tempbuff, rangeSet->userClass[i], rangeSet->userClassSize[i], ':'), rangeSet->vendClassSize[i], rangeSetInd, i);
	}
}

void addMacRange(_Byte rangeSetInd, char *macRange)
{
	char logBuff[512];

	if (macRange[0])
	{
		RangeSet *rangeSet = &config.rangeSet[rangeSetInd];

		_Byte i = 0;

		for (; i <= MAX_RANGE_FILTERS && rangeSet->macSize[i]; i++);

		if (i >= MAX_RANGE_FILTERS)
			return;

		char name[256];
		char value[256];

		mySplit(name, value, macRange, '-');

		//printf("%s=%s\n", name, value);

		if(!name[0] || !value[0])
		{
			sprintf(logBuff, "Section [%s], invalid Filter_Mac_Range %s, ignored", RANGESET, macRange);
			logDHCPMessage(logBuff, 1);
		}
		else
		{
			_Byte macSize1 = 16;
			_Byte macSize2 = 16;
			_Byte *macStart = (_Byte*)calloc(1, macSize1);
			_Byte *macEnd = (_Byte*)calloc(1, macSize2);

			if(!macStart || !macEnd)
			{
				sprintf(logBuff, "DHCP Range Load, Memory Allocation Error");
				logDHCPMessage(logBuff, 1);
			}
			else if (getHexValue(macStart, name, &macSize1) || getHexValue(macEnd, value, &macSize2))
			{
				sprintf(logBuff, "Section [%s], Invalid character in Filter_Mac_Range %s", RANGESET, macRange);
				logDHCPMessage(logBuff, 1);
				free(macStart);
				free(macEnd);
			}
			else if (memcmp(macStart, macEnd, 16) > 0)
			{
				sprintf(logBuff, "Section [%s], Invalid Filter_Mac_Range %s, (higher bound specified on left), ignored", RANGESET, macRange);
				logDHCPMessage(logBuff, 1);
				free(macStart);
				free(macEnd);
			}
			else if (macSize1 != macSize2)
			{
				sprintf(logBuff, "Section [%s], Invalid Filter_Mac_Range %s, (start/end size mismatched), ignored", RANGESET, macRange);
				logDHCPMessage(logBuff, 1);
				free(macStart);
				free(macEnd);
			}
			else
			{
				config.hasFilter = true;
				rangeSet->macSize[i] = macSize1;
				rangeSet->macStart[i] = macStart;
				rangeSet->macEnd[i] = macEnd;
				//printf("Mac Loaded, Size=%i Start=%s rangeSetInd=%i Ind=%i\n", rangeSet->macSize[i], hex2String(tempbuff, rangeSet->macStart[i], rangeSet->macSize[i]), rangeSetInd, i);
			}
		}
	}
}

void loadDHCP()
{
	char ipbuff[32];
	char logBuff[512];
	CachedData *dhcpEntry = NULL;
	char mapname[64];
	FILE *f = NULL;
	FILE *ff = NULL;

	if (f = openSection(GLOBALOPTIONS, 1))
	{
		OptionData optionData;
		loadOptions(f, GLOBALOPTIONS, &optionData);
		config.options = (_Byte*)calloc(1, optionData.optionSize);
		memcpy(config.options, optionData.options, optionData.optionSize);
		config.mask = optionData.mask;
	}

	if (!config.mask)
		config.mask = inet_addr("255.255.255.0");

	for (_Byte i = 1; i <= MAX_RANGE_SETS ; i++)
	{
		if (f = openSection(RANGESET, i))
		{
			_Byte m = config.rangeCount;
			OptionData optionData;
			optionData.rangeSetInd = i - 1;
			loadOptions(f, RANGESET, &optionData);
			_Byte *options = NULL;
			config.rangeSet[optionData.rangeSetInd].active = true;

			if (optionData.optionSize > 3)
			{
				options = (_Byte*)calloc(1, optionData.optionSize);
				memcpy(options, optionData.options, optionData.optionSize);
			}

			for (; m < MAX_DHCP_RANGES && config.dhcpRanges[m].rangeStart; m++)
			{
				config.dhcpRanges[m].rangeSetInd = optionData.rangeSetInd;
				config.dhcpRanges[m].options = options;
				config.dhcpRanges[m].mask = optionData.mask;
			}
			config.rangeCount = m;
		}
		else
			break;
	}

	//printf("%s\n", IP2String(ipbuff, config.mask));

	for (char rangeInd = 0; rangeInd < config.rangeCount; rangeInd++)
	{
		if (!config.dhcpRanges[rangeInd].mask)
			config.dhcpRanges[rangeInd].mask = config.mask;

		for (_DWord iip = config.dhcpRanges[rangeInd].rangeStart; iip <= config.dhcpRanges[rangeInd].rangeEnd; iip++)
		{
			_DWord ip = htonl(iip);

			if ((config.dhcpRanges[rangeInd].mask | (~ip)) == UINT_MAX || (config.dhcpRanges[rangeInd].mask | ip) == UINT_MAX)
				config.dhcpRanges[rangeInd].expiry[iip - config.dhcpRanges[rangeInd].rangeStart] = INT_MAX;
		}
	}

	if (f = openSection(GLOBALOPTIONS, 1))
		lockOptions(f);

	for (_Byte i = 1; i <= MAX_RANGE_SETS ;i++)
	{
		if (f = openSection(RANGESET, i))
			lockOptions(f);
		else
			break;
	}

	ff = fopen(iniFile, "rt");

	if (ff)
	{
		char sectionName[512];

		while (fgets(sectionName, 510, ff))
		{
			if (*sectionName == '[')
			{
				char *secend = strchr(sectionName, ']');

				if (secend)
				{
					*secend = 0;
					sectionName[0] = NBSP;
					myTrim(sectionName, sectionName);
				}
				else
					continue;
			}
			else
				continue;

			if (!strchr(sectionName, ':'))
				continue;

			//printf("%s\n", sectionName);

			_Byte hexValue[UCHAR_MAX];
			_Byte hexValueSize = sizeof(hexValue);
			OptionData optionData;

			if (strlen(sectionName) <= 48 && !getHexValue(hexValue, sectionName, &hexValueSize))
			{
				if (hexValueSize <= 16)
				{
					dhcpEntry = findDHCPEntry(hex2String(mapname, hexValue, hexValueSize));

					if (!dhcpEntry)
					{
						if (f = openSection(sectionName, 1))
							loadOptions(f, sectionName, &optionData);
						if (f = openSection(sectionName, 1))
							lockOptions(f);

						dhcpMap::iterator p = dhcpCache.begin();

						for (; p != dhcpCache.end(); p++)
						{
							if (p->second && p->second->ip && p->second->ip == optionData.ip)
								break;
						}

						if (p == dhcpCache.end())
						{
							memset(&lump, 0, sizeof(Lump));
							lump.cType = CTYPE_DHCP_ENTRY;
							lump.mapname = mapname;
							lump.optionSize = optionData.optionSize;
							lump.options = optionData.options;
							dhcpEntry = createCache(&lump);

							if (!dhcpEntry)
								return;
/*
							dhcpEntry = (CachedData*)calloc(1, sizeof(CachedData));

							if (!dhcpEntry)
							{
								sprintf(logBuff, "Host Options Load, Memory Allocation Error");
								logDHCPMessage(logBuff, 1);
								return;
							}

							dhcpEntry->mapname = cloneString(mapname);

							if (!dhcpEntry->mapname)
							{
								sprintf(logBuff, "Host Data Load, Memory Allocation Error");
								logDHCPMessage(logBuff, 1);
								return;
							}
*/
							dhcpEntry->ip = optionData.ip;
							dhcpEntry->rangeInd = getRangeInd(optionData.ip);
							dhcpEntry->fixed = 1;
							lockIP(optionData.ip);
							dhcpCache[dhcpEntry->mapname] = dhcpEntry;
							//printf("%s=%s=%s size=%u %u\n", mapname, dhcpEntry->mapname, IP2String(ipbuff, optionData.ip), optionData.optionSize, dhcpEntry->options);
						}
						else
						{
							sprintf(logBuff, "Static DHCP Host [%s] Duplicate IP Address %s, Entry ignored", sectionName, IP2String(ipbuff, optionData.ip));
							logDHCPMessage(logBuff, 1);
						}
					}
					else
					{
						sprintf(logBuff, "Duplicate Static DHCP Host [%s] ignored", sectionName);
						logDHCPMessage(logBuff, 1);
					}
				}
				else
				{
					sprintf(logBuff, "Invalid Static DHCP Host MAC Addr size, ignored", sectionName);
					logDHCPMessage(logBuff, 1);
				}
			}
			else
			{
				sprintf(logBuff, "Invalid Static DHCP Host MAC Addr [%s] ignored", sectionName);
				logDHCPMessage(logBuff, 1);
			}

			if (!optionData.ip)
			{
				sprintf(logBuff, "Warning: No IP Address for DHCP Static Host %s specified", sectionName);
				logDHCPMessage(logBuff, 1);
			}
		}

		fclose(ff);
	}

	ff = fopen(leaFile, "rb");

	if (ff)
	{
		DHCPClient dhcpData;

		while (fread(&dhcpData, sizeof(DHCPClient), 1, ff))
		{
			char rangeInd = -1;
			int ind = -1;

			//printf("Loading %s=%s\n", dhcpData.hostname, IP2String(ipbuff, dhcpData.ip));

			if (dhcpData.bp_hlen <= 16 && !findServer(network.allServers, MAX_SERVERS, dhcpData.ip))
			{
				hex2String(mapname, dhcpData.bp_chaddr, dhcpData.bp_hlen);

				dhcpMap::iterator p = dhcpCache.begin();

				for (; p != dhcpCache.end(); p++)
				{
					dhcpEntry = p->second;

					if (dhcpEntry && (!strcasecmp(mapname, dhcpEntry->mapname) || dhcpEntry->ip == dhcpData.ip))
						break;
				}

				if (p != dhcpCache.end() && (strcasecmp(mapname, dhcpEntry->mapname) || dhcpEntry->ip != dhcpData.ip))
					continue;

				dhcpEntry = findDHCPEntry(mapname);
				rangeInd = getRangeInd(dhcpData.ip);

				if(!dhcpEntry && rangeInd >= 0)
				{
					memset(&lump, 0, sizeof(Lump));
					lump.cType = CTYPE_DHCP_ENTRY;
					lump.mapname = mapname;
					dhcpEntry = createCache(&lump);
/*
					dhcpEntry = (CachedData*)calloc(1, sizeof(CachedData));

					if (!dhcpEntry)
					{
						sprintf(logBuff, "Loading Existing Leases, Memory Allocation Error");
						logDHCPMessage(logBuff, 1);
						return;
					}

					dhcpEntry->mapname = cloneString(mapname);

					if (!dhcpEntry->mapname)
					{
						sprintf(logBuff, "Loading Existing Leases, Memory Allocation Error");
						free(dhcpEntry);
						logDHCPMessage(logBuff, 1);
						return;
					}
*/
				}

				if (dhcpEntry)
				{
					dhcpCache[dhcpEntry->mapname] = dhcpEntry;
					dhcpEntry->ip = dhcpData.ip;
					dhcpEntry->rangeInd = rangeInd;
					dhcpEntry->expiry = dhcpData.expiry;
					dhcpEntry->local = dhcpData.local;
					dhcpEntry->display = true;

					if (dhcpData.hostname[0])
						dhcpEntry->hostname = cloneString(dhcpData.hostname);

					setLeaseExpiry(dhcpEntry);

					if (DNSService && dhcpData.hostname[0] && config.replication != 2 && dhcpData.expiry > t)
					{
						if (isLocal(dhcpEntry->ip))
							add2Cache(dhcpData.hostname, dhcpEntry->ip, dhcpData.expiry, CTYPE_LOCAL_A, CTYPE_LOCAL_PTR_AUTH);
						else
							add2Cache(dhcpData.hostname, dhcpEntry->ip, dhcpData.expiry, CTYPE_LOCAL_A, CTYPE_LOCAL_PTR_NAUTH);
					}
					//printf("Loaded %s=%s\n", dhcpData.hostname, IP2String(ipbuff, dhcpData.ip));
				}
			}
		}

		fclose(ff);

		ff = fopen(leaFile, "wb");
		config.dhcpInd = 0;

		if (ff)
		{
			dhcpMap::iterator p = dhcpCache.begin();

			for (; p != dhcpCache.end(); p++)
			{
				if ((dhcpEntry = p->second) && (dhcpEntry->expiry > t || !dhcpEntry->fixed))
				{
					memset(&dhcpData, 0, sizeof(DHCPClient));
					dhcpData.bp_hlen = 16;
					getHexValue(dhcpData.bp_chaddr, dhcpEntry->mapname, &dhcpData.bp_hlen);
					dhcpData.ip = dhcpEntry->ip;
					dhcpData.expiry = dhcpEntry->expiry;
					dhcpData.local = dhcpEntry->local;

					if (dhcpEntry->hostname)
						strcpy(dhcpData.hostname, dhcpEntry->hostname);

					config.dhcpInd++;
					dhcpData.dhcpInd = config.dhcpInd;
					dhcpEntry->dhcpInd = config.dhcpInd;
					fwrite(&dhcpData, sizeof(DHCPClient), 1, ff);
				}
			}
			fclose(ff);
		}
	}
}

bool getSection(const char *sectionName, char *buffer, _Byte serial, char *fileName)
{
	//printf("%s=%s\n",fileName,sectionName);
	char section[128];
	sprintf(section, "[%s]", sectionName);
	myUpper(section);
	FILE *f = fopen(fileName, "rt");
	char buff[512];
	_Byte found = 0;

	if (f)
	{
		while (fgets(buff, 511, f))
		{
			myUpper(buff);
			myTrim(buff, buff);

			if (strstr(buff, section) == buff)
			{
				found++;
				if (found == serial)
				{
					//printf("%s=%s\n",fileName,sectionName);
					while (fgets(buff, 511, f))
					{
						myTrim(buff, buff);

						if (strstr(buff, "[") == buff)
							break;

						if ((*buff) >= '0' && (*buff) <= '9' || (*buff) >= 'A' && (*buff) <= 'Z' || (*buff) >= 'a' && (*buff) <= 'z' || ((*buff) && strchr("/\\?*", (*buff))))
						{
							buffer += sprintf(buffer, "%s", buff);
							buffer++;
						}
					}
					break;
				}
			}
		}
		fclose(f);
	}

	*buffer = 0;
	*(buffer + 1) = 0;
	return (found == serial);
}

FILE *openSection(const char *sectionName, _Byte serial)
{
	char logBuff[512];
	char tempbuff[512];
	char section[128];
	sprintf(section, "[%s]", sectionName);
	myUpper(section);
	FILE *f = NULL;
	f = fopen(iniFile, "rt");

	if (f)
	{
		//printf("opened %s=%d\n", tempbuff, f);
		char buff[512];
		_Byte found = 0;

		while (fgets(buff, 511, f))
		{
			myUpper(buff);
			myTrim(buff, buff);

			if (strstr(buff, section) == buff)
			{
				found++;

				if (found == serial)
				{
					_DWord fpos = ftell(f);

					if (fgets(buff, 511, f))
					{
						myTrim(buff, buff);

						if (buff[0] == '@')
						{
							fclose(f);
							f = NULL;

							buff[0] = NBSP;
							myTrim(buff, buff);

							if (strchr(buff, '\\') || strchr(buff, '/'))
								strcpy(tempbuff, buff);
							else
								sprintf(tempbuff, "%s%s", filePATH, buff);

							f = fopen(tempbuff, "rt");

							if (f)
								return f;
							else
							{
								sprintf(logBuff, "Error: Section [%s], file %s not found", sectionName, tempbuff);
								logMessage(logBuff, 1);
								return NULL;
							}
						}
						else
						{
							fseek(f, fpos, SEEK_SET);
							return f;
						}
					}
				}
			}
		}
		fclose(f);
	}
	return NULL;
}

char *readSection(char* buff, FILE *f)
{
	while (fgets(buff, 511, f))
	{
		myTrim(buff, buff);

		if (*buff == '[')
			break;

		if ((*buff) >= '0' && (*buff) <= '9' || (*buff) >= 'A' && (*buff) <= 'Z' || (*buff) >= 'a' && (*buff) <= 'z' || ((*buff) && strchr("/\\?*", (*buff))))
			return buff;
	}

	fclose(f);
	return NULL;
}

char* myGetToken(char* buff, _Byte index)
{
	while (*buff)
	{
		if (index)
			index--;
		else
			break;

		buff += strlen(buff) + 1;
	}

	return buff;
}

_Word myTokenize(char *target, char *source, const char *sep, bool whiteSep)
{
	bool found = true;
	char *dp = target;
	_Word kount = 0;

	while (*source)
	{
		if (sep && sep[0] && strchr(sep, (*source)))
		{
			found = true;
			source++;
			continue;
		}
		else if (whiteSep && (*source) <= NBSP)
		{
			found = true;
			source++;
			continue;
		}

		if (found)
		{
			if (target != dp)
			{
				*dp = 0;
				dp++;
			}
			kount++;
		}

		found = false;
		*dp = *source;
		dp++;
		source++;
	}

	*dp = 0;
	dp++;
	*dp = 0;

	//printf("%s\n", target);

	return kount;
}

char* myTrim(char *target, char *source)
{
	while ((*source) && (*source) <= NBSP)
		source++;

	int i = 0;

	for (; i < 511 && source[i]; i++)
		target[i] = source[i];

	target[i] = source[i];
	i--;

	for (; i >= 0 && target[i] <= NBSP; i--)
		target[i] = 0;

	return target;
}

void mySplit(char *name, char *value, char *source, char splitChar)
{
	int i = 0;
	int j = 0;
	int k = 0;

	for (; source[i] && j <= 510 && source[i] != splitChar; i++, j++)
	{
		name[j] = source[i];
	}

	if (source[i])
	{
		i++;
		for (; k <= 510 && source[i]; i++, k++)
		{
			value[k] = source[i];
		}
	}

	name[j] = 0;
	value[k] = 0;

	myTrim(name, name);
	myTrim(value, value);
	//printf("%s %s\n", name, value);
}

char *strquery(DNSRequest *req)
{
	strcpy(req->extbuff, req->query);

	switch (req->dnsType)
	{
		case 1:
			strcat(req->extbuff, " A");
			break;
		case 2:
			strcat(req->extbuff, " NS");
			break;
		case 3:
			strcat(req->extbuff, " MD");
			break;
		case 4:
			strcat(req->extbuff, " MF");
			break;
		case 5:
			strcat(req->extbuff, " CNAME");
			break;
		case 6:
			strcat(req->extbuff, " SOA");
			break;
		case 7:
			strcat(req->extbuff, " MB");
			break;
		case 8:
			strcat(req->extbuff, " MG");
			break;
		case 9:
			strcat(req->extbuff, " MR");
			break;
		case 10:
			strcat(req->extbuff, " NULL");
			break;
		case 11:
			strcat(req->extbuff, " WKS");
			break;
		case 12:
			strcat(req->extbuff, " PTR");
			break;
		case 13:
			strcat(req->extbuff, " HINFO");
			break;
		case 14:
			strcat(req->extbuff, " MINFO");
			break;
		case 15:
			strcat(req->extbuff, " MX");
			break;
		case 16:
			strcat(req->extbuff, " TXT");
			break;
		case 28:
			strcat(req->extbuff, " AAAA");
			break;
		case 251:
			strcat(req->extbuff, " IXFR");
			break;
		case 252:
			strcat(req->extbuff, " AXFR");
			break;
		case 253:
			strcat(req->extbuff, " MAILB");
			break;
		case 254:
			strcat(req->extbuff, " MAILA");
			break;
		case 255:
			strcat(req->extbuff, " ANY");
			break;
	}
	return req->extbuff;
}

_DWord getClassNetwork(_DWord ip)
{
	InternetAddress data;
	data.ip = ip;
	data.octate[3] = 0;

	if (data.octate[0] < 192)
		data.octate[2] = 0;

	if (data.octate[0] < 128)
		data.octate[1] = 0;

	return data.ip;
}

/*
char *IP2Auth(_DWord ip)
{
InternetAddress data;
data.ip = ip;

if (data.octate[0] >= 192)
sprintf(tempbuff, "%u.%u.%u", data.octate[2], data.octate[1], data.octate[0]);
else if (data.octate[0] >= 128)
sprintf(tempbuff, "%u.%u", data.octate[1], data.octate[0]);
else
sprintf(tempbuff, "%u", data.octate[0]);

strcat(tempbuff, arpa);
return tempbuff;
}
*/

char *IP2String(char *target, _DWord ip, _Byte dnsType)
{
	char *dp = target;
	(*dp) = dnsType;
	dp++;
	InternetAddress inaddr;
	inaddr.ip = ip;
	sprintf(dp, "%u.%u.%u.%u", inaddr.octate[0], inaddr.octate[1], inaddr.octate[2], inaddr.octate[3]);
	//_Byte *octate = (_Byte*)&ip;
	//sprintf(target, "%u.%u.%u.%u", octate[0], octate[1], octate[2], octate[3]);
	return target;
}

char *IP2String(char *target, _DWord ip)
{
	InternetAddress inaddr;
	inaddr.ip = ip;
	sprintf(target, "%u.%u.%u.%u", inaddr.octate[0], inaddr.octate[1], inaddr.octate[2], inaddr.octate[3]);
	//_Byte *octate = (_Byte*)&ip;
	//sprintf(target, "%u.%u.%u.%u", octate[0], octate[1], octate[2], octate[3]);
	return target;
}

_Byte addServer(_DWord *array, _Byte maxServers, _DWord ip)
{
	if (ip)
	{
		for (_Byte i = 0; i < maxServers; i++)
		{
			if (array[i] == ip)
				return i;
			else if (!array[i])
			{
				array[i] = ip;
				return i;
			}
		}
	}
	return maxServers;
}

_DWord *findServer(_DWord *array, _Byte maxServers, _DWord ip)
{
	if (ip)
	{
		for (_Byte i = 0; i < maxServers && array[i]; i++)
		{
			if (array[i] == ip)
				return &(array[i]);
		}
	}
	return NULL;
}

bool isInt(char *str)
{
	if (!str || !(*str))
		return false;

	for(; *str; str++)
		if (*str <  '0' || *str > '9')
			return false;

	return true;
}

bool isIP(char *str)
{
	if (!str || !(*str))
		return false;

	_DWord ip = inet_addr(str);

	if (ip == INADDR_NONE || ip == INADDR_ANY)
		return false;

	int j = 0;

	for (; *str; str++)
	{
		if (*str == '.' && *(str + 1) != '.')
			j++;
		else if (*str < '0' || *str > '9')
			return false;
	}

	if (j == 3)
		return true;
	else
		return false;
}

/*
char *toBase64(_Byte *source, _Byte length)
{
	_Byte a = 0, b = 0, i = 0;
	char *dp = tempbuff;

	for (; length; length--, source++)
	{
		i += 2;
		a = (*source) >> i;
		*dp = base64[a + b];
		dp++;
		b = (*source) << (8 - i);
		b >>= 2;
		if (i == 6)
		{
			*dp = base64[b];
			dp++;
			i = b = 0;
		}
	}
	if (i)
	{
		*dp = base64[b];
		dp++;
	}
	*dp = 0;
	//printf("%s\n",tempbuff);
	return tempbuff;
}

_Byte getBaseValue(_Byte a)
{
	if (a >= 'A' && a <= 'Z')
		a -= 'A';
	else if (a >= 'a' && a <= 'z')
		a = a - 'a' + 26;
	else if (a >= '0' && a <= '9')
		a = a - '0' + 52;
	else if (a == '+')
		a = 62;
	else if (a == '/')
		a = 63;
	else
		a = UCHAR_MAX;

	return a;
}

_Byte fromBase64(_Byte *target, char *source)
{
	//printf("SOURCE=%s\n", source);
	_Byte b = 0;
	_Byte shift = 4;
	_Byte bp_hlen = (3 * strlen(source))/4;
	*target = 0;

	if (*source)
	{
		b = getBaseValue(*source);
		*target = b << 2;
		source++;

		while (*source)
		{
			b = getBaseValue(*source);
			(*target) += (b >> (8 - shift));
			target++;
			(*target) = (b << shift);
			shift += 2;

			if (shift > 8)
			{
				source++;

				if (*source)
				{
					b = getBaseValue(*source);
					*target = b << 2;
					shift = 4;
				}
				else
					break;
			}

			source++;
		}
	}
	//printf("SIZE=%u\n", bp_hlen);
	return bp_hlen;
}

char *toUUE(char *tempbuff, _Byte *source, _Byte length)
{
	_Byte a = 0, b = 0, i = 0;
	char *dp = tempbuff;

	for (; length; length--, source++)
	{
		i += 2;
		a = (*source) >> i;
		*dp = a + b + NBSP;
		dp++;
		b = (*source) << (8 - i);
		b >>= 2;
		if (i == 6)
		{
			*dp = b + NBSP;
			dp++;
			i = b = 0;
		}
	}
	if (i)
	{
		*dp = b + NBSP;
		dp++;
	}
	*dp = 0;
	//printf("%s\n",tempbuff);
	return tempbuff;
}

_Byte fromUUE(_Byte *target, char *source)
{
	//printf("SOURCE=%s\n", source);
	_Byte b = 0;
	_Byte shift = 4;
	_Byte bp_hlen = (3 * strlen(source))/4;
	*target = 0;

	if (*source)
	{
		b = *source - NBSP;
		*target = b << 2;
		source++;

		while (*source)
		{
			b = *source - NBSP;
			(*target) += (b >> (8 - shift));
			target++;
			(*target) = (b << shift);
			shift += 2;

			if (shift > 8)
			{
				source++;

				if (*source)
				{
					b = *source - NBSP;
					*target = b << 2;
					shift = 4;
				}
				else
					break;
			}

			source++;
		}
	}
	//printf("SIZE=%u\n", bp_hlen);
	return bp_hlen;
}
*/
char *hex2String(char *target, _Byte *hex, _Byte bytes)
{
	char *dp = target;

	if (bytes)
		dp += sprintf(target, "%02x", *hex);
	else
		*target = 0;

	for (_Byte i = 1; i < bytes; i++)
			dp += sprintf(dp, ":%02x", *(hex + i));

	return target;
}

char *genHostName(char *target, _Byte *hex, _Byte bytes)
{
	char *dp = target;

	if (bytes)
		dp += sprintf(target, "Host%02x", *hex);
	else
		*target = 0;

	for (_Byte i = 1; i < bytes; i++)
			dp += sprintf(dp, "%02x", *(hex + i));

	return target;
}

/*
char *IP62String(char *target, _Byte *source)
{
	_Word *dw = (_Word*)source;
	char *dp = target;
	_Byte markbyte;

	for (markbyte = 4; markbyte > 0 && !dw[markbyte - 1]; markbyte--);

	for (_Byte i = 0; i < markbyte; i++)
		dp += sprintf(dp, "%x:", ntohs(dw[i]));

	for (markbyte = 4; markbyte < 8 && !dw[markbyte]; markbyte++);

	for (_Byte i = markbyte; i < 8; i++)
		dp += sprintf(dp, ":%x", htons(dw[i]));

	return target;
}
*/

char *IP62String(char *target, _Byte *source)
{
	char *dp = target;
	bool zerostarted = false;
	bool zeroended = false;

	for (_Byte i = 0; i < 16; i += 2, source += 2)
	{
		if (source[0])
		{
			if (zerostarted)
				zeroended = true;

			if (zerostarted && zeroended)
			{
				dp += sprintf(dp, "::");
				zerostarted = false;
			}
			else if (dp != target)
				dp += sprintf(dp, ":");

			dp += sprintf(dp, "%x", source[0]);
			dp += sprintf(dp, "%02x", source[1]);
		}
		else if (source[1])
		{
			if (zerostarted)
				zeroended = true;

			if (zerostarted && zeroended)
			{
				dp += sprintf(dp, "::");
				zerostarted = false;
			}
			else if (dp != target)
				dp += sprintf(dp, ":");

			dp += sprintf(dp, "%0x", source[1]);
		}
		else if (!zeroended)
			zerostarted = true;
	}

	return target;
}

char *getHexValue(_Byte *target, char *source, _Byte *size)
{
	if (*size)
		memset(target, 0, (*size));

	for ((*size) = 0; (*source) && (*size) < UCHAR_MAX; (*size)++, target++)
	{
		if ((*source) >= '0' && (*source) <= '9')
		{
			(*target) = (*source) - '0';
		}
		else if ((*source) >= 'a' && (*source) <= 'f')
		{
			(*target) = (*source) - 'a' + 10;
		}
		else if ((*source) >= 'A' && (*source) <= 'F')
		{
			(*target) = (*source) - 'A' + 10;
		}
		else
		{
			return source;
		}

		source++;

		if ((*source) >= '0' && (*source) <= '9')
		{
			(*target) *= 16;
			(*target) += (*source) - '0';
		}
		else if ((*source) >= 'a' && (*source) <= 'f')
		{
			(*target) *= 16;
			(*target) += (*source) - 'a' + 10;
		}
		else if ((*source) >= 'A' && (*source) <= 'F')
		{
			(*target) *= 16;
			(*target) += (*source) - 'A' + 10;
		}
		else if ((*source) == ':' || (*source) == '-')
		{
			source++;
			continue;
		}
		else if (*source)
		{
			return source;
		}
		else
		{
			continue;
		}

		source++;

		if ((*source) == ':' || (*source) == '-')
		{
			source++;
		}
		else if (*source)
			return source;
	}

	if (*source)
		return source;

	//printf("macfucked in=%s\n", tSource);
	//printf("macfucked out=%s\n", hex2String(tempbuff, tTarget, *size));
	return NULL;
}

char *myUpper(char *string)
{
	char diff = 'a' - 'A';
	_Word len = strlen(string);
	for (int i = 0; i < len; i++)
		if (string[i] >= 'a' && string[i] <= 'z')
			string[i] -= diff;
	return string;
}

char *myLower(char *string)
{
	char diff = 'a' - 'A';
	_Word len = strlen(string);
	for (int i = 0; i < len; i++)
		if (string[i] >= 'A' && string[i] <= 'Z')
			string[i] += diff;
	return string;
}

bool wildcmp(char *string, char *wild)
{
	// Written by Jack Handy - jakkhandy@hotmail.com
	// slightly modified
	char *cp = NULL;
	char *mp = NULL;

	while ((*string) && (*wild != '*'))
	{
		if ((*wild != *string) && (*wild != '?'))
		{
			return 0;
		}
		wild++;
		string++;
	}

	while (*string)
	{
		if (*wild == '*')
		{
			if (!*++wild)
				return 1;

			mp = wild;
			cp = string + 1;
		}
		else if ((*wild == *string) || (*wild == '?'))
		{
			wild++;
			string++;
		}
		else
		{
			wild = mp;
			string = cp++;
		}
	}

	while (*wild == '*')
		wild++;

	return !(*wild);
}

bool isLocal(_DWord ip)
{
	if (config.rangeStart && htonl(ip) >= config.rangeStart && htonl(ip) <= config.rangeEnd)
		return true;
//	else if (getRangeInd(ip) >= 0)
//		return true;
	else
		return false;
}

char *setMapName(char *tempbuff, char *mapname, _Byte dnsType)
{
	char *dp = tempbuff;
	(*dp) = dnsType;
	dp++;
	strcpy(dp, mapname);
	myLower(dp);
	return tempbuff;
}

_Byte makeLocal(char *mapname)
{
	if (!strcasecmp(mapname, config.zone))
	{
		mapname[0] = 0;
		return QTYPE_A_ZONE;
	}
	else if (!strcasecmp(mapname, config.authority))
	{
		//char *dp = strstr(mapname, arpa);
		//(*dp) = 0;
		return QTYPE_P_ZONE;
	}
	else if (char *dp = strchr(mapname, '.'))
	{
		if (!strcasecmp(dp + 1, config.zone))
		{
			*dp = 0;
			return QTYPE_A_LOCAL;
		}
		else if (dp = strstr(mapname, arpa))
		{
			if (strstr(mapname, config.authority))
			{
				*dp = 0;
				return QTYPE_P_LOCAL;
			}
			else
			{
				*dp = 0;
				return QTYPE_P_EXT;
			}
		}
		else if (strstr(mapname, ip6arpa))
			return QTYPE_P_EXT;
		else
			return QTYPE_A_EXT;
	}
	else
		return QTYPE_A_BARE;
}

void listCache()
{
	char ipbuff[32];
	char logBuff[512];
	hostMap::iterator p = dnsCache[currentInd].begin();
	CachedData *cache = NULL;

	while (p != dnsCache[currentInd].end())
	{
		cache = p->second;

		if (cache->hostname)
			sprintf(logBuff, "%s=%s", cache->mapname, cache->hostname);
		else
			sprintf(logBuff, "%s=%s", cache->mapname, IP2String(ipbuff, cache->ip));

		logDNSMessage(logBuff, 1);
		p++;
	}
}

void listDhcpCache()
{
	char logBuff[512];
	dhcpMap::iterator p = dhcpCache.begin();
	CachedData *cache = NULL;

	while (p != dhcpCache.end())
	{
		cache = p->second;
		sprintf(logBuff, cache->mapname);
		logDHCPMessage(logBuff, 1);
		p++;
	}
}

void checkSize()
{
	//listCache();
	//listDhcpCache();
	//printf("Start %u=%u\n",dnsCache[currentInd].size(),dnsAge[currentInd].size());
	//sprintf(logBuff, "Start Cache size %u=%u",dnsCache[currentInd].size(),dnsAge[currentInd].size());
	//debug(logBuff);

	CachedData *cache = NULL;
	expiryMap::iterator p;
	//_Byte maxDelete = 3;

	//while (p != dnsAge[currentInd].end() && p->first < t && maxDelete > 0)
	while (true)
	{
		p = dnsAge[currentInd].begin();

		if (p == dnsAge[currentInd].end())
			break;

		if (p->first > t)
			break;

		cache = p->second;
		//printf("processing %s=%i\n", cache->mapname, p->first - t);

		dnsAge[currentInd].erase(p);

		if (cache && cache->expiry > t)
		{
			dnsAge[currentInd].insert(pair<time_t, CachedData*>(cache->expiry, cache));
			//sprintf(logBuff, "Entry %s being advanced", cache->name);
			//logMessage(logBuff, 1);
		}
		else if (cache)
		{
			if (cache->cType == CTYPE_QUEUE && cache->expiry)
			{
				if (cache->dnsIndex < MAX_SERVERS)
				{
					if (network.currentDNS == cache->dnsIndex)
					{
						if (network.DNS[1])
						{
							network.currentDNS++;

							if (network.currentDNS >= MAX_SERVERS || !network.DNS[network.currentDNS])
								network.currentDNS = 0;
						}
					}
				}
				else if (cache->dnsIndex >= 128 && cache->dnsIndex < 192)
				{
					DNSRoute *dnsRoute = &config.dnsRoutes[(cache->dnsIndex - 128) / 2];
					_Byte currentDNS = cache->dnsIndex % 2;

					if (dnsRoute->currentDNS == currentDNS && dnsRoute->DNS[1])
						dnsRoute->currentDNS = 1 - dnsRoute->currentDNS;
				}
			}

			if (config.replication != 2)
			{
				if (cache->cType == CTYPE_LOCAL_A)
					config.serial1 = t;
				else if (cache->cType == CTYPE_LOCAL_PTR_AUTH)
					config.serial2 = t;
			}

			//sprintf(logBuff, "Data Type=%u Cache Size=%u, Age Size=%u, Entry %s being deleted", cache->cType, dnsCache[currentInd].size(), dnsAge[currentInd].size(), cache->name);
			//logMessage(logBuff, 1);
			delDnsEntry(cache);
			//maxDelete--;
		}
	}

	//sprintf(logBuff, "End Cache size %u=%u",dnsCache[currentInd].size(),dnsAge[currentInd].size());
	//debug(logBuff);

/*
	if (ind == currentInd && dhcpService)
	{
		//printf("dhcpAge=%u\n", dhcpAge.size());

		p = dhcpAge.begin();

		while (p != dhcpAge.end() && p->first < t)
		{
			cache = p->second;
			//printf("processing %s=%i\n", cache->mapname, p->first - t);

			if (cache->hanged && cache->expiry > t)
			{
				q = p;
				p++;
				dhcpAge.erase(q);
				dhcpAge.insert(pair<time_t, CachedData*>(cache->expiry, cache));
			}
			else
			{
				q = p;
				p++;
				dhcpAge.erase(q);

				if (cache->hanged && cache->expiry < t)
				{
					sendRepl(cache);
					printf("Lease released\n");
				}

				cache->hanged = false;
			}
		}
	}
*/
}

void delDnsEntry(CachedData* cache)
{
	hostMap::iterator r = dnsCache[currentInd].find(cache->mapname);

	for (; r != dnsCache[currentInd].end(); r++)
	{
		if (strcasecmp(r->second->mapname, cache->mapname))
			break;
		else if (r->second == cache)
		{
			//sprintf(logBuff, "cType=%u dnsType=%u Size=%u, Entry %s being deleted", cache->cType, cache->dnsType, dnsCache[currentInd].size(), cache->name);
			//debug(logBuff);
			dnsCache[currentInd].erase(r);
			free(cache);
			break;
		}
	}
}

void calcRangeLimits(_DWord ip, _DWord mask, _DWord *rangeStart, _DWord *rangeEnd)
{
	*rangeStart = htonl(ip & mask) + 1;
	*rangeEnd = htonl(ip | (~mask)) - 1;
}

bool checkMask(_DWord mask)
{
	mask = htonl(mask);

	while (mask)
	{
		if (mask < (mask << 1))
			return false;

		mask <<= 1;
	}
	return true;
}

_DWord calcMask(_DWord rangeStart, _DWord rangeEnd)
{
	InternetAddress ip1, ip2, mask;

	ip1.ip = htonl(rangeStart);
	ip2.ip = htonl(rangeEnd);

	for (_Byte i = 0; i < 4; i++)
	{
		mask.octate[i] = ip1.octate[i] ^ ip2.octate[i];

		if (i && mask.octate[i - 1] < 255)
			mask.octate[i] = 0;
		else if (mask.octate[i] == 0)
			mask.octate[i] = 255;
		else if (mask.octate[i] < 2)
			mask.octate[i] = 254;
		else if (mask.octate[i] < 4)
			mask.octate[i] = 252;
		else if (mask.octate[i] < 8)
			mask.octate[i] = 248;
		else if (mask.octate[i] < 16)
			mask.octate[i] = 240;
		else if (mask.octate[i] < 32)
			mask.octate[i] = 224;
		else if (mask.octate[i] < 64)
			mask.octate[i] = 192;
		else if (mask.octate[i] < 128)
			mask.octate[i] = 128;
		else
			mask.octate[i] = 0;
	}

	return mask.ip;
}

char *findHost(char *tempbuff, _DWord ip)
{
	IP2String(tempbuff, htonl(ip));
	CachedData *cache = findEntry(tempbuff, DNS_TYPE_PTR);

	if (cache)
		strcpy(tempbuff, cache->hostname);
	else
		tempbuff[0] = 0;

	return tempbuff;
}

CachedData *findEntry(char *key, _Byte dnsType, _Byte cType)
{
	char tempbuff[512];
	hostMap::iterator it = dnsCache[currentInd].find(setMapName(tempbuff, key, dnsType));

	while (it != dnsCache[currentInd].end() && it->second && !strcasecmp(it->second->mapname, tempbuff))
	{
		if (it->second->cType == cType)
			return it->second;
		else
			it++;
	}

	return NULL;
}

CachedData *findEntry(char *key, _Byte dnsType)
{
	char tempbuff[512];
	//printf("finding %u=%s\n",ind,key);
	hostMap::iterator it = dnsCache[currentInd].find(setMapName(tempbuff, key, dnsType));

	if (it != dnsCache[currentInd].end() && it->second)
		return it->second;

	return NULL;
}

CachedData *findQueue(char *key)
{
	//printf("finding %u=%s\n",ind,key);
	hostMap::iterator it = dnsCache[currentInd].find(key);

	if (it != dnsCache[currentInd].end() && it->second->cType == CTYPE_QUEUE)
		return it->second;

	return NULL;
}

CachedData *findDHCPEntry(char *key)
{
	//printf("finding %u=%s\n",ind,key);
	myLower(key);
	dhcpMap::iterator it = dhcpCache.find(key);

	if (it != dhcpCache.end() && it->second) {
		for (dhcpMap::iterator it2 = dhcpCache.begin(); it2 != dhcpCache.end();) {
			if (it2->second) {
				if (!strcmp(it2->second->hostname, it->second->hostname)) {
					if (!strcmp(it2->second->mapname, it->second->mapname)) {
						++it2;
					} else {
						dhcpCache.erase(it2++);
					}
				} else {
					++it2;
				}
			} else {
				++it2;
			}
		}
		return it->second;
	}

	return NULL;
}

void addEntry(CachedData *entry)
{
	myLower(entry->mapname);
	dnsCache[currentInd].insert(pair<string, CachedData*>(entry->mapname, entry));

	if (entry->expiry && entry->expiry < INT_MAX)
		dnsAge[currentInd].insert(pair<time_t, CachedData*>(entry->expiry, entry));
}

char *cloneString(char *string)
{
	char *s = (char*)calloc(1, strlen(string) + 1);

	if (s)
		strcpy(s, string);

	return s;
}


_DWord getSerial(char *zone)
{
	char tempbuff[512];
	char logBuff[512];
	char ipbuff[32];
	_DWord serial1 = 0;
	DNSRequest req;
	memset(&req, 0, sizeof(DNSRequest));
	req.remote.sin_family = AF_INET;
	req.remote.sin_port = htons(IPPORT_DNS);
	timeval tv1;
	fd_set readfds1;

	if (config.replication == 2)
		req.remote.sin_addr.s_addr = config.zoneServers[0];
	else
		req.remote.sin_addr.s_addr = config.zoneServers[1];

	req.sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	req.dnsPacket = (DNSPacket*)req.raw;
	req.dnsPacket->header.questionsCount = htons(1);
	req.dnsPacket->header.recursionDesired = false;
	req.dnsPacket->header.queryID = (t % USHRT_MAX);
	req.dp = &req.dnsPacket->data;
	req.dp += pQu(req.dp, zone);
	req.dp += pUShort(req.dp, DNS_TYPE_SOA);
	req.dp += pUShort(req.dp, DNS_CLASS_IN);
	req.bytes = req.dp - req.raw;
	//pUShort(req.raw, req.bytes - 2);

	if ((req.bytes = sendto(req.sock, req.raw, req.bytes, 0, (sockaddr*)&req.remote, sizeof(req.remote))) <= 0)
	{
		closesocket(req.sock);
		sprintf(logBuff, "Failed to send request to Primary Server %s", IP2String(ipbuff, req.remote.sin_addr.s_addr));
		logDNSMessage(logBuff, 1);
		return 0;
	}

	FD_ZERO(&readfds1);
	tv1.tv_sec = 3;
	tv1.tv_usec = 0;
	FD_SET(req.sock, &readfds1);
	select(USHRT_MAX, &readfds1, NULL, NULL, &tv1);

	if (FD_ISSET(req.sock, &readfds1))
	{
		req.sockLen = sizeof(req.remote);
		req.bytes = recvfrom(req.sock, req.raw, sizeof(req.raw), 0, (sockaddr*)&req.remote, &req.sockLen);

		if (req.bytes > 0 && !req.dnsPacket->header.responseCode && req.dnsPacket->header.responseFlag && ntohs(req.dnsPacket->header.answersCount))
		{
			req.dp = &req.dnsPacket->data;

			for (int j = 1; j <= ntohs(req.dnsPacket->header.questionsCount); j++)
			{
				req.dp += fQu(tempbuff, req.dnsPacket, req.dp);
				req.dp += 4;
			}

			for (int i = 1; i <= ntohs(req.dnsPacket->header.answersCount); i++)
			{
				req.dp += fQu(tempbuff, req.dnsPacket, req.dp);
				req.dnsType = fUShort(req.dp);
				req.dp += 2; //type
				req.qclass = fUShort(req.dp);
				req.dp += 2; //class
				fULong(req.dp);
				req.dp += 4; //ttl
				req.dp += 2; //datalength

				if (req.dnsType == DNS_TYPE_SOA)
				{
					req.dp += fQu(tempbuff, req.dnsPacket, req.dp);
					req.dp += fQu(tempbuff, req.dnsPacket, req.dp);
					serial1 = fULong(req.dp);
				}
			}
			closesocket(req.sock);
			return serial1;
		}
		else
		{
			closesocket(req.sock);
			//sprintf(logBuff, "Zone %s not found on Primary Server %s", zone, IP2String(ipbuff, req.remote.sin_addr.s_addr));
			//logDNSMessage(logBuff, 1);
			return 0;
		}
	}

	closesocket(req.sock);
	sprintf(logBuff, "Failed to contact the Primary Server %s", IP2String(ipbuff, req.remote.sin_addr.s_addr));
	logDNSMessage(logBuff, 1);
	return 0;
}

void sendServerName()
{
	errno = 0;
	DNSRequest req;
	memset(&req, 0, sizeof(DNSRequest));
	req.remote.sin_family = AF_INET;
	req.remote.sin_port = htons(IPPORT_DNS);
	req.remote.sin_addr.s_addr = config.zoneServers[0];

	timeval tv1;
	fd_set readfds1;

	req.sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	req.dnsPacket = (DNSPacket*)req.raw;
	req.dnsPacket->header.optionCode = OPCODE_DYNAMIC_UPDATE;
	req.dnsPacket->header.responseFlag = true;
	req.dnsPacket->header.zonesCount = htons(1);
	req.dnsPacket->header.prerequisitesCount = htons(1);
	req.dnsPacket->header.queryID = (t % USHRT_MAX);
	req.dp = &req.dnsPacket->data;
	req.dp += pQu(req.dp, config.zone);
	req.dp += pUShort(req.dp, DNS_TYPE_SOA);
	req.dp += pUShort(req.dp, DNS_CLASS_IN);
	req.dp += pQu(req.dp, config.servername_fqn);
	req.dp += pUShort(req.dp, DNS_TYPE_A);
	req.dp += pUShort(req.dp, DNS_CLASS_IN);
	req.dp += pULong(req.dp, 0);
	req.dp += pUShort(req.dp, 4);
	req.dp += pIP(req.dp, config.zoneServers[1]);
	req.bytes = req.dp - req.raw;
	//pUShort(req.raw, req.bytes - 2);

	if ((req.bytes = sendto(req.sock, req.raw, req.bytes, 0, (sockaddr*)&req.remote, sizeof(req.remote))) <= 0)
	{
		closesocket(req.sock);
	}

	FD_ZERO(&readfds1);
	tv1.tv_sec = 5;
	tv1.tv_usec = 0;
	FD_SET(req.sock, &readfds1);
	select(USHRT_MAX, &readfds1, NULL, NULL, &tv1);

	if (FD_ISSET(req.sock, &readfds1))
	{
		req.sockLen = sizeof(req.remote);
		req.bytes = recvfrom(req.sock, req.raw, sizeof(req.raw), 0, (sockaddr*)&req.remote, &req.sockLen);
	}

	closesocket(req.sock);
}

_Word recvTcpDnsMess(char *target, SOCKET sock, _Word targetSize)
{
	timeval tv1;
	fd_set readfds1;

	FD_ZERO(&readfds1);
	FD_SET(sock, &readfds1);
	tv1.tv_sec = 5;
	tv1.tv_usec = 0;

	if (select(sock + 1, &readfds1, NULL, NULL, &tv1))
	{
		errno = 0;
		short chunk = recv(sock, target, 2, 0);
		errno = WSAGetLastError();

		if (!errno && chunk == 2)
		{
			char *ptr;
			_Word rcd = chunk;
			_Word bytes = fUShort(target) + rcd;

			if (bytes > targetSize - 2)
				return 0;

			while (rcd < bytes)
			{
				FD_ZERO(&readfds1);
				FD_SET(sock, &readfds1);
				tv1.tv_sec = 5;
				tv1.tv_usec = 0;

				if (select(sock + 1, &readfds1, NULL, NULL, &tv1))
				{
					errno = 0;
					ptr = target + rcd;
					chunk = recv(sock, ptr, bytes - rcd, 0);
					errno = WSAGetLastError();

					if (chunk <= 0 || errno)
						return 0;
					else
						rcd += chunk;
				}
				else
					return 0;
			}

			return rcd;
		}
	}

	return 0;
}

void emptyCache(_Byte ind)
{
	//debug("emptyCache");
	char logBuff[512];
	CachedData *cache = NULL;

	//sprintf(logBuff, "Emptying cache[%d] Start %d=%d",ind, dnsCache[ind].size(), dnsAge[ind].size());
	//logMessage(logBuff, 2);

	config.mxCount[ind] = 0;
	dnsAge[ind].clear();
	hostMap::iterator p = dnsCache[ind].begin();

	while (p != dnsCache[ind].end())
	{
		cache = p->second;
		dnsCache[ind].erase(p);
		free(cache);
		p = dnsCache[ind].begin();
	}

	//dnsCache[ind].clear();
}

void __cdecl checkZone(void *lpParam)
{
	char ipbuff[16];
	char logBuff[512];

	data18 *magin = (data18*)lpParam;
	Sleep(1000*(config.refresh));

	while (kRunning)
	{
//		//if (!dhcpService && !findEntry(IP2String(ipbuff, htonl(config.zoneServers[1])), DNS_TYPE_PTR))
//		if (!dhcpService)
//			sendServerName();

		_Byte updateInd = !magin->currentInd;
		emptyCache(updateInd);
		sprintf(logBuff, "Checking Serial from Primary Server %s", IP2String(ipbuff, config.zoneServers[0]));
		logDNSMessage(logBuff, 2);

		_DWord serial1 = getSerial(config.zone);
		_DWord serial2 = 0;

		if (serial1)
			serial2 = getSerial(config.authority);

		if (!serial1 || !serial2)
		{
			//config.dnsRepl = 0;
			//config.dhcpRepl = 0;
			sprintf(logBuff, "Failed to get SOA from Primary Server, waiting %i seconds to retry", config.retry);
			logDNSMessage(logBuff, 1);
			Sleep(1000*(config.retry));
			continue;
		}
		else if (config.serial1 && config.serial1 == serial1 && config.serial2 && config.serial2 == serial2)
		{
			if (config.refresh > (_DWord)(INT_MAX - t))
				config.dnsRepl = INT_MAX;
			else
				config.dnsRepl = t + config.refresh + config.retry + config.retry;

			if (config.expire > (_DWord)(INT_MAX - t))
				config.expireTime = INT_MAX;
			else
				config.expireTime = t + config.expire;

			sprintf(logBuff, "Zone Refresh not required");
			logDNSMessage(logBuff, 2);
			Sleep(1000*(config.refresh));
		}
		else
		{
			//WaitForSingleObject(rEvent, INFINITE);
			serial1 = getZone(updateInd, config.zone);
			Sleep(5*1000);

			if (serial1)
				serial2 = getZone(updateInd, config.authority);
			//SetEvent(rEvent);

			if (!serial1 || !serial2)
			{
				sprintf(logBuff, "Waiting %u seconds to retry", config.retry);
				logDNSMessage(logBuff, 1);
				Sleep(1000*(config.retry));
			}
			else
			{
				if (config.refresh > (_DWord)(INT_MAX - t))
					config.dnsRepl = INT_MAX;
				else
					config.dnsRepl = t + config.refresh + config.retry + config.retry;

				magin->currentInd = updateInd;
				magin->done = true;
				config.serial1 = serial1;
				config.serial2 = serial2;

				if (config.expire > (_DWord)(INT_MAX - t))
					config.expireTime = INT_MAX;
				else
					config.expireTime = t + config.expire;

				Sleep(1000*(config.refresh));
			}
		}
	}

	_endthread();
	return;
}

FILE *pullZone(SOCKET sock)
{
    char target[4096];
    timeval tv1;
    fd_set readfds1;
    FILE *f = fopen(tempFile, "wb");

    if (f)
    {
        fclose(f);
        f = fopen(tempFile, "ab");
    }
    else
    {
		closesocket(sock);
        return NULL;
	}

    while (true)
    {
        FD_ZERO(&readfds1);
        FD_SET(sock, &readfds1);
        tv1.tv_sec = 10;
        tv1.tv_usec = 0;

        if (select((sock + 1), &readfds1, NULL, NULL, &tv1) > 0)
        {
            errno = 0;
            short bytes = recv(sock, target, sizeof(target), 0);
            errno = WSAGetLastError();

            if (errno)
			{
				closesocket(sock);
                fclose(f);
				return NULL;
			}

            //debug(bytes);

            if (bytes <= 0)
                break;

            if (bytes != (short)fwrite(target, 1, bytes, f))
			{
				closesocket(sock);
                fclose(f);
				return NULL;
			}
        }
        else
		{
			break;
			//closesocket(sock);
			//fclose(f);
			//return NULL;
		}
    }

	closesocket(sock);
	fclose(f);
    f = fopen(tempFile, "rb");
    return f;
}

_DWord getZone(_Byte ind, char *zone)
{
	Lump lump;
	char tempbuff[512];
	char ipbuff[16];
	char logBuff[512];
	char localhost[] = "localhost";
	char localhost_ip[] = "1.0.0.127";
	_DWord serial1 = 0;
	_DWord serial2 = 0;
	_DWord hostExpiry = 0;
	_DWord refresh = 0;
	_DWord retry = 0;
	_DWord expire = 0;
	_DWord expiry;
	_DWord minimum = 0;
	int added = 0;
	char *data;
	char *dp;
	_DWord ip;
	DNSRequest req;
	CachedData *cache = NULL;

	memset(&lump, 0, sizeof(Lump));
	lump.cType = CTYPE_LOCALHOST_A;
	lump.dnsType = DNS_TYPE_A;
	lump.mapname = localhost;
	cache = createCache(&lump);

	if (cache)
	{
		cache->ip = ntohl(inet_addr(localhost_ip));
		cache->expiry = INT_MAX;
		dnsCache[ind].insert(pair<string, CachedData*>(cache->mapname, cache));
	}

	memset(&lump, 0, sizeof(Lump));
	lump.cType = CTYPE_LOCALHOST_PTR;
	lump.dnsType = DNS_TYPE_PTR;
	lump.mapname = localhost_ip;
	lump.hostname = localhost;
	cache = createCache(&lump);

	if (cache)
	{
		cache->expiry = INT_MAX;
		dnsCache[ind].insert(pair<string, CachedData*>(cache->mapname, cache));
	}

	memset(&req, 0, sizeof(DNSRequest));
	req.sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (req.sock == INVALID_SOCKET)
	{
		sprintf(logBuff, "Failed to Create Socket, Zone Transfer Failed");
		logDNSMessage(logBuff, 1);
		return 0;
	}

	req.addr.sin_family = AF_INET;
	req.addr.sin_addr.s_addr = config.zoneServers[1];
	req.addr.sin_port = 0;

	int nRet = bind(req.sock, (sockaddr*)&req.addr, sizeof(req.addr));

	if (nRet == SOCKET_ERROR)
	{
		closesocket(req.sock);
		sprintf(logBuff, "Error: Interface %s not ready, Zone Transfer Failed", IP2String(ipbuff, req.addr.sin_addr.s_addr));
		logDNSMessage(logBuff, 1);
		return 0;
	}

	req.remote.sin_family = AF_INET;
	req.remote.sin_port = htons(IPPORT_DNS);
	req.remote.sin_addr.s_addr = config.zoneServers[0];

	req.sockLen = sizeof(req.remote);

	if (connect(req.sock, (sockaddr*)&req.remote, req.sockLen) >= 0)
	{
		req.dp = req.raw;
		req.dp += 2;
		req.dnsPacket = (DNSPacket*)req.dp;
		req.dnsPacket->header.questionsCount = htons(1);
		req.dnsPacket->header.queryID = (t % USHRT_MAX);
		req.dp = &req.dnsPacket->data;
		req.dp += pQu(req.dp, zone);
		req.dp += pUShort(req.dp, DNS_TYPE_AXFR);
		req.dp += pUShort(req.dp, DNS_CLASS_IN);
		req.bytes = req.dp - req.raw;
		pUShort(req.raw, req.bytes - 2);

		if (send(req.sock, req.raw, req.bytes, 0) < req.bytes)
		{
			closesocket(req.sock);
			sprintf(logBuff, "Failed to contact Primary Server %s, Zone Transfer Failed", IP2String(ipbuff, req.remote.sin_addr.s_addr));
			logDNSMessage(logBuff, 1);
			return 0;
		}

		FILE *f = pullZone(req.sock);

		if (!f)
			return 0;

		while (kRunning && !serial2)
		{
			req.bytes = fread(req.raw, 1, 2, f);

			if (req.bytes != 2)
				break;

			_Word pktSize = fUShort(req.raw);

			req.bytes = fread(req.raw, 1, pktSize, f);

			if ((_Word)req.bytes != pktSize)
			{
				fclose(f);
				return 0;
			}

			req.dnsPacket = (DNSPacket*)(req.raw);
			req.dp = &req.dnsPacket->data;
			char *dataend = req.raw + pktSize;

			if (req.dnsPacket->header.responseCode)
			{
				sprintf(logBuff, "Primary Server %s, zone %s refused", IP2String(ipbuff, req.remote.sin_addr.s_addr), zone);
				logDNSMessage(logBuff, 1);
				fclose(f);
				return 0;
			}

			if (!req.dnsPacket->header.responseFlag || !ntohs(req.dnsPacket->header.answersCount))
			{
				fclose(f);
				return 0;
			}

			for (int j = 1; j <= ntohs(req.dnsPacket->header.questionsCount); j++)
			{
				req.dp += fQu(req.query, req.dnsPacket, req.dp);
				req.dp += 4;
			}

			for (int i = 1; i <= ntohs(req.dnsPacket->header.answersCount); i++)
			{
				//char *dp = req.dp;
				req.dp += fQu(req.mapname, req.dnsPacket, req.dp);

				if (!req.mapname[0])
				{
					fclose(f);
					return 0;
				}

				//sprintf(logBuff, "%u=%s\n", pktSize, req.mapname);
				//logMessage(logBuff, 2);

				req.dnsType = fUShort(req.dp);
				req.dp += 2; //type
				req.qclass = fUShort(req.dp);
				req.dp += 2; //class
				expiry = fULong(req.dp);
				req.dp += 4; //ttl
				int dataSize = fUShort(req.dp);
				req.dp += 2; //datalength
				data = req.dp;
				req.dp += dataSize;

				switch (req.dnsType)
				{
					case DNS_TYPE_SOA:

						data += fQu(req.cname, req.dnsPacket, data);
						data += fQu(tempbuff, req.dnsPacket, data);

						if (!config.nsP[0])
							strcpy(config.nsP, req.cname);

						if (!serial1)
						{
							hostExpiry = expiry;
							serial1 = fULong(data);
							data += 4;
							refresh = fULong(data);
							data += 4;
							retry = fULong(data);
							data += 4;
							expire = fULong(data);
							data += 4;
							minimum = fULong(data);
							data += 4;
							added++;
						}
						else if (!serial2)
							serial2 = fULong(data);

						break;

					case DNS_TYPE_A:

						ip = fIP(data);
						makeLocal(req.mapname);
						memset(&lump, 0, sizeof(Lump));
						lump.cType = CTYPE_LOCAL_A;
						lump.dnsType = DNS_TYPE_A;
						lump.mapname = req.mapname;
						cache = createCache(&lump);

						if (cache)
						{
							cache->ip = ip;
							cache->expiry = INT_MAX;
							dnsCache[ind].insert(pair<string, CachedData*>(cache->mapname, cache));
							added++;
						}
						break;

					case DNS_TYPE_PTR:

						myLower(req.mapname);
						dp = strstr(req.mapname, arpa);

						if (dp)
						{
							*dp = 0;
							fQu(req.cname, req.dnsPacket, data);
							makeLocal(req.cname);
							memset(&lump, 0, sizeof(Lump));
							lump.cType = CTYPE_LOCAL_PTR_AUTH;
							lump.dnsType = DNS_TYPE_PTR;
							lump.mapname = req.mapname;
							lump.hostname = req.cname;
							cache = createCache(&lump);

							if (cache)
							{
								cache->expiry = INT_MAX;
								dnsCache[ind].insert(pair<string, CachedData*>(cache->mapname, cache));
								added++;
							}
						}
						break;

					case DNS_TYPE_MX:

						if (makeLocal(req.mapname) == QTYPE_A_ZONE)
						{
							config.mxServers[ind][config.mxCount[ind]].pref = fUShort(data);
							data += sizeof(_Word);
							fQu(req.cname, req.dnsPacket, data);
							strcpy(config.mxServers[ind][config.mxCount[ind]].hostname, req.cname);
							config.mxCount[ind]++;
							added++;
						}
						break;

					case DNS_TYPE_NS:

						fQu(req.cname, req.dnsPacket, data);

						if (!config.nsS[0] && strcasecmp(config.nsP, req.cname))
							strcpy(config.nsS, req.cname);

						break;

					case DNS_TYPE_CNAME:

						makeLocal(req.mapname);
						fQu(req.cname, req.dnsPacket, data);
						memset(&lump, 0, sizeof(Lump));

						//debug(req.mapname);
						//debug(req.cname);

						if (makeLocal(req.cname) == QTYPE_A_EXT)
							lump.cType = CTYPE_EXT_CNAME;
						else
							lump.cType = CTYPE_LOCAL_CNAME;

						lump.dnsType = DNS_TYPE_A;
						lump.mapname = req.mapname;
						lump.hostname = req.cname;
						cache = createCache(&lump);

						//sprintf(logBuff, "%s=%s=%u=%s=%s", req.mapname, req.cname, cache->mapname[0], &cache->mapname[1], cache->hostname);
						//logDNSMessage(logBuff, 2);

						if (cache)
						{
							dnsCache[ind].insert(pair<string, CachedData*>(cache->mapname, cache));
							cache->expiry = INT_MAX;
							added++;
						}
						break;
				}
			}

			if (req.dp != dataend)
			{
				fclose(f);
				return 0;
			}
		}

		fclose(f);

		if (serial1 && serial1 == serial2 && hostExpiry)
		{
			if (config.replication == 2)
			{
				config.lease = hostExpiry;
				config.refresh = refresh;
				config.retry = retry;
				config.expire = expire;
				config.minimum = minimum;
			}

			//printf("Refresh ind %i serial %u size %i\n", ind, serial1, dnsCache[ind].size());
			sprintf(logBuff, "Zone %s Transferred from Primary Server, %u RRs imported", zone, added);
			logDNSMessage(logBuff, 1);
			return serial1;
		}
		else
		{
			sprintf(logBuff, "Primary Server %s, zone %s Invalid AXFR data", IP2String(ipbuff, req.remote.sin_addr.s_addr), zone);
			logDNSMessage(logBuff, 1);
		}
	}
	else
	{
		sprintf(logBuff, "Failed to contact Primary Server %s, Zone Transfer Failed", IP2String(ipbuff, req.remote.sin_addr.s_addr));
		logDNSMessage(logBuff, 1);
		closesocket(req.sock);
		return 0;
	}
}

bool getSecondary()
{
	char logBuff[512];
	_DWord ip;
	_DWord hostExpiry = 0;
	_DWord expiry = 0;
	char *data = NULL;
	char *dp = NULL;
	_Word rr = 0;
	DNSRequest req;
	_DWord serial = 0;

	memset(&req, 0, sizeof(DNSRequest));
	req.sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (req.sock == INVALID_SOCKET)
		return false;

	req.addr.sin_family = AF_INET;
	req.addr.sin_addr.s_addr = config.zoneServers[0];
	req.addr.sin_port = 0;

	int nRet = bind(req.sock, (sockaddr*)&req.addr, sizeof(req.addr));

	if (nRet == SOCKET_ERROR)
	{
		closesocket(req.sock);
		return false;
	}

	req.remote.sin_family = AF_INET;
	req.remote.sin_port = htons(IPPORT_DNS);

	if (dhcpService && config.replication == 1)
		req.remote.sin_addr.s_addr = config.zoneServers[1];
	else
		return false;

	req.sockLen = sizeof(req.remote);
	time_t t = time(NULL);

	if (connect(req.sock, (sockaddr*)&req.remote, req.sockLen) == 0)
	{
		req.dp = req.raw;
		req.dp += 2;
		req.dnsPacket = (DNSPacket*)req.dp;
		req.dnsPacket->header.questionsCount = htons(1);
		req.dnsPacket->header.queryID = (t % USHRT_MAX);
		req.dp = &req.dnsPacket->data;
		req.dp += pQu(req.dp, config.authority);
		req.dp += pUShort(req.dp, DNS_TYPE_AXFR);
		req.dp += pUShort(req.dp, DNS_CLASS_IN);
		req.bytes = req.dp - req.raw;
		pUShort(req.raw, (req.bytes - 2));

		if (send(req.sock, req.raw, req.bytes, 0) < req.bytes)
		{
			closesocket(req.sock);
			return false;
		}

		FILE *f = pullZone(req.sock);

		if (!f)
			return false;

		while (kRunning)
		{
			req.bytes = fread(req.raw, 1, 2, f);

			if (req.bytes < 2)
				break;

			_Word pktSize = fUShort(req.raw);
			req.bytes = fread(req.raw, 1, pktSize, f);

			if ((_Word)req.bytes != pktSize)
			{
				fclose(f);
				return false;
			}

			req.dnsPacket = (DNSPacket*)(req.raw);
			req.dp = &req.dnsPacket->data;
			char *dataend = req.raw + pktSize;

			if (req.dnsPacket->header.responseCode)
			{
				fclose(f);
				return false;
			}

			if (!req.dnsPacket->header.responseFlag || !ntohs(req.dnsPacket->header.answersCount))
			{
				fclose(f);
				return false;
			}

			for (int j = 1; j <= ntohs(req.dnsPacket->header.questionsCount); j++)
			{
				req.dp += fQu(req.query, req.dnsPacket, req.dp);
				req.dp += 4;
			}

			for (int i = 1; i <= ntohs(req.dnsPacket->header.answersCount); i++)
			{
				//char *dp = req.dp;
				req.dp += fQu(req.mapname, req.dnsPacket, req.dp);

				if (!req.mapname[0])
				{
					fclose(f);
					return  false;
				}

				req.dnsType = fUShort(req.dp);
				req.dp += 2; //type
				req.qclass = fUShort(req.dp);
				req.dp += 2; //class
				expiry = fULong(req.dp);
				req.dp += 4; //ttl
				int dataSize = fUShort(req.dp);
				req.dp += 2; //datalength
				data = req.dp;
				req.dp += dataSize;

				if (req.dnsType == DNS_TYPE_PTR)
				{
					myLower(req.mapname);
					dp = strstr(req.mapname, arpa);

					if (dp)
					{
						*dp = 0;
						ip = ntohl(inet_addr(req.mapname));
						fQu(req.cname, req.dnsPacket, data);
						makeLocal(req.cname);

						dhcpMap::iterator p = dhcpCache.begin();
						CachedData *dhcpEntry = NULL;

						for (; p != dhcpCache.end(); p++)
						{
							if ((dhcpEntry = p->second) && dhcpEntry->ip && dhcpEntry->hostname)
							{
								if (ip == dhcpEntry->ip && !strcasecmp(req.cname, dhcpEntry->hostname))
								{
									if (expiry < (_DWord)(INT_MAX - t))
										expiry += t;
									else
										expiry = INT_MAX;

									add2Cache(req.cname, ip, expiry, CTYPE_LOCAL_A, CTYPE_LOCAL_PTR_AUTH);
									rr++;
									break;
								}
							}
						}
					}
				}
			}

			if (req.dp != dataend)
			{
				fclose(f);
				return false;
			}
		}

		sprintf(logBuff, "%u RRs rebuild from Secondary Server", rr);
		logDNSMessage(logBuff, 2);
		fclose(f);
		return true;
	}
	else
	{
		closesocket(req.sock);
		return false;
	}
}

void __cdecl init(void *lpParam)
{
	FILE *f = NULL;
	char raw[512];
	char name[512];
	char value[512];
	char ipbuff[32];
	char logBuff[512];
	char tempbuff[512];

	memset(&config, 0, sizeof(config));
	memset(&network, 0, sizeof(network));
	GetModuleFileName(NULL, filePATH, _MAX_PATH);
	char *fileExt = strrchr(filePATH, '.');
	*fileExt = 0;
	sprintf(leaFile, "%s.state", filePATH);
	sprintf(iniFile, "%s.ini", filePATH);
	sprintf(lnkFile, "%s.url", filePATH);
	sprintf(htmFile, "%s.htm", filePATH);
	sprintf(tempFile, "%s.tmp", filePATH);
	fileExt = strrchr(filePATH, '\\');
	*fileExt = 0;
	fileExt++;
	sprintf(logFile, "%s\\log\\%s%%Y%%m%%d.log", filePATH, fileExt);
	sprintf(cliFile, "%s\\log\\%%s.log", filePATH);
	strcat(filePATH, "\\");

	//printf("log=%s\n", logFile);

	config.dnsLogLevel = 1;
	config.dhcpLogLevel = 1;

	lEvent = CreateEvent(
		NULL,                  // default security descriptor
		FALSE,                 // ManualReset
		TRUE,                  // Signalled
		TEXT("AchalDualServerLogEvent"));  // object name

	if (lEvent == NULL)
	{
		printf("CreateEvent error: %d\n", GetLastError());
		exit(-1);
	}
	else if ( GetLastError() == ERROR_ALREADY_EXISTS )
	{
		sprintf(logBuff, "CreateEvent opened an existing Event\nServer May already be Running");
		logDHCPMessage(logBuff, 0);
		exit(-1);
	}

	SetEvent(lEvent);

	if (f = openSection("LOGGING", 1))
	{
		tempbuff[0] = 0;

		while (readSection(raw, f))
		{
			mySplit(name, value, raw, '=');

			if (name[0] && value[0])
			{
				if (!strcasecmp(name, "DNSLogLevel"))
				{
					if (!strcasecmp(value, "None"))
						config.dnsLogLevel = 0;
					else if (!strcasecmp(value, "Normal"))
						config.dnsLogLevel = 1;
					else if (!strcasecmp(value, "All"))
						config.dnsLogLevel = 2;
					else
						sprintf(tempbuff, "Section [LOGGING], Invalid DNSLogLevel: %s", value);
				}
				else if (!strcasecmp(name, "DHCPLogLevel"))
				{
					if (!strcasecmp(value, "None"))
						config.dhcpLogLevel = 0;
					else if (!strcasecmp(value, "Normal"))
						config.dhcpLogLevel = 1;
					else if (!strcasecmp(value, "All"))
						config.dhcpLogLevel = 2;
//					else if (!strcasecmp(value, "Debug"))
//						config.dhcpLogLevel = 3;
					else
						sprintf(tempbuff, "Section [LOGGING], Invalid DHCPLogLevel: %s", value);
				}
				else
					sprintf(tempbuff, "Section [LOGGING], Invalid Entry %s ignored", raw);
			}
			else
				sprintf(tempbuff, "Section [LOGGING], Invalid Entry %s ignored", raw);
		}

		if (tempbuff[0])
			logMessage(tempbuff, 1);

		sprintf(logBuff, "%s Starting...", sVersion);
		logMessage(logBuff, 1);
	}
	else
	{
		sprintf(logBuff, "%s Starting...", sVersion);
		logMessage(logBuff, 1);
	}

	_Word wVersionRequested = MAKEWORD(1, 1);
	WSAStartup(wVersionRequested, &config.wsaData);

	if (config.wsaData.wVersion != wVersionRequested)
	{
		sprintf(logBuff, "WSAStartup Error");
		logMessage(logBuff, 1);
	}

	if (f = openSection("SERVICES", 1))
	{
		dhcpService = false;
		DNSService = false;

		while(readSection(raw, f))
			if (!strcasecmp(raw, "DNS"))
				DNSService = true;
			else if (!strcasecmp(raw, "DHCP"))
				dhcpService = true;
			else
			{
				sprintf(logBuff, "Section [SERVICES] invalid entry %s ignored", raw);
				logMessage(logBuff, 1);
			}

		if (!dhcpService && !DNSService)
		{
			dhcpService = true;
			DNSService = true;
		}
	}

	if (DNSService)
	{
		sprintf(logBuff, "Starting DNS Service");
		logDNSMessage(logBuff, 1);

		if (FILE *f = openSection("FORWARDING_SERVERS", 1))
		{
			while (readSection(raw, f))
			{
				if (isIP(raw))
				{
					_DWord addr = inet_addr(raw);
					addServer(config.specifiedDNSServers, MAX_SERVERS, addr);
				}
				else
				{
					sprintf(logBuff, "Section [FORWARDING_SERVERS] Invalid Entry: %s ignored", raw);
					logDNSMessage(logBuff, 1);
				}
			}
		}
	}

	if (dhcpService)
	{
		sprintf(logBuff, "Starting DHCP Service");
		logDHCPMessage(logBuff, 1);
	}

	if (DNSService)
	{
		if (config.dnsLogLevel == 3)
			sprintf(logBuff, "DNS Logging: All");
		else if (config.dnsLogLevel == 2)
			sprintf(logBuff, "DNS Logging: All");
		else if (config.dnsLogLevel == 1)
			sprintf(logBuff, "DNS Logging: Normal");
		else
			sprintf(logBuff, "DNS Logging: None");

		logDNSMessage(logBuff, 1);
	}

	if (dhcpService)
	{
		if (config.dhcpLogLevel == 3)
			sprintf(logBuff, "DHCP Logging: Debug");
		else if (config.dhcpLogLevel == 2)
			sprintf(logBuff, "DHCP Logging: All");
		else if (config.dhcpLogLevel == 1)
			sprintf(logBuff, "DHCP Logging: Normal");
		else
			sprintf(logBuff, "DHCP Logging: None");

		logDHCPMessage(logBuff, 1);
	}

	if (f = openSection("LISTEN_ON", 1))
	{
		while (readSection(raw, f))
		{
			if (isIP(raw))
			{
				_DWord addr = inet_addr(raw);
				addServer(config.specifiedServers, MAX_SERVERS, addr);
			}
			else
			{
				sprintf(logBuff, "Warning: Section [LISTEN_ON], Invalid Interface Address %s, ignored", raw);
				logMessage(logBuff, 1);
			}
		}
	}

	config.lease = 36000;

	if (f = openSection("TIMINGS", 1))
	{
		while (readSection(raw, f))
		{
			mySplit(name, value, raw, '=');

			if (name[0] && value[0])
			{
				if (atol(value) || !strcasecmp(value,"0"))
				{
					if (!strcasecmp(name, "AddressTime"))
					{
						config.lease = atol(value);

						if (!config.lease)
							config.lease = UINT_MAX;
					}
					else if (!strcasecmp(name, "Refresh"))
						config.refresh = atol(value);
					else if (!strcasecmp(name, "Retry"))
						config.retry = atol(value);
					else if (!strcasecmp(name, "Expire"))
						config.expire = atol(value);
					else if (!strcasecmp(name, "Minimum"))
						config.minimum = atol(value);
					else if (!strcasecmp(name, "MinCacheTime"))
						config.minCache = atol(value);
					else if (!strcasecmp(name, "MaxCacheTime"))
						config.maxCache = atol(value);
					else
					{
						sprintf(logBuff, "Section [TIMINGS], Invalid Entry: %s ignored", raw);
						logDNSMessage(logBuff, 1);
					}
				}
				else
				{
					sprintf(logBuff, "Section [TIMINGS], Invalid value: %s ignored", value);
					logDNSMessage(logBuff, 1);
				}
			}
			else
			{
				sprintf(logBuff, "Section [TIMINGS], Missing value, entry %s ignored", raw);
				logDNSMessage(logBuff, 1);
			}
		}
	}

	if (!config.refresh)
	{
		config.refresh = config.lease / 10;

		if (config.refresh > 3600)
			config.refresh = 3600;

		if (config.refresh < 300)
			config.refresh = 300;
	}

	if (!config.retry || config.retry > config.refresh)
	{
		config.retry = config.refresh / 5;

		if (config.retry > 600)
			config.retry = 600;

		if (config.retry < 60)
			config.retry = 60;
	}

	if (!config.expire)
	{
		if (UINT_MAX/24 > config.lease)
			config.expire = 24 * config.lease;
		else
			config.expire = UINT_MAX;
	}

	if (!config.minimum)
		config.minimum = config.retry;

	if (f = openSection("DOMAIN_NAME", 1))
	{
		while (readSection(raw, f))
		{
			mySplit(name, value, raw, '=');

			if (name[0] && value[0])
			{
				InternetAddress mask;
				InternetAddress network;
				char left[64];

				config.authority[0] = 0;
				myLower(value);
				mask.ip = 0;
				network.ip = 0;

				for (_Byte octateNum = 0; octateNum < 3; octateNum++)
				{
					mySplit(left, value, value, '.');

					if (left[0] == '0' || (atoi(left) && atoi(left) < 256))
					{
						for (int j = 2; j >= 0; j--)
						{
							network.octate[j + 1] = network.octate[j];
							mask.octate[j + 1] = mask.octate[j];
						}

						mask.octate[0] = UCHAR_MAX;
						network.octate[0] = atoi(left);
						strcat(config.authority, left);
						strcat(config.authority, ".");
					}
					else
						break;

					if (!strcasecmp(value, arpa + 1))
						break;
				}

				if (!strcasecmp(value, arpa + 1))
				{
					strcat(config.authority, arpa + 1);
					config.aLen = strlen(config.authority);
					calcRangeLimits(network.ip, mask.ip, &config.rangeStart, &config.rangeEnd);
					//IP2String(logBuff, htonl(config.rangeStart));
					//logMessage(logBuff, 1);
					//IP2String(logBuff, htonl(config.rangeEnd));
					//logMessage(logBuff, 1);
					config.authorized = 1;
				}
				else
				{
					sprintf(logBuff, "Warning: Invalid Domain Name (Part %s), ignored", config.authority);
					config.aLen = 0;
					config.authority[0] = 0;
					logDNSMessage(logBuff, 1);
				}
			}

			if (checkQueue(name))
			{
				strcpy(config.zone, name);
				config.zLen = strlen(config.zone);
			}
			else
			{
				config.aLen = 0;
				config.authority[0] = 0;
				sprintf(logBuff, "Warning: Invalid Domain Name %s, ignored", raw);
				logDNSMessage(logBuff, 1);
			}
		}
	}

	getInterfaces(&network);
	sprintf(config.servername_fqn, "%s.%s", config.servername, config.zone);

	if (f = openSection("ZONE_REPLICATION", 1))
	{
		int i = 2;
		while (readSection(raw, f))
		{
			if(i < MAX_TCP_CLIENTS)
			{
				if (DNSService && !config.authorized)
				{
					sprintf(logBuff, "Section [ZONE_REPLICATION], Server is not an authority, entry %s ignored", raw);
					logDNSMessage(logBuff, 1);
					continue;
				}

				mySplit(name, value, raw, '=');

				if (name[0] && value[0])
				{
					if (checkQueue(name) && !isIP(name) && isIP(value))
					{
						if (!strcasecmp(name, "Primary"))
							config.zoneServers[0] = inet_addr(value);
						else if (!strcasecmp(name, "Secondary"))
							config.zoneServers[1] = inet_addr(value);
						else if (DNSService && !strcasecmp(name, "AXFRClient"))
						{
							config.zoneServers[i] = inet_addr(value);
							i++;
						}
						else
						{
							sprintf(logBuff, "Section [ZONE_REPLICATION] Invalid Entry: %s ignored", raw);
							logDNSMessage(logBuff, 1);
						}
					}
					else
					{
						sprintf(logBuff, "Section [ZONE_REPLICATION] Invalid Entry: %s ignored", raw);
						logDNSMessage(logBuff, 1);
					}
				}
				else
				{
					sprintf(logBuff, "Section [ZONE_REPLICATION], Missing value, entry %s ignored", raw);
					logDNSMessage(logBuff, 1);
				}
			}
		}
	}

	if (!config.zoneServers[0] && config.zoneServers[1])
	{
		sprintf(logBuff, "Section [ZONE_REPLICATION] Missing Primary Server");
		logDNSMessage(logBuff, 1);
	}
	else if (config.zoneServers[0] && !config.zoneServers[1])
	{
		sprintf(logBuff, "Section [ZONE_REPLICATION] Missing Secondary Server");
		logDNSMessage(logBuff, 1);
	}
	else if (config.zoneServers[0] && config.zoneServers[1])
	{
		if (findServer(network.staticServers, MAX_SERVERS, config.zoneServers[0]) && findServer(network.staticServers, MAX_SERVERS, config.zoneServers[1]))
		{
			sprintf(logBuff, "Section [ZONE_REPLICATION] Primary & Secondary should be Different Boxes");
			logDNSMessage(logBuff, 1);
		}
		else if (findServer(network.staticServers, MAX_SERVERS, config.zoneServers[0]))
			config.replication = 1;
		else if (findServer(network.staticServers, MAX_SERVERS, config.zoneServers[1]))
			config.replication = 2;
		else
		{
			sprintf(logBuff, "Section [ZONE_REPLICATION] No Server IP not found on this Machine");
			logDNSMessage(logBuff, 1);
		}
	}

	if (dhcpService)
	{
		loadDHCP();

		fEvent = CreateEvent(
			NULL,                  // default security descriptor
			FALSE,                 // ManualReset
			TRUE,                  // Signalled
			TEXT("AchalDualServerFileEvent"));  // object name

		if (fEvent == NULL)
		{
			printf("CreateEvent error: %d\n", GetLastError());
			exit(-1);
		}
		else if ( GetLastError() == ERROR_ALREADY_EXISTS )
		{
			sprintf(logBuff, "CreateEvent opened an existing Event\nServer May already be Running");
			logDHCPMessage(logBuff, 0);
			exit(-1);
		}
		//SetEvent(fEvent);

/*
		rEvent = CreateEvent(
			NULL,                  // default security descriptor
			FALSE,                 // ManualReset
			TRUE,                  // Signalled
			TEXT("AchalDualServerReplicationEvent"));  // object name

		if (rEvent == NULL)
		{
			printf("CreateEvent error: %d\n", GetLastError());
			exit(-1);
		}
		else if ( GetLastError() == ERROR_ALREADY_EXISTS )
		{
			sprintf(logBuff, "CreateEvent opened an existing Event\nServer May already be Running");
			logDHCPMessage(logBuff, 0);
			exit(-1);
		}
		//SetEvent(rEvent);
*/
		for (int i = 0; i < config.rangeCount; i++)
		{
			char *logPtr = logBuff;
			logPtr += sprintf(logPtr, "DHCP Range: ");
			logPtr += sprintf(logPtr, "%s", IP2String(ipbuff, htonl(config.dhcpRanges[i].rangeStart)));
			logPtr += sprintf(logPtr, "-%s", IP2String(ipbuff, htonl(config.dhcpRanges[i].rangeEnd)));
			logPtr += sprintf(logPtr, "/%s", IP2String(ipbuff, config.dhcpRanges[i].mask));
			logDHCPMessage(logBuff, 1);
		}

		if (config.replication)
		{
			lockIP(config.zoneServers[0]);
			lockIP(config.zoneServers[1]);
		}
	}

	if (DNSService)
	{
		if (f = openSection("DNS_ALLOWED_HOSTS", 1))
		{
			int i = 0;

			while (readSection(raw, f))
			{
				if(i < MAX_DNS_RANGES)
				{
					_DWord rs = 0;
					_DWord re = 0;
					mySplit(name, value, raw, '-');

					if (isIP(name) && isIP(value))
					{
						rs = htonl(inet_addr(name));
						re = htonl(inet_addr(value));
					}
					else if (isIP(name) && !value[0])
					{
						rs = htonl(inet_addr(name));
						re = rs;
					}

					//printf("%u=%u\n", rs, re);

					if (rs && re && rs <= re)
					{
						config.dnsRanges[i].rangeStart = rs;
						config.dnsRanges[i].rangeEnd = re;
						i++;
					}
					else
					{
						sprintf(logBuff, "Section [DNS_ALLOWED_HOSTS] Invalid entry %s in ini file, ignored", raw);
						logDNSMessage(logBuff, 1);
					}
				}
			}
		}

		if (config.replication != 2 && (f = openSection("DNS_HOSTS", 1)))
		{
			while (readSection(raw, f))
			{
				mySplit(name, value, raw, '=');

				if (name[0] && value[0])
				{
					if (checkQueue(name) && !isIP(name))
					{
						_DWord ip = inet_addr(value);
						_Byte nameType = makeLocal(name);
						bool ipLocal = isLocal(ip);

						if (!strcasecmp(value, "0.0.0.0"))
						{
							addHostNotFound(name);
							continue;
						}
						else if (!ip)
						{
							sprintf(logBuff, "Section [DNS_HOSTS] Invalid Entry %s ignored", raw);
							logDNSMessage(logBuff, 1);
							continue;
						}

						switch (nameType)
						{
							case QTYPE_A_ZONE:
							case QTYPE_A_BARE:
							case QTYPE_A_LOCAL:
								add2Cache(name, ip, INT_MAX, CTYPE_STATIC_A_AUTH, 0);
								break;

							default:
								if (config.replication)
								{
									sprintf(logBuff, "Section [DNS_HOSTS] forward entry for %s not in Forward Zone, ignored", raw);
									logDNSMessage(logBuff, 1);
								}
								else
									add2Cache(name, ip, INT_MAX, CTYPE_STATIC_A_NAUTH, 0);

								break;
						}

						if (ipLocal)
						{
							add2Cache(name, ip, INT_MAX, 0, CTYPE_STATIC_PTR_AUTH);
							holdIP(ip);
						}
						else if (config.replication)
						{
							sprintf(logBuff, "Section [DNS_HOSTS] reverse entry for %s not in Reverse Zone, ignored", raw);
							logDNSMessage(logBuff, 1);
						}
						else
							add2Cache(name, ip, INT_MAX, 0, CTYPE_STATIC_PTR_NAUTH);
					}
					else
					{
						sprintf(logBuff, "Section [DNS_HOSTS] Invalid Entry: %s ignored", raw);
						logDNSMessage(logBuff, 1);
					}
				}
				else
				{
					sprintf(logBuff, "Section [DNS_HOSTS], Missing value, entry %s ignored", raw);
					logDNSMessage(logBuff, 1);
				}
			}
		}

		if (config.replication != 2 && (f = openSection("ALIASES", 1)))
		{
			int i = 0;

			while (readSection(raw, f))
			{
				mySplit(name, value, raw, '=');

				if (name[0] && value[0])
				{
					_Byte nameType = makeLocal(name);
					_Byte aliasType = makeLocal(value);

					if (checkQueue(name) && checkQueue(value) && strcasecmp(value, config.zone))
					{
						if ((nameType == QTYPE_A_BARE || nameType == QTYPE_A_LOCAL || nameType == QTYPE_A_ZONE))
						{
							CachedData *cache = findEntry(name, DNS_TYPE_A);

							if (!cache)
							{
								memset(&lump, 0, sizeof(Lump));

								if ((aliasType == QTYPE_A_BARE || aliasType == QTYPE_A_LOCAL || aliasType == QTYPE_A_ZONE))
									lump.cType = CTYPE_LOCAL_CNAME;
								else
									lump.cType = CTYPE_EXT_CNAME;

								lump.dnsType = DNS_TYPE_A;
								lump.mapname = name;
								lump.hostname = value;
								cache = createCache(&lump);

								if (cache)
								{
									cache->expiry = INT_MAX;
									addEntry(cache);
								}
							}
							else
							{
								sprintf(logBuff, "Section [ALIASES] duplicate entry %s ignored", raw);
								logDNSMessage(logBuff, 1);
							}
						}
						else
						{
							sprintf(logBuff, "Section [ALIASES] alias %s should be bare/local name, entry ignored", name);
							logDNSMessage(logBuff, 1);
						}
					}
					else
					{
						sprintf(logBuff, "Section [ALIASES] Invalid Entry: %s ignored", raw);
						logDNSMessage(logBuff, 1);
					}
				}
				else
				{
					sprintf(logBuff, "Section [ALIASES], Missing value, entry %s ignored", raw);
					logDNSMessage(logBuff, 1);
				}
			}
		}

		if (config.replication != 2 && (f = openSection("MAIL_SERVERS", 1)))
		{
			config.mxCount[0] = 0;

			while (readSection(raw, f))
			{
				if (config.mxCount[0] < MAX_SERVERS)
				{
					mySplit(name, value, raw, '=');
					if (name[0] && value[0])
					{
						if (checkQueue(name) && atoi(value))
						{
							config.mxServers[0][config.mxCount[0]].pref = atoi(value);
							config.mxServers[1][config.mxCount[0]].pref = atoi(value);

							if (!strchr(name, '.'))
							{
								strcat(name, ".");
								strcat(name, config.zone);
							}

							strcpy(config.mxServers[0][config.mxCount[0]].hostname, name);
							strcpy(config.mxServers[1][config.mxCount[0]].hostname, name);
							config.mxCount[0]++;
						}
						else
						{
							sprintf(logBuff, "Section [MAIL_SERVERS] Invalid Entry: %s ignored", raw);
							logDNSMessage(logBuff, 1);
						}
					}
					else
					{
						sprintf(logBuff, "Section [MAIL_SERVERS], Missing value, entry %s ignored", raw);
						logDNSMessage(logBuff, 1);
					}
				}
				//config.mxCount[1] = config.mxCount[0];
			}
		}

		if (f = openSection("CONDITIONAL_FORWARDERS", 1))
		{
			int i = 0;

			while (readSection(raw, f))
			{
				if (i < MAX_COND_FORW)
				{
					mySplit(name, value, raw, '=');

					if (name[0] && value[0])
					{
						int j = 0;

						for (; j < MAX_COND_FORW && config.dnsRoutes[j].zone[0]; j++)
						{
							if (!strcasecmp(config.dnsRoutes[j].zone, name))
							{
								sprintf(logBuff, "Section [CONDITIONAL_FORWARDERS], Duplicate Entry for Child Zone %s ignored", raw);
								logDNSMessage(logBuff, 1);
								break;
							}
						}

						if (j < MAX_COND_FORW && !config.dnsRoutes[j].zone[0])
						{
							if (name[0] && checkQueue(name) && value[0])
							{
								char *value1 = strchr(value, ',');

								if (value1)
								{
									*value1 = 0;
									value1++;

									_DWord ip = inet_addr(myTrim(value, value));
									_DWord ip1 = inet_addr(myTrim(value1, value1));

									if (isIP(value) && isIP(value1))
									{
										strcpy(config.dnsRoutes[i].zone, name);
										config.dnsRoutes[i].zLen = strlen(config.dnsRoutes[i].zone);
										config.dnsRoutes[i].DNS[0] = ip;
										config.dnsRoutes[i].DNS[1] = ip1;
										i++;
									}
									else
									{
										sprintf(logBuff, "Section [CONDITIONAL_FORWARDERS] Invalid Entry: %s ignored", raw);
										logDNSMessage(logBuff, 1);
									}
								}
								else
								{
									_DWord ip = inet_addr(value);

									if (isIP(value))
									{
										strcpy(config.dnsRoutes[i].zone, name);
										config.dnsRoutes[i].zLen = strlen(config.dnsRoutes[i].zone);
										config.dnsRoutes[i].DNS[0] = ip;
										i++;
									}
									else
									{
										sprintf(logBuff, "Section [CONDITIONAL_FORWARDERS] Invalid Entry: %s ignored", raw);
										logDNSMessage(logBuff, 1);
									}
								}
							}
							else
							{
								sprintf(logBuff, "Section [CONDITIONAL_FORWARDERS] Invalid Entry: %s ignored", raw);
								logDNSMessage(logBuff, 1);
							}
						}
					}
					else
					{
						sprintf(logBuff, "Section [CONDITIONAL_FORWARDERS], Missing value, entry %s ignored", raw);
						logDNSMessage(logBuff, 1);
					}
				}
			}
		}

		if (f = openSection("WILD_HOSTS", 1))
		{
			int i = 0;

			while (readSection(raw, f))
			{
				if (i < MAX_WILDCARD_HOSTS)
				{
					mySplit(name, value, raw, '=');

					if (name[0] && value[0])
					{
						if (checkQueue(name) && (isIP(value) || !strcasecmp(value, "0.0.0.0")))
						{
							_DWord ip = inet_addr(value);
							strcpy(config.wildcardHosts[i].wildcard, name);
							myLower(config.wildcardHosts[i].wildcard);
							config.wildcardHosts[i].ip = ip;
							i++;
						}
						else
						{
							sprintf(logBuff, "Section [WILD_HOSTS] Invalid Entry: %s ignored", raw);
							logDNSMessage(logBuff, 1);
						}
					}
					else
					{
						sprintf(logBuff, "Section [WILD_HOSTS], Missing value, entry %s ignored", raw);
						logDNSMessage(logBuff, 1);
					}
				}
			}
		}

		if (config.replication == 2)
		{
//			if (dhcpService)
//				strcpy(config.nsS, config.servername_fqn);

			while (kRunning)
			{
//				//if (!dhcpService && !findEntry(IP2String(ipbuff, htonl(config.zoneServers[1])), DNS_TYPE_PTR))
//				if (!dhcpService)
//				{
//					sendServerName();
//					Sleep(1000);
//				}

				_DWord serial1 = getSerial(config.zone);
				_DWord serial2 = 0;

				if (serial1)
					serial2 = getSerial(config.authority);

				if (serial1 && serial2)
				{
					config.serial1 = getZone(0, config.zone);
					Sleep(5*1000);

					if (config.serial1)
						config.serial2 = getZone(0, config.authority);
				}

				if (config.serial1 && config.serial2)
				{
					if (config.refresh > (_DWord)(INT_MAX - t))
						config.dnsRepl = INT_MAX;
					else
						config.dnsRepl = t + config.refresh + config.retry + config.retry;

					break;
				}

				sprintf(logBuff, "Failed to get Zone(s) from Primary Server, waiting %d seconds to retry", config.retry);
				logDNSMessage(logBuff, 1);

				Sleep(config.retry*1000);
			}

			if (dhcpService)
			{
				CachedData *cache = NULL;
				hostMap::iterator p = dnsCache[0].begin();

				while (p != dnsCache[0].end())
				{
					cache = p->second;

					switch (cache->cType)
					{
						case CTYPE_STATIC_A_AUTH:
							holdIP(cache->ip);
							break;

						case CTYPE_STATIC_PTR_AUTH:
							holdIP(htonl(inet_addr(cache->mapname)));
							break;
					}

					p++;
				}
			}

			if (config.expire > (_DWord)(INT_MAX - t))
				config.expireTime = INT_MAX;
			else
				config.expireTime = t + config.expire;

			magin.currentInd = 0;
			magin.done = false;
			_beginthread(checkZone, 0, &magin);
		}
		else if (config.replication == 1)
		{
			strcpy(config.nsP, config.servername_fqn);

			if (!dhcpService)
			{
				findHost(config.nsS, config.zoneServers[1]);

				if (config.nsS[0])
				{
					strcat(config.nsS, ".");
					strcat(config.nsS, config.zone);
				}
			}

			config.serial1 = t;
			config.serial2 = t;
			config.expireTime = INT_MAX;
			char localhost[] = "localhost";
			add2Cache(localhost, inet_addr("127.0.0.1"), INT_MAX, CTYPE_LOCALHOST_A, CTYPE_LOCALHOST_PTR);

			if (isLocal(config.zoneServers[0]))
				add2Cache(config.servername, config.zoneServers[0], INT_MAX, CTYPE_SERVER_A_AUTH, CTYPE_SERVER_PTR_AUTH);
			else
				add2Cache(config.servername, config.zoneServers[0], INT_MAX, CTYPE_SERVER_A_AUTH, CTYPE_SERVER_PTR_NAUTH);

			if (dhcpService)
				getSecondary();
		}
		else
		{
			strcpy(config.nsP, config.servername_fqn);
			config.serial1 = t;
			config.serial2 = t;
			config.expireTime = INT_MAX;
			char localhost[] = "localhost";
			add2Cache(localhost, inet_addr("127.0.0.1"), INT_MAX, CTYPE_LOCALHOST_A, CTYPE_LOCALHOST_PTR);

			bool ifspecified = false;

			for (int i = 0; i < MAX_SERVERS && network.listenServers[i]; i++)
			{
				if (isLocal(network.listenServers[i]))
					add2Cache(config.servername, network.listenServers[i], INT_MAX, CTYPE_SERVER_A_AUTH, CTYPE_SERVER_PTR_AUTH);
				else
					add2Cache(config.servername, network.listenServers[i], INT_MAX, CTYPE_SERVER_A_AUTH, CTYPE_SERVER_PTR_NAUTH);
			}
		}
	}

	if (dhcpService)
	{
		if (config.replication)
		{
			config.dhcpReplConn.sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

			if (config.dhcpReplConn.sock == INVALID_SOCKET)
			{
				sprintf(logBuff, "Failed to Create DHCP Replication Socket");
				logDHCPMessage(logBuff, 1);
			}
			else
			{
				//printf("Socket %u\n", config.dhcpReplConn.sock);

				if (config.replication == 1)
					config.dhcpReplConn.server = config.zoneServers[0];
				else
					config.dhcpReplConn.server = config.zoneServers[1];

				config.dhcpReplConn.addr.sin_family = AF_INET;
				config.dhcpReplConn.addr.sin_addr.s_addr = config.dhcpReplConn.server;
				config.dhcpReplConn.addr.sin_port = 0;

				int nRet = bind(config.dhcpReplConn.sock, (sockaddr*)&config.dhcpReplConn.addr, sizeof(struct sockaddr_in));

				if (nRet == SOCKET_ERROR)
				{
					config.dhcpReplConn.ready = false;
					sprintf(logBuff, "DHCP Replication Server, Bind Failed");
					logDHCPMessage(logBuff, 1);
				}
				else
				{
					config.dhcpReplConn.port = IPPORT_DHCPS;
					config.dhcpReplConn.loaded = true;
					config.dhcpReplConn.ready = true;

					data3 op;
					memset(&token, 0, sizeof(DHCPRequest));
					token.vp = token.DHCPPacket.vend_data;
					token.messsize = sizeof(DHCPPacket);

					token.remote.sin_port = htons(IPPORT_DHCPS);
					token.remote.sin_family = AF_INET;

					if (config.replication == 1)
						token.remote.sin_addr.s_addr = config.zoneServers[1];
					else if (config.replication == 2)
						token.remote.sin_addr.s_addr = config.zoneServers[0];

					token.DHCPPacket.header.bp_op = BOOTP_REQUEST;
					token.DHCPPacket.header.bp_xid = t;
					strcpy(token.DHCPPacket.header.bp_sname, config.servername);
					token.DHCPPacket.header.bp_magic_num[0] = 99;
					token.DHCPPacket.header.bp_magic_num[1] = 130;
					token.DHCPPacket.header.bp_magic_num[2] = 83;
					token.DHCPPacket.header.bp_magic_num[3] = 99;

					op.opt_code = DHCP_OPTION_MESSAGETYPE;
					op.size = 1;
					op.value[0] = DHCP_MESS_INFORM;
					pvdata(&token, &op);

					if (DNSService)
					{
						op.opt_code = DHCP_OPTION_DNS;
						op.size = 4;

						if (config.replication == 1)
							pIP(op.value, config.zoneServers[0]);
						else
							pIP(op.value, config.zoneServers[1]);

						pvdata(&token, &op);
					}

					//op.opt_code = DHCP_OPTION_HOSTNAME;
					//op.size = strlen(config.servername);
					//memcpy(op.value, config.servername, op.size);
					//pvdata(&token, &op);

					token.vp[0] = DHCP_OPTION_END;
					token.vp++;
					token.bytes = token.vp - (_Byte*)token.raw;

 					if (config.replication == 2)
						_beginthread(sendToken, 0, 0);
				}
			}
		}

		if (config.lease >= INT_MAX)
			sprintf(logBuff, "Default Lease: Infinity");
		else
			sprintf(logBuff, "Default Lease: %u (sec)", config.lease);

		logDHCPMessage(logBuff, 1);
	}

	if (config.replication == 1)
		sprintf(logBuff, "Server Name: %s (Primary)", config.servername);
	else if (config.replication == 2)
		sprintf(logBuff, "Server Name: %s (Secondary)", config.servername);
	else
		sprintf(logBuff, "Server Name: %s", config.servername);

	logDNSMessage(logBuff, 1);

	if (DNSService)
	{
		if (config.authorized)
			sprintf(logBuff, "Authority for Zone: %s (%s)", config.zone, config.authority);
		else
			sprintf(logBuff, "Domain Name: %s", config.zone);

		logDNSMessage(logBuff, 1);

		if (config.lease >= INT_MAX)
			sprintf(logBuff, "Default Host Expiry: Infinity");
		else
			sprintf(logBuff, "Default Host Expiry: %u (sec)", config.lease);

		logDNSMessage(logBuff, 1);

		if (config.replication)
		{
			sprintf(logBuff, "Refresh: %u (sec)", config.refresh);
			logDNSMessage(logBuff, 1);
			sprintf(logBuff, "Retry: %u (sec)", config.retry);
			logDNSMessage(logBuff, 1);

			if (config.expire == UINT_MAX)
				sprintf(logBuff, "Expire: Infinity");
			else
				sprintf(logBuff, "Expire: %u (sec)", config.expire);

			logDNSMessage(logBuff, 1);
			sprintf(logBuff, "Min: %u (sec)", config.minimum);
			logDNSMessage(logBuff, 1);
		}

		for (int i = 0; i < MAX_COND_FORW && config.dnsRoutes[i].DNS[0]; i++)
		{
			char temp[256];

			if (!config.dnsRoutes[i].DNS[1])
				sprintf(logBuff, "Conditional Forwarder: %s for %s", IP2String(ipbuff, config.dnsRoutes[i].DNS[0]), config.dnsRoutes[i].zone);
			else
				sprintf(logBuff, "Conditional Forwarder: %s, %s for %s", IP2String(temp, config.dnsRoutes[i].DNS[0]), IP2String(ipbuff, config.dnsRoutes[i].DNS[1]), config.dnsRoutes[i].zone);

			logDNSMessage(logBuff, 1);
		}

		for (int i = 0; i < MAX_SERVERS && network.DNS[i]; i++)
		{
			sprintf(logBuff, "Default Forwarding Server: %s", IP2String(ipbuff, network.DNS[i]));
			logDNSMessage(logBuff, 1);
		}

		//char temp[128];

		for (int i = 0; i <= MAX_DNS_RANGES && config.dnsRanges[i].rangeStart; i++)
		{
			char *logPtr = logBuff;
			logPtr += sprintf(logPtr, "%s", "DNS Service Permitted Hosts: ");
			logPtr += sprintf(logPtr, "%s-", IP2String(ipbuff, htonl(config.dnsRanges[i].rangeStart)));
			logPtr += sprintf(logPtr, "%s", IP2String(ipbuff, htonl(config.dnsRanges[i].rangeEnd)));
			logDNSMessage(logBuff, 1);
		}
	}
	else
	{
		sprintf(logBuff, "Domain Name: %s", config.zone);
		logDNSMessage(logBuff, 1);
	}

	sprintf(logBuff, "Detecting Static Interfaces..");
	logMessage(logBuff, 1);

	do
	{
		closeConn();
		getInterfaces(&network);

		network.maxFD = config.dhcpReplConn.sock;

		bool ifSpecified = false;
		bool bindfailed = false;

		if (dhcpService)
		{
			int i = 0;

			for (int j = 0; j < MAX_SERVERS && network.listenServers[j]; j++)
			{
				network.dhcpConn[i].sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

				if (network.dhcpConn[i].sock == INVALID_SOCKET)
				{
					bindfailed = true;
					sprintf(logBuff, "Failed to Create Socket");
					logDHCPMessage(logBuff, 1);
					continue;
				}

				//printf("Socket %u\n", network.dhcpConn[i].sock);

				network.dhcpConn[i].addr.sin_family = AF_INET;
				network.dhcpConn[i].addr.sin_addr.s_addr = network.listenServers[j];
				network.dhcpConn[i].addr.sin_port = htons(IPPORT_DHCPS);

				network.dhcpConn[i].broadCastVal = TRUE;
				network.dhcpConn[i].broadCastSize = sizeof(network.dhcpConn[i].broadCastVal);
				setsockopt(network.dhcpConn[i].sock, SOL_SOCKET, SO_BROADCAST, (char*)(&network.dhcpConn[i].broadCastVal), network.dhcpConn[i].broadCastSize);

				int nRet = bind(network.dhcpConn[i].sock,
								(sockaddr*)&network.dhcpConn[i].addr,
								sizeof(struct sockaddr_in)
							   );

				if (nRet == SOCKET_ERROR)
				{
					bindfailed = true;
					closesocket(network.dhcpConn[i].sock);
					sprintf(logBuff, "Warning: %s UDP Port 67 already in use", IP2String(ipbuff, network.listenServers[j]));
					logDHCPMessage(logBuff, 1);
					continue;
				}

				network.dhcpConn[i].loaded = true;
				network.dhcpConn[i].ready = true;

				if (network.maxFD < network.dhcpConn[i].sock)
					network.maxFD = network.dhcpConn[i].sock;

				network.dhcpConn[i].server = network.listenServers[j];
				network.dhcpConn[i].mask = network.listenMasks[j];
				network.dhcpConn[i].port = IPPORT_DHCPS;

				i++;
			}

			network.HTTPConnection.port = 6788;
			network.HTTPConnection.server = inet_addr("127.0.0.1");
			network.APIConnection.port = 5999;
			network.APIConnection.server = inet_addr("127.0.0.1");

			if (f = openSection("HTTP_INTERFACE", 1))
			{
				while (readSection(raw, f))
				{
					mySplit(name, value, raw, '=');

					if (!strcasecmp(name, "HTTPServer"))
					{
						mySplit(name, value, value, ':');

						if (isIP(name))
						{
							network.HTTPConnection.server = inet_addr(name);
						}
						else
						{
							network.HTTPConnection.loaded = false;
							sprintf(logBuff, "Warning: Section [HTTP_INTERFACE], Invalid IP Address %s, ignored", name);
							logDHCPMessage(logBuff, 1);
						}

						if (value[0])
						{
							if (atoi(value))
								network.HTTPConnection.port = atoi(value);
							else
							{
								network.HTTPConnection.loaded = false;
								sprintf(logBuff, "Warning: Section [HTTP_INTERFACE], Invalid port %s, ignored", value);
								logDHCPMessage(logBuff, 1);
							}
						}

						if (network.HTTPConnection.server != inet_addr("127.0.0.1") && !findServer(network.allServers, MAX_SERVERS, network.HTTPConnection.server))
						{
							bindfailed = true;
							network.HTTPConnection.loaded = false;
							sprintf(logBuff, "Warning: Section [HTTP_INTERFACE], %s not available, ignored", raw);
							logDHCPMessage(logBuff, 1);
						}
					}
					else if (!strcasecmp(name, "HTTPClient"))
					{
						if (isIP(value))
							addServer(config.HTTPClients, 8, inet_addr(value));
						else
						{
							sprintf(logBuff, "Warning: Section [HTTP_INTERFACE], invalid client IP %s, ignored", raw);
							logDHCPMessage(logBuff, 1);
						}
					}
					else if (!strcasecmp(name, "HTTPTitle"))
					{
						strncpy(htmlTitle, value, 255);
						htmlTitle[255] = 0;
					}
					else
					{
						sprintf(logBuff, "Warning: Section [HTTP_INTERFACE], invalid entry %s, ignored", raw);
						logDHCPMessage(logBuff, 1);
					}
				}
			}

			if (!htmlTitle[0])
				sprintf(htmlTitle, "Dual Server on %s", config.servername);

			network.HTTPConnection.sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

			if (network.HTTPConnection.sock == INVALID_SOCKET)
			{
				bindfailed = true;
				sprintf(logBuff, "Failed to Create Socket");
				logDHCPMessage(logBuff, 1);
			}
			else
			{
				//printf("Socket %u\n", network.HTTPConnection.sock);

				network.HTTPConnection.addr.sin_family = AF_INET;
				network.HTTPConnection.addr.sin_addr.s_addr = network.HTTPConnection.server;
				network.HTTPConnection.addr.sin_port = htons(network.HTTPConnection.port);

				int nRet = bind(network.HTTPConnection.sock, (sockaddr*)&network.HTTPConnection.addr, sizeof(struct sockaddr_in));

				if (nRet == SOCKET_ERROR)
				{
					bindfailed = true;
					sprintf(logBuff, "Http Interface %s TCP Port %u not available", IP2String(ipbuff, network.HTTPConnection.server), network.HTTPConnection.port);
					logDHCPMessage(logBuff, 1);
					closesocket(network.HTTPConnection.sock);
				}
				else
				{
					nRet = listen(network.HTTPConnection.sock, SOMAXCONN);

					if (nRet == SOCKET_ERROR)
					{
						bindfailed = true;
						sprintf(logBuff, "%s TCP Port %u Error on Listen", IP2String(ipbuff, network.HTTPConnection.server), network.HTTPConnection.port);
						logDHCPMessage(logBuff, 1);
						closesocket(network.HTTPConnection.sock);
					}
					else
					{
						network.HTTPConnection.loaded = true;
						network.HTTPConnection.ready = true;

						if (network.HTTPConnection.sock > network.maxFD)
							network.maxFD = network.HTTPConnection.sock;
					}
				}
			}



			closesocket(network.APIConnection.sock);
			network.APIConnection.sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
			if (network.APIConnection.sock == INVALID_SOCKET)
			{
				printf("Ya dunn goodfed\n\n");
				closesocket(network.APIConnection.sock);
			}
			else
			{
				network.APIConnection.addr.sin_family = AF_INET;
				network.APIConnection.addr.sin_addr.s_addr = inet_addr("127.0.0.1");
				network.APIConnection.addr.sin_port = htons(6777);
				int nRet = bind(network.APIConnection.sock, (sockaddr*)&network.APIConnection.addr, sizeof(struct sockaddr_in));
				if (nRet == SOCKET_ERROR) {
					bindfailed = true;
					sprintf(logBuff, "API Interface %s TCP Port %u not available {%d}", IP2String(ipbuff, inet_addr("127.0.0.1")), 6777, WSAGetLastError());
					logDHCPMessage(logBuff, 1);
					closesocket(network.APIConnection.sock);
				}
				else
				{
					nRet = listen(network.APIConnection.sock, SOMAXCONN);
					if (nRet == SOCKET_ERROR)
					{
						printf("Dang.\n\n");
						closesocket(network.APIConnection.sock);
					}
					else
					{
						network.APIConnection.loaded = true;
						network.APIConnection.ready = true;

						if (network.APIConnection.sock > network.maxFD)
							network.maxFD = network.APIConnection.sock;
					}
				}
			}



		}

		if (DNSService)
		{
			int i = 0;

			for (int j = 0; j < MAX_SERVERS && network.listenServers[j]; j++)
			{
				network.DNS_UDPConnections[i].sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

				if (network.DNS_UDPConnections[i].sock == INVALID_SOCKET)
				{
					bindfailed = true;
					sprintf(logBuff, "Failed to Create Socket");
					logDNSMessage(logBuff, 1);
					continue;
				}

				//printf("Socket %u\n", network.DNS_UDPConnections[i].sock);

				network.DNS_UDPConnections[i].addr.sin_family = AF_INET;
				network.DNS_UDPConnections[i].addr.sin_addr.s_addr = network.listenServers[j];
				network.DNS_UDPConnections[i].addr.sin_port = htons(IPPORT_DNS);

				int nRet = bind(network.DNS_UDPConnections[i].sock,
								(sockaddr*)&network.DNS_UDPConnections[i].addr,
								sizeof(struct sockaddr_in)
							   );

				if (nRet == SOCKET_ERROR)
				{
					bindfailed = true;
					closesocket(network.DNS_UDPConnections[i].sock);
					sprintf(logBuff, "Warning: %s UDP Port 53 already in use", IP2String(ipbuff, network.listenServers[j]));
					logDNSMessage(logBuff, 1);
					continue;
				}

				network.DNS_UDPConnections[i].loaded = true;
				network.DNS_UDPConnections[i].ready = true;

				if (network.maxFD < network.DNS_UDPConnections[i].sock)
					network.maxFD = network.DNS_UDPConnections[i].sock;

				network.DNS_UDPConnections[i].server = network.listenServers[j];
				network.DNS_UDPConnections[i].port = IPPORT_DNS;

				i++;
			}

			network.forwConn.sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

			if (network.forwConn.sock == INVALID_SOCKET)
			{
				bindfailed = true;
				sprintf(logBuff, "Failed to Create Socket");
				logDNSMessage(logBuff, 1);
			}
			else
			{
				network.forwConn.addr.sin_family = AF_INET;
				network.forwConn.server = network.DNS[0];
				network.forwConn.port = IPPORT_DNS;
				//bind(network.forwConn.sock, (sockaddr*)&network.forwConn.addr, sizeof(struct sockaddr_in));

				network.forwConn.loaded = true;
				network.forwConn.ready = true;

				if (network.maxFD < network.forwConn.sock)
					network.maxFD = network.forwConn.sock;
			}

			i = 0;

			for (int j = 0; j < MAX_SERVERS && network.listenServers[j]; j++)
			{
				network.DNS_TCPConnections[i].sock = socket( PF_INET, SOCK_STREAM, IPPROTO_TCP);

				if (network.DNS_TCPConnections[i].sock == INVALID_SOCKET)
				{
					bindfailed = true;
					sprintf(logBuff, "Failed to Create Socket");
					logDNSMessage(logBuff, 1);
				}
				else
				{
					//printf("Socket %u\n", network.DNS_TCPConnections[i].sock);
					network.DNS_TCPConnections[i].addr.sin_family = AF_INET;
					network.DNS_TCPConnections[i].addr.sin_addr.s_addr = network.listenServers[j];
					network.DNS_TCPConnections[i].addr.sin_port = htons(IPPORT_DNS);

					int nRet = bind(network.DNS_TCPConnections[i].sock,
									(sockaddr*)&network.DNS_TCPConnections[i].addr,
									sizeof(struct sockaddr_in));

					if (nRet == SOCKET_ERROR)
					{
						bindfailed = true;
						closesocket(network.DNS_TCPConnections[i].sock);
						sprintf(logBuff, "Warning: %s TCP Port 53 already in use", IP2String(ipbuff, network.listenServers[j]));
						logDNSMessage(logBuff, 1);
					}
					else
					{
						nRet = listen(network.DNS_TCPConnections[i].sock, SOMAXCONN);

						if (nRet == SOCKET_ERROR)
						{
							closesocket(network.DNS_TCPConnections[i].sock);
							sprintf(logBuff, "TCP Port 53 Error on Listen");
							logDNSMessage(logBuff, 1);
						}
						else
						{
							network.DNS_TCPConnections[i].server = network.listenServers[j];
							network.DNS_TCPConnections[i].port = IPPORT_DNS;

							network.DNS_TCPConnections[i].loaded = true;
							network.DNS_TCPConnections[i].ready = true;

							if (network.maxFD < network.DNS_TCPConnections[i].sock)
								network.maxFD = network.DNS_TCPConnections[i].sock;

							i++;
						}
					}
				}
			}
		}

		network.maxFD++;

		if (dhcpService)
		{
			for (_Byte m = 0; m < MAX_SERVERS && network.allServers[m]; m++)
				lockIP(network.allServers[m]);

			for (_Byte m = 0; m < MAX_SERVERS && network.DNS[m]; m++)
				lockIP(network.DNS[m]);
		}

		if (bindfailed)
			config.failureCount++;
		else
			config.failureCount = 0;

		//printf("%i %i %i\n", network.dhcpConn[0].ready, network.DNS_UDPConnections[0].ready, network.DNS_TCPConnections[0].ready);

		if ((dhcpService && !network.dhcpConn[0].ready) || (DNSService && !(network.DNS_UDPConnections[0].ready && network.DNS_TCPConnections[0].ready)))
		{
			sprintf(logBuff, "No Static Interface ready, Waiting...");
			logMessage(logBuff, 1);
			continue;
		}

		if (dhcpService && network.HTTPConnection.ready)
		{
			sprintf(logBuff, "Lease Status URL: http://%s:%u", IP2String(ipbuff, network.HTTPConnection.server), network.HTTPConnection.port);
			logDHCPMessage(logBuff, 1);
			FILE *f = fopen(htmFile, "wt");

			if (f)
			{
				fprintf(f, "<html><head><meta http-equiv=\"refresh\" content=\"0;url=http://%s:%u\"</head></html>", IP2String(ipbuff, network.HTTPConnection.server), network.HTTPConnection.port);
				fclose(f);
			}
		}
		else
		{
			FILE *f = fopen(htmFile, "wt");

			if (f)
			{
				fprintf(f, "<html><body><h2>DHCP/HTTP Service is not running</h2></body></html>");
				fclose(f);
			}
		}

		for (int i = 0; i < MAX_SERVERS && network.staticServers[i]; i++)
		{
			for (_Byte j = 0; j < MAX_SERVERS; j++)
			{
				if (network.dhcpConn[j].server == network.staticServers[i] || network.DNS_UDPConnections[j].server == network.staticServers[i])
				{
					sprintf(logBuff, "Listening On: %s", IP2String(ipbuff, network.staticServers[i]));
					logMessage(logBuff, 1);
					break;
				}
			}
		}

	} while (kRunning && detectChange());

	_endthread();
	return;
}

bool detectChange()
{
	char logBuff[512];
	//debug("Calling detectChange()");

	network.ready = true;

	if (config.failureCount)
	{
		_DWord eventWait = (_DWord)(10000 * pow(2, config.failureCount));
		Sleep(eventWait);
		sprintf(logBuff, "Retrying failed Listening Interfaces..");
		logDHCPMessage(logBuff, 1);
		network.ready = false;

		while (network.busy)
			Sleep(500);

		return true;
	}

	DWORD ret = NotifyAddrChange(NULL, NULL);

	if ((errno = WSAGetLastError()) && errno != WSA_IO_PENDING)
	{
		sprintf(logBuff, "NotifyAddrChange error...%d", errno);
		logDHCPMessage(logBuff, 1);
	}

	Sleep(1000);
	sprintf(logBuff, "Network changed, re-detecting Static Interfaces..");
	logDHCPMessage(logBuff, 1);
	network.ready = false;

	while (network.busy)
		Sleep(500);

	return true;
}

void getInterfaces(Network *network)
{
	char logBuff[512];
	char ipbuff[32];

	memset(network, 0, sizeof(Network));

	SOCKET sd = WSASocket(PF_INET, SOCK_DGRAM, 0, 0, 0, 0);

	if (sd == INVALID_SOCKET)
		return;

	INTERFACE_INFO InterfaceList[MAX_SERVERS];
	unsigned long nBytesReturned;

	if (WSAIoctl(sd, SIO_GET_INTERFACE_LIST, 0, 0, &InterfaceList, sizeof(InterfaceList), &nBytesReturned, 0, 0) == SOCKET_ERROR)
		return;

	int nNumInterfaces = nBytesReturned / sizeof(INTERFACE_INFO);

	for (int i = 0; i < nNumInterfaces; ++i)
	{
		sockaddr_in *pAddress = (sockaddr_in*)&(InterfaceList[i].iiAddress);
		u_long nFlags = InterfaceList[i].iiFlags;

		//		if (!((nFlags & IFF_POINTTOPOINT)))
		if (!((nFlags & IFF_POINTTOPOINT) || (nFlags & IFF_LOOPBACK)))
		{
			addServer(network->allServers, MAX_SERVERS, pAddress->sin_addr.s_addr);
		}
	}

	closesocket(sd);

	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter;

	pAdapterInfo = (IP_ADAPTER_INFO*) calloc(1, sizeof(IP_ADAPTER_INFO));
	DWORD ulOutBufLen = sizeof(IP_ADAPTER_INFO);

	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
	{
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO*)calloc(1, ulOutBufLen);
	}

	if ((GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR)
	{
		pAdapter = pAdapterInfo;
		while (pAdapter)
		{
			if (!pAdapter->DhcpEnabled)
			{
				IP_ADDR_STRING *sList = &pAdapter->IpAddressList;
				while (sList)
				{
					_DWord iaddr = inet_addr(sList->IpAddress.String);

					if (iaddr)
					{
						for (_Byte k = 0; k < MAX_SERVERS; k++)
						{
							if (network->staticServers[k] == iaddr)
								break;
							else if (!network->staticServers[k])
							{
								network->staticServers[k] = iaddr;
								network->staticMasks[k] = inet_addr(sList->IpMask.String);
								break;
							}
						}
					}
					sList = sList->Next;
				}

//				IP_ADDR_STRING *rList = &pAdapter->GatewayList;
//				while (rList)
//				{
//					_DWord trouter = inet_addr(rList->IpAddress.String);
//					addServer(config.routers, trouter);
//					rList = rList->Next;
//				}
			}
			pAdapter = pAdapter->Next;
		}
		free(pAdapterInfo);
	}

	if (config.specifiedServers[0])
	{
		for (_Byte i = 0; i < MAX_SERVERS && config.specifiedServers[i]; i++)
		{
			_Byte j = 0;

			for (; j < MAX_SERVERS && network->staticServers[j]; j++)
			{
				if (network->staticServers[j] == config.specifiedServers[i])
				{
					_Byte k = addServer(network->listenServers, MAX_SERVERS, network->staticServers[j]);

					if (k < MAX_SERVERS)
						network->listenMasks[k] = network->staticMasks[j];

					break;
				}
			}

			if (j == MAX_SERVERS || !network->staticServers[j])
			{
				if (findServer(network->allServers, MAX_SERVERS, config.specifiedServers[i]))
					sprintf(logBuff, "Warning: Section [LISTEN_ON] Interface %s is not static, ignored", IP2String(ipbuff, config.specifiedServers[i]));
				else
					sprintf(logBuff, "Warning: Section [LISTEN_ON] Interface %s is not found, ignored", IP2String(ipbuff, config.specifiedServers[i]));

				logMessage(logBuff, 2);
			}
		}
	}
	else
	{
		for (_Byte i = 0; i < MAX_SERVERS && network->allServers[i]; i++)
		{
			_Byte j = 0;

			for (; j < MAX_SERVERS && network->staticServers[j]; j++)
			{
				if (network->staticServers[j] == network->allServers[i])
				{
					_Byte k = addServer(network->listenServers, MAX_SERVERS, network->staticServers[j]);

					if (k < MAX_SERVERS)
						network->listenMasks[k] = network->staticMasks[j];

					break;
				}
			}

			if (j == MAX_SERVERS || !network->staticServers[j])
			{
				sprintf(logBuff, "Warning: Interface %s is not Static, ignored", IP2String(ipbuff, network->allServers[i]));
				logMessage(logBuff, 2);
			}
		}
	}

	FIXED_INFO *FixedInfo;
	IP_ADDR_STRING *pIPAddr;

	FixedInfo = (FIXED_INFO*)GlobalAlloc(GPTR, sizeof(FIXED_INFO));
	ulOutBufLen = sizeof(FIXED_INFO);

	if (ERROR_BUFFER_OVERFLOW == GetNetworkParams(FixedInfo, &ulOutBufLen))
	{
		GlobalFree(FixedInfo);
		FixedInfo = (FIXED_INFO*)GlobalAlloc(GPTR, ulOutBufLen);
	}

	if (!GetNetworkParams(FixedInfo, &ulOutBufLen))
	{
		if (!config.servername[0])
			strcpy(config.servername, FixedInfo->HostName);

		//printf("d=%u=%s", strlen(FixedInfo->DomainName), FixedInfo->DomainName);

		if (!config.zone[0])
		{
			strcpy(config.zone, FixedInfo->DomainName);
			config.zLen = strlen(config.zone);
		}

		if (!config.zone[0] || config.zone[0] == NBSP)
		{
			strcpy(config.zone, "workgroup");
			config.zLen = strlen(config.zone);
		}

		if (!config.specifiedDNSServers[0])
		{
			pIPAddr = &FixedInfo->DnsServerList;

			while (pIPAddr)
			{
				_DWord addr = inet_addr(pIPAddr->IpAddress.String);

				if (!DNSService || !findServer(network->allServers, MAX_SERVERS, addr))
					addServer(network->DNS, MAX_SERVERS, addr);

				pIPAddr = pIPAddr->Next;
			}
		}
		GlobalFree(FixedInfo);
	}

	for (int i = 0; i < MAX_SERVERS && config.specifiedDNSServers[i]; i++)
	{
		if (!DNSService || !findServer(network->allServers, MAX_SERVERS, config.specifiedDNSServers[i]))
			addServer(network->DNS, MAX_SERVERS, config.specifiedDNSServers[i]);
	}
	return;
}

void __cdecl updateStateFile(void *lpParam)
{
	CachedData *dhcpEntry = (CachedData*)lpParam;
	DHCPClient dhcpData;
	memset(&dhcpData, 0, sizeof(DHCPClient));
	dhcpData.bp_hlen = 16;
	getHexValue(dhcpData.bp_chaddr, dhcpEntry->mapname, &dhcpData.bp_hlen);
	dhcpData.ip = dhcpEntry->ip;
	dhcpData.expiry = dhcpEntry->expiry;
	dhcpData.local = dhcpEntry->local;
	strcpy(dhcpData.hostname, dhcpEntry->hostname);
	WaitForSingleObject(fEvent, INFINITE);

	if (dhcpEntry->dhcpInd)
	{
		dhcpData.dhcpInd = dhcpEntry->dhcpInd;
		FILE *f = fopen(leaFile, "rb+");

		if (f)
		{
			if (fseek(f, (dhcpData.dhcpInd - 1)*sizeof(DHCPClient), SEEK_SET) >= 0)
				fwrite(&dhcpData, sizeof(DHCPClient), 1, f);

			fclose(f);
		}
	}
	else
	{
		config.dhcpInd++;
		dhcpEntry->dhcpInd = config.dhcpInd;
		dhcpData.dhcpInd = config.dhcpInd;
		FILE *f = fopen(leaFile, "ab");

		if (f)
		{
			fwrite(&dhcpData, sizeof(DHCPClient), 1, f);
			fclose(f);
		}
	}

	SetEvent(fEvent);
	_endthread();
	return;
}

_Word gdmess(DHCPRequest *req, _Byte sockInd)
{
	//debug("gdmess");
	char ipbuff[32];
	char logBuff[512];
	memset(req, 0, sizeof(DHCPRequest));
	req->sockInd = sockInd;
	req->sockLen = sizeof(req->remote);
	errno = 0;

	req->bytes = recvfrom(network.dhcpConn[req->sockInd].sock,
	                      req->raw,
	                      sizeof(req->raw),
	                      0,
	                      (sockaddr*)&req->remote,
	                      &req->sockLen);

	//printf("IP=%s bytes=%u\n", IP2String(ipbuff,req->remote.sin_addr.s_addr), req->bytes);

	errno = WSAGetLastError();

	//printf("errno=%u\n", errno);

	if (errno || req->bytes <= 0 || req->DHCPPacket.header.bp_op != BOOTP_REQUEST)
		return 0;

	hex2String(req->chaddr, req->DHCPPacket.header.bp_chaddr, req->DHCPPacket.header.bp_hlen);

	data3 *op;
	_Byte *raw = req->DHCPPacket.vend_data;
	_Byte *rawEnd = raw + (req->bytes - sizeof(DHCPHeader));

	for (; raw < rawEnd && *raw != DHCP_OPTION_END;)
	{
		op = (data3*)raw;
		//printf("OpCode=%u,MessType=%u\n", op->opt_code, op->value[0]);

		switch (op->opt_code)
		{
			case DHCP_OPTION_PAD:
				raw++;
				continue;

			case DHCP_OPTION_PARAMREQLIST:
				for (int ix = 0; ix < op->size; ix++)
					req->paramreqlist[op->value[ix]] = 1;
				break;

			case DHCP_OPTION_MESSAGETYPE:
				req->req_type = op->value[0];
				break;

			case DHCP_OPTION_SERVERID:
				req->server = fIP(op->value);
				break;

			case DHCP_OPTION_IPADDRLEASE:
				req->lease = fULong(op->value);
				break;

			case DHCP_OPTION_MAXDHCPMSGSIZE:
				req->messsize = fUShort(op->value);
				break;

			case DHCP_OPTION_REQUESTEDIPADDR:
				req->requestIP = fIP(op->value);
				break;

			case DHCP_OPTION_HOSTNAME:
				memcpy(req->hostname, op->value, op->size);
				req->hostname[op->size] = 0;
				req->hostname[64] = 0;

				if (char *ptr = strchr(req->hostname, '.'))
					*ptr = 0;

				break;

			case DHCP_OPTION_VENDORCLASSID:
				memcpy(&req->vendClass, op, op->size + 2);
				break;

			case DHCP_OPTION_USERCLASS:
				memcpy(&req->userClass, op, op->size + 2);
				break;

			case DHCP_OPTION_RELAYAGENTINFO:
				memcpy(&req->agentOption, op, op->size + 2);
				break;

			case DHCP_OPTION_CLIENTID:
				memcpy(&req->clientId, op, op->size + 2);
				break;

			case DHCP_OPTION_SUBNETSELECTION:
				memcpy(&req->subnet, op, op->size + 2);
				req->subnetIP = fULong(op->value);
				break;

			case DHCP_OPTION_DNS:
				req->DNS = fULong(op->value);
				break;

			case DHCP_OPTION_REBINDINGTIME:
				req->rebind = fULong(op->value);
				break;
		}
		raw += 2;
		raw += op->size;
	}

	if (!req->subnetIP)
	{
		if (req->DHCPPacket.header.bp_giaddr)
			req->subnetIP = req->DHCPPacket.header.bp_giaddr;
		else
			req->subnetIP = network.dhcpConn[req->sockInd].server;
	}

	if (!req->messsize)
	{
		if (req->req_type == DHCP_MESS_NONE)
			req->messsize = req->bytes;
		else
			req->messsize = sizeof(DHCPPacket);
	}

//	if (!req->hostname[0] && req->DHCPPacket.header.bp_ciaddr)
//	{
//		CachedData* cache = findEntry(IP2String(ipbuff, htonl(req->DHCPPacket.header.bp_ciaddr)), DNS_TYPE_PTR);
//
//		if (cache)
//			strcpy(req->hostname, cache->hostname);
//	}
//
//	if ((req->req_type == 1 || req->req_type == 3) && config.dhcpLogLevel == 3)
//	{
//		DHCPRequest *req1 = (DHCPRequest*)calloc(1, sizeof(DHCPRequest));
//		memcpy(req1, req, sizeof(DHCPRequest));
//		_beginthread(logDebug, 0, req1);
//	}

	if (verbatim || config.dhcpLogLevel >= 2)
	{
		if (req->req_type == DHCP_MESS_NONE)
		{
			if (req->DHCPPacket.header.bp_giaddr)
				sprintf(logBuff, "BOOTPREQUEST for %s (%s) from RelayAgent %s received", req->chaddr, req->hostname, IP2String(ipbuff, req->DHCPPacket.header.bp_giaddr));
			else
				sprintf(logBuff, "BOOTPREQUEST for %s (%s) from interface %s received", req->chaddr, req->hostname, IP2String(ipbuff, network.dhcpConn[req->sockInd].server));

			logDHCPMessage(logBuff, 2);
		}
		else if (req->req_type == DHCP_MESS_DISCOVER)
		{
			if (req->DHCPPacket.header.bp_giaddr)
				sprintf(logBuff, "DHCPDISCOVER for %s (%s) from RelayAgent %s received", req->chaddr, req->hostname, IP2String(ipbuff, req->DHCPPacket.header.bp_giaddr));
			else
				sprintf(logBuff, "DHCPDISCOVER for %s (%s) from interface %s received", req->chaddr, req->hostname, IP2String(ipbuff, network.dhcpConn[req->sockInd].server));

			logDHCPMessage(logBuff, 2);
		}
		else if (req->req_type == DHCP_MESS_REQUEST)
		{
			if (req->DHCPPacket.header.bp_giaddr)
				sprintf(logBuff, "DHCPREQUEST for %s (%s) from RelayAgent %s received", req->chaddr, req->hostname, IP2String(ipbuff, req->DHCPPacket.header.bp_giaddr));
			else
				sprintf(logBuff, "DHCPREQUEST for %s (%s) from interface %s received", req->chaddr, req->hostname, IP2String(ipbuff, network.dhcpConn[req->sockInd].server));

			logDHCPMessage(logBuff, 2);
		}
	}

	req->vp = req->DHCPPacket.vend_data;
	memset(req->vp, 0, sizeof(DHCPPacket) - sizeof(DHCPHeader));
	//printf("end bytes=%u\n", req->bytes);

	return 1;
}

void debug(int i)
{
	char t[254];
	sprintf(t, "%i", i);
	logMessage(t, 1);
}

void debug(const char *mess)
{
	char t[254];
	strcpy(t, mess);
	logMessage(t, 1);
}

void logDirect(char *mess)
{
	tm *ttm = localtime(&t);
	char buffer[_MAX_PATH];
	strftime(buffer, sizeof(buffer), logFile, ttm);

	if (strcmp(config.logFileName, buffer))
	{
		if (config.logFileName[0])
		{
			FILE *f = fopen(config.logFileName, "at");

			if (f)
			{
				fprintf(f, "Logging Continued on file %s\n", buffer);
				fclose(f);
			}

			strcpy(config.logFileName, buffer);
			f = fopen(config.logFileName, "at");

			if (f)
			{
				fprintf(f, "%s\n\n", sVersion);
				fclose(f);
			}
		}

		strcpy(config.logFileName, buffer);
		WritePrivateProfileString("InternetShortcut","URL", buffer, lnkFile);
		WritePrivateProfileString("InternetShortcut","IconIndex", "0", lnkFile);
		WritePrivateProfileString("InternetShortcut","IconFile", buffer, lnkFile);
	}

	FILE *f = fopen(config.logFileName, "at");

	if (f)
	{
		strftime(buffer, sizeof(buffer), "%d-%b-%y %X", ttm);
		fprintf(f, "[%s] %s\n", buffer, mess);
		fclose(f);
	}
	else
	{
		config.dnsLogLevel = 0;
		config.dhcpLogLevel = 0;
	}

	return;
}

void __cdecl logThread(void *lpParam)
{
	WaitForSingleObject(lEvent, INFINITE);
	char *mess = (char*)lpParam;
	time_t t = time(NULL);
	tm *ttm = localtime(&t);
	char buffer[_MAX_PATH];
	strftime(buffer, sizeof(buffer), logFile, ttm);

	if (strcmp(config.logFileName, buffer))
	{
		if (config.logFileName[0])
		{
			FILE *f = fopen(config.logFileName, "at");

			if (f)
			{
				fprintf(f, "Logging Continued on file %s\n", buffer);
				fclose(f);
			}

			strcpy(config.logFileName, buffer);
			f = fopen(config.logFileName, "at");

			if (f)
			{
				fprintf(f, "%s\n\n", sVersion);
				fclose(f);
			}
		}

		strcpy(config.logFileName, buffer);
		WritePrivateProfileString("InternetShortcut","URL", buffer, lnkFile);
		WritePrivateProfileString("InternetShortcut","IconIndex", "0", lnkFile);
		WritePrivateProfileString("InternetShortcut","IconFile", buffer, lnkFile);
	}

	FILE *f = fopen(config.logFileName, "at");

	if (f)
	{
		strftime(buffer, sizeof(buffer), "%d-%b-%y %X", ttm);
		fprintf(f, "[%s] %s\n", buffer, mess);
		fclose(f);
	}
	else
	{
		config.dnsLogLevel = 0;
		config.dhcpLogLevel = 0;
	}

	free(mess);
	SetEvent(lEvent);

	_endthread();
	return;
}

/*
void __cdecl logDebug(void *lpParam)
{
	char localBuff[1024];
	char localreq->extbuff[256];
	DHCPRequest *req = (DHCPRequest*)lpParam;
	genHostName(localBuff, req->DHCPPacket.header.bp_chaddr, req->DHCPPacket.header.bp_hlen);
	sprintf(localreq->extbuff, cliFile, localBuff);
	FILE *f = fopen(localreq->extbuff, "at");

	if (f)
	{
		tm *ttm = localtime(&t);
		strftime(localreq->extbuff, sizeof(localreq->extbuff), "%d-%m-%y %X", ttm);

		char *s = localBuff;
		s += sprintf(s, localreq->extbuff);
		s += sprintf(s, " SourceMac=%s", req->chaddr);
		s += sprintf(s, " ClientIP=%s", IP2String(localreq->extbuff, req->DHCPPacket.header.bp_ciaddr));
		s += sprintf(s, " SourceIP=%s", IP2String(localreq->extbuff, req->remote.sin_addr.s_addr));
		s += sprintf(s, " RelayAgent=%s", IP2String(localreq->extbuff, req->DHCPPacket.header.bp_giaddr));
		fprintf(f, "%s\n", localBuff);

		data3 *op;
		_Byte *raw = req->DHCPPacket.vend_data;
		_Byte *rawEnd = raw + (req->bytes - sizeof(DHCPHeader));
		_Byte maxInd = sizeof(opData) / sizeof(data4);

		for (; raw < rawEnd && *raw != DHCP_OPTION_END;)
		{
			op = (data3*)raw;

			BYTE opType = 2;
			char opName[40] = "Private";

			for (_Byte i = 0; i < maxInd; i++)
				if (op->opt_code == opData[i].opTag)
				{
					strcpy(opName, opData[i].opName);
					opType = opData[i].opType;
					break;
				}

			s = localBuff;
			s += sprintf(s, "\t%d\t%s\t", op->opt_code, opName);
			//printf("OpCode=%u,OpLen=%u,OpType=%u\n", op->opt_code, op->size, opType);

			switch (opType)
			{
				case 1:
					memcpy(localreq->extbuff, op->value, op->size);
					localreq->extbuff[op->size] = 0;
					sprintf(s, "%s", localreq->extbuff);
					break;
				case 3:
					for (BYTE x = 4; x <= op->size; x += 4)
					{
						IP2String(localreq->extbuff, fIP(op->value));
						s += sprintf(s, "%s,", localreq->extbuff);
					}
					break;
				case 4:
					sprintf(s, "%u", fULong(op->value));
					break;
				case 5:
					sprintf(s, "%u", fUShort(op->value));
					break;
				case 6:
				case 7:
					sprintf(s, "%u", op->value[0]);
					break;
				default:
					if (op->size == 1)
						sprintf(s, "%u", op->value[0]);
					else
						hex2String(s, op->value, op->size);
					break;
			}

			fprintf(f, "%s\n", localBuff);
			raw += 2;
			raw += op->size;
		}
		fclose(f);
	}
	free(req);
}
*/

void logMessage(char *logBuff, _Byte logLevel)
{
	if (verbatim)
		printf("%s\n", logBuff);

	if (logLevel <= config.dnsLogLevel || logLevel <= config.dhcpLogLevel)
	{
		char *mess = cloneString(logBuff);
		_beginthread(logThread, 0, mess);
	}
}

void logDHCPMessage(char *logBuff, _Byte logLevel)
{
	if (verbatim)
		printf("%s\n", logBuff);

	if (logLevel <= config.dhcpLogLevel)
	{
		char *mess = cloneString(logBuff);
		_beginthread(logThread, 0, mess);
	}
}

void logDNSMessage(char *logBuff, _Byte logLevel)
{
	if (verbatim)
		printf("%s\n", logBuff);

	if (logLevel <= config.dnsLogLevel)
	{
		char *mess = cloneString(logBuff);
		_beginthread(logThread, 0, mess);
	}
}

void logDNSMessage(DNSRequest *req, char *logBuff, _Byte logLevel)
{
	if (verbatim)
		printf("%s\n", logBuff);

	if (logLevel <= config.dnsLogLevel)
	{
		char *mess = (char*)calloc(1, 512);
		sprintf(mess, "Client %s, %s", inet_ntoa(req->remote.sin_addr), logBuff);
		_beginthread(logThread, 0, mess);
	}
}

void logTCPMessage(DNSRequest *req, char *logBuff, _Byte logLevel)
{
	if (verbatim)
		printf("%s\n", logBuff);

	if (logLevel <= config.dnsLogLevel)
	{
		char *mess = (char*)calloc(1, 512);
		sprintf(mess, "TCP Client %s, %s", inet_ntoa(req->remote.sin_addr), logBuff);
		_beginthread(logThread, 0, mess);
	}
}

CachedData *createCache(Lump *lump)
{
	_Word dataSize = 4 + sizeof(CachedData) + strlen(lump->mapname);
	CachedData *cache = NULL;

	switch (lump->cType)
	{
		case CTYPE_DHCP_ENTRY:
		{
			dataSize += 64;
			dataSize += lump->optionSize;
			cache = (CachedData*)calloc(1, dataSize);

			if (!cache)
				return NULL;

			_Byte *dp = &cache->data;
			cache->mapname = (char*)dp;
			strcpy(cache->mapname, lump->mapname);
			myLower(cache->mapname);
			dp += strlen(cache->mapname);
			dp++;
			cache->hostname = (char*)dp;

			if (lump->hostname)
				strcpy(cache->hostname, lump->hostname);

			dp += 65;

			if (lump->optionSize >= 5)
			{
				cache->options = dp;
				memcpy(cache->options, lump->options, lump->optionSize);
			}
			break;
		}

		case CTYPE_QUEUE:
		{
			//debug("about to create queue");
			dataSize += strlen(lump->query);
			dataSize +=  sizeof(SOCKADDR_IN);
			cache = (CachedData*)calloc(1, dataSize);

			if (!cache)
				return NULL;

			cache->cType = lump->cType;
			cache->dnsType = lump->dnsType;
			_Byte *dp = &cache->data;
			cache->mapname = (char*)dp;
			cache->name = (char*)dp;
			strcpy(cache->mapname, lump->mapname);
			//myLower(cache->mapname);
			dp += strlen(cache->mapname);
			dp++;
			cache->query = (char*)dp;
			strcpy(cache->query, lump->query);
			//debug(cache->query);
			//debug(strlen(cache->query));
			dp += strlen(cache->query);
			dp++;
			//debug((int)lump->addr);
			cache->addr = (SOCKADDR_IN*)dp;
			memcpy(cache->addr, lump->addr, sizeof(SOCKADDR_IN));
			//debug("done create queue");
			break;
		}

		case CTYPE_CACHED:
		{
			dataSize += lump->bytes;
			cache = (CachedData*)calloc(1, dataSize);

			if (!cache)
				return NULL;

			cache->cType = lump->cType;
			cache->dnsType = lump->dnsType;
			_Byte *dp = &cache->data;
			cache->mapname = (char*)dp;
			setMapName(cache->mapname, lump->mapname, lump->dnsType);
			dp++;
			cache->name = (char*)dp;
			dp += strlen(lump->mapname);
			dp++;
			cache->response = dp;
			cache->bytes = lump->bytes;
			memcpy(cache->response, lump->response, cache->bytes);
			break;
		}

		case CTYPE_LOCAL_PTR_AUTH:
		case CTYPE_LOCAL_PTR_NAUTH:
		case CTYPE_LOCALHOST_PTR:
		case CTYPE_SERVER_PTR_AUTH:
		case CTYPE_SERVER_PTR_NAUTH:
		case CTYPE_STATIC_PTR_AUTH:
		case CTYPE_STATIC_PTR_NAUTH:
		case CTYPE_LOCAL_CNAME:
		case CTYPE_EXT_CNAME:
		{
			dataSize += strlen(lump->hostname);
			cache = (CachedData*)calloc(1, dataSize);

			if (!cache)
				return NULL;

			cache->cType = lump->cType;
			cache->dnsType = lump->dnsType;
			_Byte *dp = &cache->data;
			cache->mapname = (char*)dp;
			setMapName(cache->mapname, lump->mapname, lump->dnsType);
			dp++;
			cache->name = (char*)dp;
			dp += strlen(lump->mapname);
			dp++;
			cache->hostname = (char*)dp;
			strcpy(cache->hostname, lump->hostname);
			break;
		}

		default:
		{
			cache = (CachedData*)calloc(1, dataSize);

			if (!cache)
				return NULL;

			cache->cType = lump->cType;
			cache->dnsType = lump->dnsType;
			_Byte *dp = &cache->data;
			cache->mapname = (char*)dp;
			setMapName(cache->mapname, lump->mapname, lump->dnsType);
			dp++;
			cache->name = (char*)dp;
			break;
		}
	}

	//sprintf(logBuff, "New Cache cType=%d dnsType=%u name=%s", cache->cType, cache->dnsType, cache->name);
	//logMessage(logBuff, 1);
	return cache;
}
