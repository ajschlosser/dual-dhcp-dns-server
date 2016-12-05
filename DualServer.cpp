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
//data1 network;
data1 network;
data2 cfig;
data9 token;
data9 dhcpr;
data5 dnsr;
data71 lump;
data18 magin;
MYBYTE currentInd = 0;
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
bool dnsService = true;
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
//const char send200[] = "HTTP/1.1 200 OK\r\nDate: %s\r\nLast-Modified: %s\r\nContent-Type: text/html\r\nConnection: Close\r\nTransfer-Encoding: chunked\r\n";
//const char send403[] = "HTTP/1.1 403 Forbidden\r\nDate: %s\r\nLast-Modified: %s\r\nContent-Type: text/html\r\nConnection: Close\r\n\r\n";
const char send403[] = "HTTP/1.1 403 Forbidden\r\n\r\n<h1>403 Forbidden</h1>";
const char send404[] = "HTTP/1.1 404 Not Found\r\n\r\n<h1>404 Not Found</h1>";
const char td200[] = "<td>%s</td>";
const char sVersion[] = "Dual DHCP DNS Server Version 7.29 Windows Build 7035";
const char htmlStart[] = "<html>\n<head>\n<title>%s</title><meta http-equiv=\"refresh\" content=\"60\">\n<meta http-equiv=\"cache-control\" content=\"no-cache\">\n</head>\n";
//const char bodyStart[] = "<body bgcolor=\"#cccccc\"><table width=\"800\"><tr><td align=\"center\"><font size=\"5\"><b>%s</b></font></b></b></td></tr><tr><td align=\"right\"><a target=\"_new\" href=\"http://dhcp-dns-server.sourceforge.net/\">http://dhcp-dns-server.sourceforge.net/</b></b></td></tr></table>";
const char bodyStart[] = "<body bgcolor=\"#cccccc\"><table width=640><tr><td align=\"center\"><font size=\"5\"><b>%s</b></font></td></tr><tr><td align=\"right\"><a target=\"_new\" href=\"http://dhcp-dns-server.sourceforge.net\">http://dhcp-dns-server.sourceforge.net</td></tr></table>";
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
			if (verbatim || cfig.dnsLogLevel || cfig.dhcpLogLevel)
			{
				sprintf(logBuff, "Thread Creation Failed");
				logMess(logBuff, 1);
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

			if (!network.dhcpConn[0].ready && !network.dnsUdpConn[0].ready)
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
				if (network.httpConn.ready)
					FD_SET(network.httpConn.sock, &readfds);

				for (int i = 0; i < MAX_SERVERS && network.dhcpConn[i].ready; i++)
					FD_SET(network.dhcpConn[i].sock, &readfds);

				if (cfig.dhcpReplConn.ready)
					FD_SET(cfig.dhcpReplConn.sock, &readfds);
			}

			if (dnsService)
			{
				for (int i = 0; i < MAX_SERVERS && network.dnsUdpConn[i].ready; i++)
					FD_SET(network.dnsUdpConn[i].sock, &readfds);

				for (int i = 0; i < MAX_SERVERS && network.dnsTcpConn[i].ready; i++)
					FD_SET(network.dnsTcpConn[i].sock, &readfds);

				if (network.forwConn.ready)
					FD_SET(network.forwConn.sock, &readfds);
			}

			if (select(network.maxFD, &readfds, NULL, NULL, &tv))
			{
				t = time(NULL);

				if (dhcpService)
				{
					if (network.httpConn.ready && FD_ISSET(network.httpConn.sock, &readfds))
					{
						data19 *req = (data19*)calloc(1, sizeof(data19));

						if (req)
						{
							req->sockLen = sizeof(req->remote);
							req->sock = accept(network.httpConn.sock, (sockaddr*)&req->remote, &req->sockLen);
							errno = WSAGetLastError();

							if (errno || req->sock == INVALID_SOCKET)
							{
								sprintf(logBuff, "Accept Failed, WSAError %u", errno);
								logDHCPMess(logBuff, 1);
								free(req);
							}
							else
								procHTTP(req);
						}
						else
						{
							sprintf(logBuff, "Memory Error");
							logDHCPMess(logBuff, 1);
						}
					}

					if (cfig.dhcpReplConn.ready && FD_ISSET(cfig.dhcpReplConn.sock, &readfds))
					{
						errno = 0;
						dhcpr.sockLen = sizeof(dhcpr.remote);

						dhcpr.bytes = recvfrom(cfig.dhcpReplConn.sock,
											   dhcpr.raw,
											   sizeof(dhcpr.raw),
											   0,
											   (sockaddr*)&dhcpr.remote,
											   &dhcpr.sockLen);

						errno = WSAGetLastError();

						if (errno || dhcpr.bytes <= 0)
							cfig.dhcpRepl = 0;
					}

					for (int i = 0; i < MAX_SERVERS && network.dhcpConn[i].ready; i++)
					{
						if (FD_ISSET(network.dhcpConn[i].sock, &readfds) && gdmess(&dhcpr, i) && sdmess(&dhcpr))
							alad(&dhcpr);
					}
				}

				if (dnsService)
				{
					for (int i = 0; i < MAX_SERVERS && network.dnsUdpConn[i].ready; i++)
					{
						if (FD_ISSET(network.dnsUdpConn[i].sock, &readfds))
						{
							if (gdnmess(&dnsr, i))
							{
								if (scanloc(&dnsr))
								{
									if (dnsr.dnsp->header.ancount)
									{
										if (verbatim || cfig.dnsLogLevel >= 2)
										{
											if (dnsr.dnsType == DNS_TYPE_SOA)
												sprintf(logBuff, "SOA Sent for zone %s", dnsr.query);
											else if (dnsr.dnsType == DNS_TYPE_NS)
												sprintf(logBuff, "NS Sent for zone %s", dnsr.query);
											else if (dnsr.cType == CTYPE_CACHED)
												sprintf(logBuff, "%s resolved from Cache to %s", strquery(&dnsr), getResult(&dnsr));
											else
												sprintf(logBuff, "%s resolved Locally to %s", strquery(&dnsr), getResult(&dnsr));

											logDNSMess(&dnsr, logBuff, 2);
										}
									}
 									else if (dnsr.dnsp->header.rcode == RCODE_NOERROR)
 									{
										dnsr.dnsp->header.rcode = RCODE_NAMEERROR;

										if (verbatim || cfig.dnsLogLevel >= 2)
										{
											sprintf(logBuff, "%s not found", strquery(&dnsr));
											logDNSMess(&dnsr, logBuff, 2);
										}
									}
									sdnmess(&dnsr);
								}
								else if (!fdnmess(&dnsr))
								{
									if (!dnsr.dnsp->header.ancount && (dnsr.dnsp->header.rcode == RCODE_NOERROR || dnsr.dnsp->header.rcode == RCODE_NAMEERROR))
									{
										dnsr.dnsp->header.rcode = RCODE_NAMEERROR;

										if (verbatim || cfig.dnsLogLevel >= 2)
										{
											sprintf(logBuff, "%s not found", strquery(&dnsr));
											logDNSMess(&dnsr, logBuff, 2);
										}
									}
									sdnmess(&dnsr);
								}
							}
							else if (dnsr.dnsp)
								sdnmess(&dnsr);
						}
					}

					for (int i = 0; i < MAX_SERVERS && network.dnsTcpConn[i].ready; i++)
					{
						if (FD_ISSET(network.dnsTcpConn[i].sock, &readfds))
						{
							dnsr.sockInd = i;
							dnsr.sockLen = sizeof(dnsr.remote);
							errno = 0;
							dnsr.sock = accept(network.dnsTcpConn[i].sock, (sockaddr*)&dnsr.remote, &dnsr.sockLen);
							errno = WSAGetLastError();

							if (dnsr.sock == INVALID_SOCKET || errno)
							{
								if (verbatim || cfig.dnsLogLevel)
								{
									sprintf(logBuff, "Accept Failed, WSAError=%u", errno);
									logDNSMess(logBuff, 1);
								}
							}
							else
								procTCP(&dnsr);
						}
					}

					if (network.forwConn.ready && FD_ISSET(network.forwConn.sock, &readfds))
					{
						if (frdnmess(&dnsr))
						{
							sdnmess(&dnsr);

							if (verbatim || cfig.dnsLogLevel >= 2)
							{
								if (dnsr.dnsIndex < MAX_SERVERS)
								{
									if (dnsr.dnsp->header.ancount)
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
									if (dnsr.dnsp->header.ancount)
									{
										if (getResult(&dnsr))
											sprintf(logBuff, "%s resolved from Conditional Forwarder as %s", strquery(&dnsr), dnsr.tempname);
										else
											sprintf(logBuff, "%s resolved from Conditional Forwarder", strquery(&dnsr));
									}
									else
										sprintf(logBuff, "%s not found by Conditional Forwarder", strquery(&dnsr));
								}

								logDNSMess(&dnsr, logBuff, 2);
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
				//logMess(logBuff, 2);
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
		logMess(logBuff, 1);
		closeConn();

        if (cfig.dhcpReplConn.ready)
            closesocket(cfig.dhcpReplConn.sock);

		sprintf(logBuff, "Dual Server Stopped !\n");
		logMess(logBuff, 1);

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
		if (network.httpConn.ready)
			closesocket(network.httpConn.sock);

        for (int i = 0; i < MAX_SERVERS && network.dhcpConn[i].loaded; i++)
        	if (network.dhcpConn[i].ready)
            	closesocket(network.dhcpConn[i].sock);
    }

    if (dnsService)
    {
        for (int i = 0; i < MAX_SERVERS && network.dnsUdpConn[i].loaded; i++)
        	if (network.dnsUdpConn[i].ready)
           		closesocket(network.dnsUdpConn[i].sock);

        for (int i = 0; i < MAX_SERVERS && network.dnsTcpConn[i].loaded; i++)
        	if (network.dnsTcpConn[i].ready)
            	closesocket(network.dnsTcpConn[i].sock);

        if (network.forwConn.ready)
        	closesocket(network.forwConn.sock);
    }
}

/*
void closeConn()
{
    if (dhcpService)
    {
		if (network.httpConn.ready)
		{
			closesocket(network.httpConn.sock);
			sprintf(logBuff, "httpConn %s:%u closed", IP2String(ipbuff, network.httpConn.server), network.httpConn.port);
			logMess(logBuff, 1);
		}

        for (int i = 0; i < MAX_SERVERS && network.dhcpConn[i].loaded; i++)
        	if (network.dhcpConn[i].ready)
        	{
            	closesocket(network.dhcpConn[i].sock);
				sprintf(logBuff, "dhcpConn[%u] %s:%u closed", i, IP2String(ipbuff, network.dhcpConn[i].server), network.dhcpConn[i].port);
				logMess(logBuff, 1);
			}
    }

    if (dnsService)
    {
        for (int i = 0; i < MAX_SERVERS && network.dnsUdpConn[i].loaded; i++)
        	if (network.dnsUdpConn[i].ready)
        	{
           		closesocket(network.dnsUdpConn[i].sock);
				sprintf(logBuff, "dnsUdpConn %s:%u closed", IP2String(ipbuff, network.dnsUdpConn[i].server), network.dnsUdpConn[i].port);
				logMess(logBuff, 1);
			}

        for (int i = 0; i < MAX_SERVERS && network.dnsTcpConn[i].loaded; i++)
        	if (network.dnsTcpConn[i].ready)
        	{
            	closesocket(network.dnsTcpConn[i].sock);
				sprintf(logBuff, "dnsTcpConn %s:%u closed", IP2String(ipbuff, network.dnsTcpConn[i].server), network.dnsTcpConn[i].port);
				logMess(logBuff, 1);
			}

        if (network.forwConn.ready)
        {
        	closesocket(network.forwConn.sock);
			sprintf(logBuff, "forwConn %s:%u closed", IP2String(ipbuff, network.forwConn.server), network.forwConn.port);
			logMess(logBuff, 1);
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

void showError(MYDWORD enumber)
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
		if (verbatim || cfig.dnsLogLevel || cfig.dhcpLogLevel)
		{
			sprintf(logBuff, "Thread Creation Failed");
			logMess(logBuff, 1);
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

		if (!network.dhcpConn[0].ready && !network.dnsUdpConn[0].ready)
		{
			Sleep(1000);
			network.busy = false;
			continue;
		}

		network.busy = true;

		if (dhcpService)
		{
			if (network.httpConn.ready)
				FD_SET(network.httpConn.sock, &readfds);

			for (int i = 0; i < MAX_SERVERS && network.dhcpConn[i].ready; i++)
				FD_SET(network.dhcpConn[i].sock, &readfds);

			if (cfig.dhcpReplConn.ready)
				FD_SET(cfig.dhcpReplConn.sock, &readfds);
		}

		if (dnsService)
		{
			for (int i = 0; i < MAX_SERVERS && network.dnsUdpConn[i].ready; i++)
				FD_SET(network.dnsUdpConn[i].sock, &readfds);

			for (int i = 0; i < MAX_SERVERS && network.dnsTcpConn[i].ready; i++)
				FD_SET(network.dnsTcpConn[i].sock, &readfds);

			if (network.forwConn.ready)
				FD_SET(network.forwConn.sock, &readfds);
		}

		if (select(network.maxFD, &readfds, NULL, NULL, &tv))
		{
			t = time(NULL);

			if (dhcpService)
			{
				if (network.httpConn.ready && FD_ISSET(network.httpConn.sock, &readfds))
				{
					data19 *req = (data19*)calloc(1, sizeof(data19));

					if (req)
					{
						req->sockLen = sizeof(req->remote);
						req->sock = accept(network.httpConn.sock, (sockaddr*)&req->remote, &req->sockLen);
						errno = WSAGetLastError();

						if (errno || req->sock == INVALID_SOCKET)
						{
							sprintf(logBuff, "Accept Failed, WSAError %u", errno);
							logDHCPMess(logBuff, 1);
							free(req);
						}
						else
							procHTTP(req);
					}
					else
					{
						sprintf(logBuff, "Memory Error");
						logDHCPMess(logBuff, 1);
					}
				}

				if (cfig.dhcpReplConn.ready && FD_ISSET(cfig.dhcpReplConn.sock, &readfds))
				{
					errno = 0;
					dhcpr.sockLen = sizeof(dhcpr.remote);

					dhcpr.bytes = recvfrom(cfig.dhcpReplConn.sock,
										   dhcpr.raw,
										   sizeof(dhcpr.raw),
										   0,
										   (sockaddr*)&dhcpr.remote,
										   &dhcpr.sockLen);

					errno = WSAGetLastError();

					if (errno || dhcpr.bytes <= 0)
						cfig.dhcpRepl = 0;
				}

				for (int i = 0; i < MAX_SERVERS && network.dhcpConn[i].ready; i++)
				{
					if (FD_ISSET(network.dhcpConn[i].sock, &readfds) && gdmess(&dhcpr, i) && sdmess(&dhcpr))
						alad(&dhcpr);
				}
			}

			if (dnsService)
			{
				for (int i = 0; i < MAX_SERVERS && network.dnsUdpConn[i].ready; i++)
				{
					if (FD_ISSET(network.dnsUdpConn[i].sock, &readfds))
					{
						if (gdnmess(&dnsr, i))
						{
							if (scanloc(&dnsr))
							{
								if (dnsr.dnsp->header.ancount)
								{
									if (verbatim || cfig.dnsLogLevel >= 2)
									{
										if (dnsr.dnsType == DNS_TYPE_SOA)
											sprintf(logBuff, "SOA Sent for zone %s", dnsr.query);
										else if (dnsr.dnsType == DNS_TYPE_NS)
											sprintf(logBuff, "NS Sent for zone %s", dnsr.query);
										else if (dnsr.cType == CTYPE_CACHED)
											sprintf(logBuff, "%s resolved from Cache to %s", strquery(&dnsr), getResult(&dnsr));
										else
											sprintf(logBuff, "%s resolved Locally to %s", strquery(&dnsr), getResult(&dnsr));

										logDNSMess(&dnsr, logBuff, 2);
									}
								}
								else if (dnsr.dnsp->header.rcode == RCODE_NOERROR)
								{
									dnsr.dnsp->header.rcode = RCODE_NAMEERROR;

									if (verbatim || cfig.dnsLogLevel >= 2)
									{
										sprintf(logBuff, "%s not found", strquery(&dnsr));
										logDNSMess(&dnsr, logBuff, 2);
									}
								}
								sdnmess(&dnsr);
							}
							else if (!fdnmess(&dnsr))
							{
								if (!dnsr.dnsp->header.ancount && (dnsr.dnsp->header.rcode == RCODE_NOERROR || dnsr.dnsp->header.rcode == RCODE_NAMEERROR))
								{
									dnsr.dnsp->header.rcode = RCODE_NAMEERROR;

									if (verbatim || cfig.dnsLogLevel >= 2)
									{
										sprintf(logBuff, "%s not found", strquery(&dnsr));
										logDNSMess(&dnsr, logBuff, 2);
									}
								}
								sdnmess(&dnsr);
							}
						}
						else if (dnsr.dnsp)
							sdnmess(&dnsr);
					}
				}

				for (int i = 0; i < MAX_SERVERS && network.dnsTcpConn[i].ready; i++)
				{
					if (FD_ISSET(network.dnsTcpConn[i].sock, &readfds))
					{
						dnsr.sockInd = i;
						dnsr.sockLen = sizeof(dnsr.remote);
						errno = 0;
						dnsr.sock = accept(network.dnsTcpConn[i].sock, (sockaddr*)&dnsr.remote, &dnsr.sockLen);
						errno = WSAGetLastError();

						if (dnsr.sock == INVALID_SOCKET || errno)
						{
							if (verbatim || cfig.dnsLogLevel)
							{
								sprintf(logBuff, "Accept Failed, WSAError=%u", errno);
								logDNSMess(logBuff, 1);
							}
						}
						else
							procTCP(&dnsr);
					}
				}

				if (network.forwConn.ready && FD_ISSET(network.forwConn.sock, &readfds))
				{
					if (frdnmess(&dnsr))
					{
						sdnmess(&dnsr);

						if (verbatim || cfig.dnsLogLevel >= 2)
						{
							if (dnsr.dnsIndex < MAX_SERVERS)
							{
								if (dnsr.dnsp->header.ancount)
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
								if (dnsr.dnsp->header.ancount)
								{
									if (getResult(&dnsr))
										sprintf(logBuff, "%s resolved from Conditional Forwarder as %s", strquery(&dnsr), dnsr.tempname);
									else
										sprintf(logBuff, "%s resolved from Conditional Forwarder", strquery(&dnsr));
								}
								else
									sprintf(logBuff, "%s not found by Conditional Forwarder", strquery(&dnsr));
							}

							logDNSMess(&dnsr, logBuff, 2);
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
			//logMess(logBuff, 2);
		}
		else
			checkSize();
	}
	while (kRunning);

	kRunning = false;
    sprintf(logBuff, "Closing Network Connections...");
    logMess(logBuff, 1);
	closeConn();

	if (cfig.dhcpReplConn.ready)
		closesocket(cfig.dhcpReplConn.sock);

    sprintf(logBuff, "Dual Server Stopped !\n");
    logMess(logBuff, 1);

	WSACleanup();
}

bool chkQu(char *query)
{
	if (strlen(query) >= UCHAR_MAX)
		return 0;

	while (true)
	{
		char *dp = strchr(query, '.');
		if (dp)
		{
			MYWORD size = dp - query;
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

MYWORD fQu(char *query, dnsPacket *mess, char *raw)
{
	MYBYTE *xname = (MYBYTE*)query;
	MYBYTE *xraw = (MYBYTE*)raw;
	MYWORD retvalue = 0;
	bool goneout = false;

	while (true)
	{
		MYWORD size = *xraw;
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
			xraw = (MYBYTE*)mess + size;
		}
	}

	*xname = 0;

	if (!goneout)
		retvalue++;

	return retvalue;
}

MYWORD qLen(char *query)
{
	MYWORD fullsize = 1;
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

MYWORD pQu(char *raw, char *query)
{
	MYWORD fullsize = 1;
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

MYWORD fUShort(void *raw)
{
	return ntohs(*((MYWORD*)raw));
}

MYDWORD fULong(void *raw)
{
	return ntohl(*((MYDWORD*)raw));
}

MYDWORD fIP(void *raw)
{
	return(*((MYDWORD*)raw));
}

MYBYTE pUShort(void *raw, MYWORD data)
{
	*((MYWORD*)raw) = htons(data);
	return sizeof(MYWORD);
}

MYBYTE pULong(void *raw, MYDWORD data)
{
	*((MYDWORD*)raw) = htonl(data);
	return sizeof(MYDWORD);
}

MYBYTE pIP(void *raw, MYDWORD data)
{
	*((MYDWORD*)raw) = data;
	return sizeof(MYDWORD);
}

void addRREmpty(data5 *req)
{
	req->dnsp->header.ra = 0;
	req->dnsp->header.at = 0;
	req->dnsp->header.aa = 0;
	req->dnsp->header.qr = 1;
	req->dnsp->header.qdcount = 0;
	req->dnsp->header.ancount = 0;
	req->dnsp->header.nscount = 0;
	req->dnsp->header.adcount = 0;
	req->dp = &req->dnsp->data;
}

void addRRError(data5 *req, MYBYTE rcode)
{
	req->dnsp->header.qr = 1;
	req->dp = req->raw + req->bytes;
	req->dnsp->header.rcode = rcode;
}

void addRRNone(data5 *req)
{
	if (network.dns[0])
		req->dnsp->header.ra = 1;
	else
		req->dnsp->header.ra = 0;

	req->dnsp->header.at = 0;
	req->dnsp->header.aa = 0;

	req->dnsp->header.qr = 1;
	req->dnsp->header.ancount = 0;
	req->dnsp->header.nscount = 0;
	req->dnsp->header.adcount = 0;
}

void addRRExt(data5 *req)
{
	char tempbuff[512];
	char temp[2048];
	//char logBuff[512];
	//sprintf(logBuff, "%s=%s=%i\n", req->cname, req->query, req->bytes);
	//logMess(logBuff, 2);

	if (strcasecmp(req->cname, req->query))
	{
		memcpy(temp, req->raw, req->bytes);
		dnsPacket *input = (dnsPacket*)temp;
		req->dnsp = (dnsPacket*)req->raw;

		req->dnsp->header.aa = 0;
		req->dnsp->header.at = 0;
		req->dnsp->header.qdcount = htons(1);
		req->dnsp->header.ancount = htons(1);

		//manuplate the response
		req->dp = &req->dnsp->data;
		req->dp += pQu(req->dp, req->query);
		req->dp += pUShort(req->dp, DNS_TYPE_A);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pQu(req->dp, req->query);
		req->dp += pUShort(req->dp, DNS_TYPE_CNAME);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, cfig.lease);
		req->dp += pUShort(req->dp, qLen(req->cname));
		req->dp += pQu(req->dp, req->cname);

		char *indp = &input->data;

		for (int i = 1; i <= ntohs(input->header.qdcount); i++)
		{
			indp += fQu(tempbuff, input, indp);
			indp += 4;
		}

		for (int i = 1; i <= ntohs(input->header.ancount); i++)
		{
			indp += fQu(tempbuff, input, indp);
			MYWORD type = fUShort(indp);
			req->dp += pQu(req->dp, tempbuff);
			memcpy(req->dp, indp, 8);
			req->dp += 8;
			indp += 8;
			//indp += 2; //type
			//indp += 2; //class
			//indp += 4; //ttl
			MYWORD zLen = fUShort(indp);
			indp += 2; //datalength

			switch (type)
			{
				case DNS_TYPE_A:
					req->dp += pUShort(req->dp, zLen);
					req->dp += pIP(req->dp, fIP(indp));
					break;
				case DNS_TYPE_CNAME:
					fQu(tempbuff, input, indp);
					MYWORD dl = pQu(req->dp + 2, tempbuff);
					req->dp += pUShort(req->dp, dl);
					req->dp += dl;
					break;
			}

			indp += zLen;
			req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
		}
	}
	else
	{
		req->dnsp = (dnsPacket*)req->raw;
		req->dp = req->raw + req->bytes;
	}
}

void addRRCache(data5 *req, CachedData *cache)
{
	char tempbuff[512];

	if (req->dnsType == DNS_TYPE_A)
	{
		//manuplate the response
		//printf("%s=%s\n", req->cname, req->query);
		dnsPacket *input = (dnsPacket*)cache->response;
		char *indp = &input->data;
		req->dnsp = (dnsPacket*)req->raw;
		req->dp = &req->dnsp->data;

		req->dnsp->header.aa = 0;
		req->dnsp->header.at = 0;
		req->dnsp->header.ancount = 0;
		req->dnsp->header.qdcount = htons(1);

		req->dp = &req->dnsp->data;
		req->dp += pQu(req->dp, req->query);
		req->dp += pUShort(req->dp, req->dnsType);
		req->dp += pUShort(req->dp, req->qclass);

		if(strcasecmp(req->cname, req->query))
		{
			req->dp += pQu(req->dp, req->query);
			req->dp += pUShort(req->dp, DNS_TYPE_CNAME);
			req->dp += pUShort(req->dp, DNS_CLASS_IN);
			req->dp += pULong(req->dp, cfig.lease);
			req->dp += pUShort(req->dp, qLen(req->cname));
			req->dp += pQu(req->dp, req->cname);
			req->dnsp->header.ancount = htons(1);
		}

		for (int i = 1; i <= ntohs(input->header.qdcount); i++)
		{
			indp += fQu(tempbuff, input, indp);
			indp += 4;
		}

		for (int i = 1; i <= ntohs(input->header.ancount); i++)
		{
			indp += fQu(tempbuff, input, indp);
			MYWORD type = fUShort(indp);

			if (!strcasecmp(tempbuff, req->query))
				strcpy(tempbuff, req->query);

			req->dp += pQu(req->dp, tempbuff);
			memcpy(req->dp, indp, 8);
			req->dp += 8;
			indp += 8;
			//indp += 2; //type
			//indp += 2; //class
			//indp += 4; //ttl
			MYWORD zLen = fUShort(indp);
			indp += 2; //datalength

			switch (type)
			{
				case DNS_TYPE_A:
					req->dp += pUShort(req->dp, zLen);
					req->dp += pIP(req->dp, fIP(indp));
					break;
				case DNS_TYPE_CNAME:
					fQu(tempbuff, input, indp);
					MYWORD dl = pQu(req->dp + 2, tempbuff);
					req->dp += pUShort(req->dp, dl);
					req->dp += dl;
					break;
			}

			indp += zLen;
			req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
		}
	}
	else if (req->dnsType == DNS_TYPE_PTR || req->dnsType == DNS_TYPE_ANY || req->dnsType == DNS_TYPE_AAAA)
	{
		req->dnsp = (dnsPacket*)req->raw;
		MYWORD xid = req->dnsp->header.xid;
		memcpy(req->raw, cache->response, cache->bytes);
		req->dp = req->raw + cache->bytes;
		req->dnsp->header.xid = xid;
	}
}

void addRRA(data5 *req)
{
	if (req->qType == QTYPE_A_BARE && req->cType != CTYPE_NONE)
		sprintf(req->cname, "%s.%s", req->query, cfig.zone);

	if (strcasecmp(req->query, req->cname))
	{
		req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
		req->dp += pQu(req->dp, req->query);
		req->dp += pUShort(req->dp, DNS_TYPE_CNAME);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, cfig.lease);
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
			req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
			req->dp += pQu(req->dp, req->cname);
			req->dp += pUShort(req->dp, DNS_TYPE_A);
			req->dp += pUShort(req->dp, DNS_CLASS_IN);
			req->dp += pULong(req->dp, cfig.lease);
			req->dp += pUShort(req->dp, 4);
			req->dp += pIP(req->dp, cache->ip);
		}
	}
	//req->bytes = req->dp - req->raw;
}

void addRRPtr(data5 *req)
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
			req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
			req->dp += pULong(req->dp, cfig.lease);

			if (!cache->hostname[0])
				strcpy(req->cname, cfig.zone);
			else if (!strchr(cache->hostname, '.'))
				sprintf(req->cname, "%s.%s", cache->hostname, cfig.zone);
			else
				strcpy(req->cname, cache->hostname);

			req->dp += pUShort(req->dp, qLen(req->cname));
			req->dp += pQu(req->dp, req->cname);
		}
	}
	//req->bytes = req->dp - req->raw;
}

void addRRServerA(data5 *req)
{
	if (req->qType == QTYPE_A_BARE)
		sprintf(req->cname, "%s.%s", req->query, cfig.zone);

	if (strcasecmp(req->query, req->cname))
	{
		req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
		req->dp += pQu(req->dp, req->query);
		req->dp += pUShort(req->dp, DNS_TYPE_CNAME);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, cfig.lease);
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

			if (cache->ip && cache->ip == network.dnsUdpConn[req->sockInd].server)
			{
				req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
				req->dp += pQu(req->dp, req->cname);
				req->dp += pUShort(req->dp, DNS_TYPE_A);
				req->dp += pUShort(req->dp, DNS_CLASS_IN);
				req->dp += pULong(req->dp, cfig.lease);
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

			if (cache->ip && cache->ip != network.dnsUdpConn[req->sockInd].server)
			{
				req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
				req->dp += pQu(req->dp, req->cname);
				req->dp += pUShort(req->dp, DNS_TYPE_A);
				req->dp += pUShort(req->dp, DNS_CLASS_IN);
				req->dp += pULong(req->dp, cfig.lease);
				req->dp += pUShort(req->dp, 4);
				req->dp += pIP(req->dp, cache->ip);
			}
		}
	}
	//req->bytes = req->dp - req->raw;
}

void addRRAny(data5 *req)
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
					req->dp += pULong(req->dp, cfig.lease);
					req->dp += pUShort(req->dp, 4);
					req->dp += pIP(req->dp, cache->ip);
					req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
					break;

				case CTYPE_EXT_CNAME:
					req->dp += pQu(req->dp, req->cname);
					req->dp += pUShort(req->dp, DNS_TYPE_CNAME);
					req->dp += pUShort(req->dp, DNS_CLASS_IN);
					req->dp += pULong(req->dp, cfig.lease);
					req->dp += pUShort(req->dp, qLen(cache->hostname));
					req->dp += pQu(req->dp, cache->hostname);
					req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
					break;

				case CTYPE_LOCAL_CNAME:
					req->dp += pQu(req->dp, req->cname);
					req->dp += pUShort(req->dp, DNS_TYPE_CNAME);
					req->dp += pUShort(req->dp, DNS_CLASS_IN);
					req->dp += pULong(req->dp, cfig.lease);
					sprintf(req->cname, "%s.%s", cache->hostname, cfig.zone);
					req->dp += pUShort(req->dp, qLen(req->cname));
					req->dp += pQu(req->dp, req->cname);
					req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
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
					req->dp += pULong(req->dp, cfig.lease);

					if (!cache->hostname[0])
						strcpy(req->extbuff, cfig.zone);
					else if (!strchr(cache->hostname, '.'))
						strcpy(req->extbuff, cache->hostname);
					else
						sprintf(req->extbuff, "%s.%s", cache->hostname, cfig.zone);

					req->dp += pUShort(req->dp, qLen(req->extbuff));
					req->dp += pQu(req->dp, req->extbuff);
					req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
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

void addRRWildA(data5 *req, MYDWORD ip)
{
	req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
	req->dp += pQu(req->dp, req->query);
	req->dp += pUShort(req->dp, DNS_TYPE_A);
	req->dp += pUShort(req->dp, DNS_CLASS_IN);
	req->dp += pULong(req->dp, cfig.lease);
	req->dp += pUShort(req->dp, 4);
	req->dp += pIP(req->dp, ip);
	//req->bytes = req->dp - req->raw;
}

void addRRLocalhostA(data5 *req, CachedData *cache)
{
	if (strcasecmp(req->query, req->mapname))
	{
		req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
		req->dp += pQu(req->dp, req->query);
		req->dp += pUShort(req->dp, DNS_TYPE_CNAME);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, cfig.lease);
		req->dp += pUShort(req->dp, qLen(req->mapname));
		req->dp += pQu(req->dp, req->mapname);
	}

	req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
	req->dp += pQu(req->dp, req->mapname);
	req->dp += pUShort(req->dp, DNS_TYPE_A);
	req->dp += pUShort(req->dp, DNS_CLASS_IN);
	req->dp += pULong(req->dp, cfig.lease);
	req->dp += pUShort(req->dp, 4);
	req->dp += pIP(req->dp, cache->ip);
	//req->bytes = req->dp - req->raw;
}

void addRRLocalhostPtr(data5 *req, CachedData *cache)
{
	req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
	req->dp += pQu(req->dp, req->query);
	req->dp += pUShort(req->dp, DNS_TYPE_PTR);
	req->dp += pUShort(req->dp, DNS_CLASS_IN);
	req->dp += pULong(req->dp, cfig.lease);
	req->dp += pUShort(req->dp, qLen(cache->hostname));
	req->dp += pQu(req->dp, cache->hostname);
	//req->bytes = req->dp - req->raw;
}

void addRRMX(data5 *req)
{
	if (cfig.mxCount[currentInd])
	{
		for (int m = 0; m < cfig.mxCount[currentInd]; m++)
			addRRMXOne(req, m);
	}

	//req->bytes = req->dp - req->raw;
}

void addRRSOA(data5 *req)
{
	if (cfig.authorized && cfig.expireTime > t)
	{
		req->dnsp->header.at = 1;
		req->dnsp->header.aa = 1;

		if (req->qType == QTYPE_A_BARE || req->qType == QTYPE_A_LOCAL || req->qType == QTYPE_A_ZONE)
			req->dp += pQu(req->dp, cfig.zone);
		else if (req->qType == QTYPE_P_LOCAL || req->qType == QTYPE_P_ZONE)
			req->dp += pQu(req->dp, cfig.authority);
		else
			return;

		if ((req->dnsType == DNS_TYPE_ANY || req->dnsType == DNS_TYPE_NS || req->dnsType == DNS_TYPE_SOA || req->dnsType == DNS_TYPE_AXFR) && (req->qType == QTYPE_A_ZONE || req->qType == QTYPE_P_ZONE))
			req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
		else
			req->dnsp->header.nscount = htons(htons(req->dnsp->header.nscount) + 1);

		req->dp += pUShort(req->dp, DNS_TYPE_SOA);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, cfig.lease);
		char *data = req->dp;
		req->dp += 2;
		req->dp += pQu(req->dp, cfig.nsP);
		sprintf(req->extbuff, "hostmaster.%s", cfig.zone);
		req->dp += pQu(req->dp, req->extbuff);

		if (req->qType == QTYPE_P_LOCAL || req->qType == QTYPE_P_EXT || req->qType == QTYPE_P_ZONE)
			req->dp += pULong(req->dp, cfig.serial2);
		else
			req->dp += pULong(req->dp, cfig.serial1);

		req->dp += pULong(req->dp, cfig.refresh);
		req->dp += pULong(req->dp, cfig.retry);
		req->dp += pULong(req->dp, cfig.expire);
		req->dp += pULong(req->dp, cfig.minimum);
		pUShort(data, (req->dp - data) - 2);
	}
	//req->bytes = req->dp - req->raw;
}

void addRRNS(data5 *req)
{
	//printf("%s=%u\n", cfig.ns, cfig.expireTime);
	if (cfig.authorized && cfig.expireTime > t)
	{
		req->dnsp->header.at = 1;
		req->dnsp->header.aa = 1;

		if (cfig.nsP[0] && (cfig.replication != 2 || cfig.dnsRepl > t))
		{
			if (req->qType == QTYPE_A_BARE || req->qType == QTYPE_A_LOCAL || req->qType == QTYPE_A_ZONE)
				req->dp += pQu(req->dp, cfig.zone);
			else if (req->qType == QTYPE_P_LOCAL || req->qType == QTYPE_P_ZONE)
				req->dp += pQu(req->dp, cfig.authority);
			else
				return;

			if ((req->dnsType == DNS_TYPE_ANY || req->dnsType == DNS_TYPE_NS || req->dnsType == DNS_TYPE_SOA || req->dnsType == DNS_TYPE_AXFR) && (req->qType == QTYPE_A_ZONE || req->qType == QTYPE_P_ZONE))
				req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
			else
				req->dnsp->header.nscount = htons(htons(req->dnsp->header.nscount) + 1);

			req->dp += pUShort(req->dp, DNS_TYPE_NS);
			req->dp += pUShort(req->dp, DNS_CLASS_IN);
			req->dp += pULong(req->dp, cfig.expire);
			req->dp += pUShort(req->dp, qLen(cfig.nsP));
			req->dp += pQu(req->dp, cfig.nsP);
		}

		if (cfig.nsS[0] && (cfig.replication == 2 || cfig.dnsRepl > t))
		{
			if (req->qType == QTYPE_A_BARE || req->qType == QTYPE_A_LOCAL || req->qType == QTYPE_A_ZONE)
				req->dp += pQu(req->dp, cfig.zone);
			else if (req->qType == QTYPE_P_LOCAL || req->qType == QTYPE_P_ZONE)
				req->dp += pQu(req->dp, cfig.authority);
			else
				return;

			if ((req->dnsType == DNS_TYPE_ANY || req->dnsType == DNS_TYPE_NS || req->dnsType == DNS_TYPE_SOA || req->dnsType == DNS_TYPE_AXFR) && (req->qType == QTYPE_A_ZONE || req->qType == QTYPE_P_ZONE))
				req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
			else
				req->dnsp->header.nscount = htons(htons(req->dnsp->header.nscount) + 1);

			req->dp += pUShort(req->dp, DNS_TYPE_NS);
			req->dp += pUShort(req->dp, DNS_CLASS_IN);
			req->dp += pULong(req->dp, cfig.expire);
			req->dp += pUShort(req->dp, qLen(cfig.nsS));
			req->dp += pQu(req->dp, cfig.nsS);
		}
	}
	//req->bytes = req->dp - req->raw;
}

void addRRAd(data5 *req)
{
	//printf("%s=%u\n", cfig.ns, cfig.expireTime);
	if (cfig.authorized && cfig.expireTime > t)
	{
		if (cfig.nsP[0] && (cfig.replication != 2 || cfig.dnsRepl > t))
		{
			req->dnsp->header.adcount = htons(htons(req->dnsp->header.adcount) + 1);
			req->dp += pQu(req->dp, cfig.nsP);

			req->dp += pUShort(req->dp, DNS_TYPE_A);
			req->dp += pUShort(req->dp, DNS_CLASS_IN);
			req->dp += pULong(req->dp, cfig.lease);
			req->dp += pUShort(req->dp, 4);

			if (cfig.replication)
				req->dp += pIP(req->dp, cfig.zoneServers[0]);
			else
				req->dp += pIP(req->dp, network.listenServers[req->sockInd]);
		}

		if (cfig.nsS[0] && (cfig.replication == 2 || cfig.dnsRepl > t))
		{
			req->dnsp->header.adcount = htons(htons(req->dnsp->header.adcount) + 1);
			req->dp += pQu(req->dp, cfig.nsS);
			req->dp += pUShort(req->dp, DNS_TYPE_A);
			req->dp += pUShort(req->dp, DNS_CLASS_IN);
			req->dp += pULong(req->dp, cfig.lease);
			req->dp += pUShort(req->dp, 4);
			req->dp += pIP(req->dp, cfig.zoneServers[1]);
		}
	}
	//req->bytes = req->dp - req->raw;
}

void addRRAOne(data5 *req)
{
	if (CachedData *cache = req->iterBegin->second)
	{
		req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);

		if (!cache->name[0])
			strcpy(req->cname, cfig.zone);
		else if (!strchr(cache->name, '.'))
			sprintf(req->cname, "%s.%s", cache->name, cfig.zone);
		else
			strcpy(req->cname, cache->name);

		req->dp += pQu(req->dp, req->cname);
		req->dp += pUShort(req->dp, DNS_TYPE_A);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, cfig.lease);
		req->dp += pUShort(req->dp, 4);
		req->dp += pIP(req->dp, cache->ip);
		//req->bytes = req->dp - req->raw;
	}
}

void addRRPtrOne(data5 *req)
{
	if (CachedData *cache = req->iterBegin->second)
	{
		req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
		sprintf(req->cname, "%s%s", cache->name, arpa);
		req->dp += pQu(req->dp, req->cname);
		req->dp += pUShort(req->dp, DNS_TYPE_PTR);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, cfig.lease);

		if (!cache->hostname[0])
			strcpy(req->cname, cfig.zone);
		else if (!strchr(cache->hostname, '.'))
			sprintf(req->cname, "%s.%s", cache->hostname, cfig.zone);
		else
			strcpy(req->cname, cache->hostname);

		req->dp += pUShort(req->dp, qLen(req->cname));
		req->dp += pQu(req->dp, req->cname);
	}

	//req->bytes = req->dp - req->raw;
}

void addRRSTAOne(data5 *req)
{
	if (CachedData *cache = req->iterBegin->second)
	{
		req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);

		if (!cache->name[0])
			strcpy(req->cname, cfig.zone);
		else if (!strchr(cache->name, '.'))
			sprintf(req->cname, "%s.%s", cache->name, cfig.zone);
		else
			strcpy(req->cname, cache->name);

		req->dp += pQu(req->dp, req->cname);
		req->dp += pUShort(req->dp, DNS_TYPE_A);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, cfig.lease);
		req->dp += pUShort(req->dp, 4);
		req->dp += pIP(req->dp, cache->ip);
	}
	//req->bytes = req->dp - req->raw;
}

void addRRCNOne(data5 *req)
{
	if (CachedData *cache = req->iterBegin->second)
	{
		req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);

		if (!cache->name[0])
			strcpy(req->cname, cfig.zone);
		else if (strchr(cache->name, '.'))
			strcpy(req->cname, cache->name);
		else
			sprintf(req->cname, "%s.%s", cache->name, cfig.zone);

		req->dp += pQu(req->dp, req->cname);
		req->dp += pUShort(req->dp, DNS_TYPE_CNAME);
		req->dp += pUShort(req->dp, DNS_CLASS_IN);
		req->dp += pULong(req->dp, cfig.lease);

		if (!cache->hostname[0])
			strcpy(req->cname, cfig.zone);
		else if (strchr(cache->hostname, '.'))
			strcpy(req->cname, cache->hostname);
		else
			sprintf(req->cname, "%s.%s", cache->hostname, cfig.zone);

		req->dp += pUShort(req->dp, qLen(req->cname));
		req->dp += pQu(req->dp, req->cname);
	}
	//req->bytes = req->dp - req->raw;
}

void addRRMXOne(data5 *req, MYBYTE m)
{
	//req->dp += pQu(req->dp, req->query);
	req->dnsp->header.ancount = htons(htons(req->dnsp->header.ancount) + 1);
	req->dp += pQu(req->dp, cfig.zone);
	req->dp += pUShort(req->dp, DNS_TYPE_MX);
	req->dp += pUShort(req->dp, DNS_CLASS_IN);
	req->dp += pULong(req->dp, cfig.lease);
	req->dp += pUShort(req->dp, strlen(cfig.mxServers[currentInd][m].hostname) + 4);
	req->dp += pUShort(req->dp, cfig.mxServers[currentInd][m].pref);
	req->dp += pQu(req->dp, cfig.mxServers[currentInd][m].hostname);
	//req->bytes = req->dp - req->raw;
}

void procHTTP(data19 *req)
{
	//debug("procHTTP");
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
		logDHCPMess(logBuff, 1);
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
		logDHCPMess(logBuff, 1);
		closesocket(req->sock);
		free(req);
		return;
	}
	else if (verbatim || cfig.dhcpLogLevel >= 2)
	{
		sprintf(logBuff, "Client %s, HTTP Request Received", IP2String(tempbuff, req->remote.sin_addr.s_addr));
		logDHCPMess(logBuff, 2);
		//printf("%s\n", buffer);
	}

	if (cfig.httpClients[0] && !findServer(cfig.httpClients, 8, req->remote.sin_addr.s_addr))
	{
		if (verbatim || cfig.dhcpLogLevel >= 2)
		{
			sprintf(logBuff, "Client %s, HTTP Access Denied", IP2String(tempbuff, req->remote.sin_addr.s_addr));
			logDHCPMess(logBuff, 2);
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
		if (fp && (verbatim || cfig.dhcpLogLevel >= 2))
		{
			sprintf(logBuff, "Client %s, %s not found", IP2String(tempbuff, req->remote.sin_addr.s_addr), fp);
			logDHCPMess(logBuff, 2);
		}
		else if (verbatim || cfig.dhcpLogLevel >= 2)
		{
			sprintf(logBuff, "Client %s, Invalid http request", IP2String(tempbuff, req->remote.sin_addr.s_addr));
			logDHCPMess(logBuff, 2);
		}

		req->dp = (char*)calloc(1, sizeof(send404));
		req->bytes = sprintf(req->dp, send404);
		req->memSize = sizeof(send404);
		_beginthread(sendHTTP, 0, (void*)req);
		return;
	}
}

void sendStatus(data19 *req)
{
	//debug("sendStatus");
	char ipbuff[16];
	char logBuff[512];
	char tempbuff[512];

	dhcpMap::iterator p;
	MYDWORD iip = 0;
	CachedData *dhcpEntry = NULL;
	//CachedData *cache = NULL;
	//printf("%d=%d\n", dhcpCache.size(), cfig.dhcpSize);
	req->memSize = 2048 + (135 * dhcpCache.size()) + (cfig.dhcpSize * 26);
	req->dp = (char*)calloc(1, req->memSize);

	if (!req->dp)
	{
		sprintf(logBuff, "Memory Error");
		logDHCPMess(logBuff, 1);
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

	if (cfig.dhcpRepl > t)
	{
		fp += sprintf(fp, "<tr><th colspan=\"5\"><font size=\"5\"><i>Active Leases</i></font></th></tr>\n");
		fp += sprintf(fp, "<tr><th>Mac Address</th><th>IP</th><th>Lease Expiry</th><th>Hostname (first 20 chars)</th><th>Server</th></tr>\n");
	}
	else
	{
		fp += sprintf(fp, "<tr><th colspan=\"4\"><font size=\"5\"><i>Active Leases</i></font></th></tr>\n");
		fp += sprintf(fp, "<tr><th>Mac Address</th><th>IP</th><th>Lease Expiry</th><th>Hostname (first 20 chars)</th></tr>\n");
	}

	for (p = dhcpCache.begin(); kRunning && p != dhcpCache.end() && fp < maxData; p++)
	{
		if ((dhcpEntry = p->second) && dhcpEntry->display && dhcpEntry->expiry >= t)
		{
			fp += sprintf(fp, "<tr>");
			fp += sprintf(fp, td200, dhcpEntry->mapname);
			fp += sprintf(fp, td200, IP2String(tempbuff, dhcpEntry->ip));

			if (dhcpEntry->expiry >= INT_MAX)
				fp += sprintf(fp, td200, "Infinity");
			else
			{
				tm *ttm = localtime(&dhcpEntry->expiry);
				strftime(tempbuff, sizeof(tempbuff), "%d-%b-%y %X", ttm);
				fp += sprintf(fp, td200, tempbuff);
			}

			if (dhcpEntry->hostname[0])
			{
				strcpy(tempbuff, dhcpEntry->hostname);
				tempbuff[20] = 0;
				fp += sprintf(fp, td200, tempbuff);
			}
			else
				fp += sprintf(fp, td200, "&nbsp;");

			if (cfig.dhcpRepl > t)
			{
				if (dhcpEntry->local && cfig.replication == 1)
					fp += sprintf(fp, td200, "Primary");
				else if (dhcpEntry->local && cfig.replication == 2)
					fp += sprintf(fp, td200, "Secondary");
				else if (cfig.replication == 1)
					fp += sprintf(fp, td200, "Secondary");
				else
					fp += sprintf(fp, td200, "Primary");
			}

			fp += sprintf(fp, "</tr>\n");
		}
	}

/*
	fp += sprintf(fp, "</table>\n<br>\n<table border=\"1\" width=\"640\" cellpadding=\"1\" bgcolor=\"#b8b8b8\">\n");
	fp += sprintf(fp, "<tr><th colspan=\"5\"><font size=\"5\"><i>Free Dynamic Leases</i></font></th></tr>\n");
	MYBYTE colNum = 0;

	for (char rangeInd = 0; kRunning && rangeInd < cfig.rangeCount && fp < maxData; rangeInd++)
	{
		for (MYDWORD ind = 0, iip = cfig.dhcpRanges[rangeInd].rangeStart; kRunning && iip <= cfig.dhcpRanges[rangeInd].rangeEnd; iip++, ind++)
		{
			if (cfig.dhcpRanges[rangeInd].expiry[ind] < t)
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
	fp += sprintf(fp, "</table>\n<br>\n<table border=\"1\" cellpadding=\"1\" width=\"640\" bgcolor=\"#b8b8b8\">\n");
	fp += sprintf(fp, "<tr><th colspan=\"4\"><font size=\"5\"><i>Free Dynamic Leases</i></font></th></tr>\n");
	fp += sprintf(fp, "<tr><td><b>DHCP Range</b></td><td align=\"right\"><b>Available Leases</b></td><td align=\"right\"><b>Free Leases</b></td></tr>\n");

	for (char rangeInd = 0; kRunning && rangeInd < cfig.rangeCount && fp < maxData; rangeInd++)
	{
		float ipused = 0;
		float ipfree = 0;
		int ind = 0;

		for (MYDWORD iip = cfig.dhcpRanges[rangeInd].rangeStart; iip <= cfig.dhcpRanges[rangeInd].rangeEnd; iip++, ind++)
		{
			if (cfig.dhcpRanges[rangeInd].expiry[ind] < t)
				ipfree++;
			else if (cfig.dhcpRanges[rangeInd].dhcpEntry[ind] && !(cfig.dhcpRanges[rangeInd].dhcpEntry[ind]->fixed))
				ipused++;
		}

		IP2String(tempbuff, ntohl(cfig.dhcpRanges[rangeInd].rangeStart));
		IP2String(ipbuff, ntohl(cfig.dhcpRanges[rangeInd].rangeEnd));
		fp += sprintf(fp, "<tr><td>%s - %s</td><td align=\"right\">%5.0f</td><td align=\"right\">%5.0f</td></tr>\n", tempbuff, ipbuff, (ipused + ipfree), ipfree);
	}

	fp += sprintf(fp, "</table>\n<br>\n<table border=\"1\" width=\"640\" cellpadding=\"1\" bgcolor=\"#b8b8b8\">\n");
	fp += sprintf(fp, "<tr><th colspan=\"4\"><font size=\"5\"><i>Free Static Leases</i></font></th></tr>\n");
	fp += sprintf(fp, "<tr><th>Mac Address</th><th>IP</th><th>Mac Address</th><th>IP</th></tr>\n");

	MYBYTE colNum = 0;

	for (p = dhcpCache.begin(); kRunning && p != dhcpCache.end() && fp < maxData; p++)
	{
		if ((dhcpEntry = p->second) && dhcpEntry->fixed && dhcpEntry->expiry < t)
		{
			if (!colNum)
			{
				fp += sprintf(fp, "<tr>");
				colNum = 1;
			}
			else if (colNum == 1)
			{
				colNum = 2;
			}
			else if (colNum == 2)
			{
				fp += sprintf(fp, "</tr>\n<tr>");
				colNum = 1;
			}

			fp += sprintf(fp, td200, dhcpEntry->mapname);
			fp += sprintf(fp, td200, IP2String(tempbuff, dhcpEntry->ip));
		}
	}

	if (colNum)
		fp += sprintf(fp, "</tr>\n");

	fp += sprintf(fp, "</table>\n</body>\n</html>");
	MYBYTE x = sprintf(tempbuff, "%u", (fp - contentStart));
	memcpy((contentStart - 12), tempbuff, x);
	req->bytes = fp - req->dp;

	_beginthread(sendHTTP, 0, (void*)req);
	return;
}

/*
void sendScopeStatus(data19 *req)
{
	//debug("sendScopeStatus");

	MYBYTE rangeCount = 0;
	req->memSize = 1536 + (150 * cfig.rangeCount);
	req->dp = (char*)calloc(1, req->memSize);

	if (!req->dp)
	{
		sprintf(logBuff, "Memory Error");
		logDHCPMess(logBuff, 1);
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
	MYBYTE colNum = 0;

	for (char rangeInd = 0; kRunning && rangeInd < cfig.rangeCount && fp < maxData; rangeInd++)
	{
		float ipused = 0;
		float ipfree = 0;
		int ind = 0;

		for (MYDWORD iip = cfig.dhcpRanges[rangeInd].rangeStart; iip <= cfig.dhcpRanges[rangeInd].rangeEnd; iip++, ind++)
		{
			if (cfig.dhcpRanges[rangeInd].expiry[ind] > t)
				ipused++;
			else
				ipfree++;
		}

		IP2String(tempbuff, ntohl(cfig.dhcpRanges[rangeInd].rangeStart));
		IP2String(req->extbuff, ntohl(cfig.dhcpRanges[rangeInd].rangeEnd));
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
	data19 *req = (data19*)lpParam;

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

void procTCP(data5 *req)
{
	//debug("procTCP");

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
		logDNSMess(logBuff, 1);
		closesocket(req->sock);
		return;
	}

	MYWORD pktSize = fUShort(req->raw);
	req->dp = req->raw + 2;
	req->dnsp = (dnsPacket*)(req->dp);

	if (req->dnsp->header.qr)
		return;

	req->dp = &req->dnsp->data;
	MYDWORD clientIP = req->remote.sin_addr.s_addr;

	if (!findServer(network.allServers, MAX_SERVERS, clientIP) && !findServer(cfig.zoneServers, MAX_TCP_CLIENTS, clientIP) && !findServer(&cfig.zoneServers[2], MAX_TCP_CLIENTS - 2, clientIP))
	{
		sprintf(logBuff, "DNS TCP Query, Access Denied");
		logTCPMess(req, logBuff, 1);
		addRRError(req, RCODE_REFUSED);
		sendTCPmess(req);
		closesocket(req->sock);
		return;
	}

	if (ntohs(req->dnsp->header.qdcount) != 1 || ntohs(req->dnsp->header.ancount))
	{
		sprintf(logBuff, "DNS Query Format Error");
		logTCPMess(req, logBuff, 1);
		addRRError(req, RCODE_FORMATERROR);
		sendTCPmess(req);
		closesocket(req->sock);
		return;
	}

	if (req->dnsp->header.opcode != OPCODE_STANDARD_QUERY)
	{
		switch (req->dnsp->header.opcode)
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
				sprintf(logBuff, "OpCode %u not supported", req->dnsp->header.opcode);
		}

		logTCPMess(req, logBuff, 1);
		addRRError(req, RCODE_NOTIMPL);
		sendTCPmess(req);
		closesocket(req->sock);
		return;
	}

	for (int i = 1; i <= ntohs(req->dnsp->header.qdcount); i++)
	{
		req->dp += fQu(req->query, req->dnsp, req->dp);
		req->dnsType = fUShort(req->dp);
		req->dp += 2;
		req->qclass = fUShort(req->dp);
		req->dp += 2;
	}

	if (req->qclass != DNS_CLASS_IN)
	{
		sprintf(logBuff, "DNS Class %u not supported", req->qclass);
		logTCPMess(req, logBuff, 1);
		addRRError(req, RCODE_NOTIMPL);
		sendTCPmess(req);
		closesocket(req->sock);
		return;
	}

	if (!req->dnsType)
	{
		sprintf(logBuff, "missing query type");
		logTCPMess(req, logBuff, 1);
		addRRError(req, RCODE_FORMATERROR);
		sendTCPmess(req);
		closesocket(req->sock);
		return;
	}

	strcpy(req->cname, req->query);
	strcpy(req->mapname, req->query);
	myLower(req->mapname);
	req->qLen = strlen(req->cname);
	req->qType = makeLocal(req->mapname);

	if (req->qType == QTYPE_A_EXT && req->qLen > cfig.zLen)
	{
		char *dp = req->cname + (req->qLen - cfig.zLen);

		if (!strcasecmp(dp, cfig.zone))
			req->qType = QTYPE_CHILDZONE;
	}

	if (req->dnsType != DNS_TYPE_NS && req->dnsType != DNS_TYPE_SOA && req->dnsType != DNS_TYPE_AXFR && req->dnsType != DNS_TYPE_IXFR)
	{
		addRRError(req, RCODE_NOTIMPL);
		sendTCPmess(req);
		sprintf(logBuff, "%s,  Query Type not supported", strquery(req));
		logTCPMess(req, logBuff, 1);
		closesocket(req->sock);
		return;
	}
	else if (!cfig.authorized || (req->qType != QTYPE_A_ZONE && req->qType != QTYPE_A_LOCAL && req->qType != QTYPE_P_ZONE && req->qType != QTYPE_P_LOCAL))
	{
		addRRError(req, RCODE_NOTAUTH);
		sendTCPmess(req);
		sprintf(logBuff, "Server is not authority for zone %s", req->query);
		logTCPMess(req, logBuff, 1);
	}
	else if (cfig.expireTime < t)
	{
		addRRError(req, RCODE_NOTZONE);
		sendTCPmess(req);
		sprintf(logBuff, "Zone %s expired", req->query);
		logTCPMess(req, logBuff, 1);
	}
	else
	{
		switch (req->dnsType)
		{
			case DNS_TYPE_SOA:
				addRRNone(req);
				addRRSOA(req);
				sendTCPmess(req);

				if (req->dnsp->header.ancount)
					sprintf(logBuff, "SOA Sent for zone %s", req->query);
				else
					sprintf(logBuff, "%s not found", strquery(req));

				logTCPMess(req, logBuff, 2);
				break;

			case DNS_TYPE_NS:
				addRRNone(req);
				addRRNS(req);
				addRRAd(req);
				sendTCPmess(req);

				if (req->dnsp->header.ancount)
					sprintf(logBuff, "NS Sent for zone %s", req->query);
				else
					sprintf(logBuff, "%s not found", strquery(req));

				logTCPMess(req, logBuff, 2);
				break;

			case DNS_TYPE_AXFR:
			case DNS_TYPE_IXFR:

				if (req->qType == QTYPE_A_ZONE)
				{
					MYWORD records = 0;

					addRREmpty(req);
					addRRSOA(req);

					if (!sendTCPmess(req))
					{
						closesocket(req->sock);
						return;
					}
					else
						records++;

					addRREmpty(req);
					addRRNS(req);

					if (!sendTCPmess(req))
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

							if (!sendTCPmess(req))
							{
								closesocket(req->sock);
								return;
							}
							else
								records++;
						}
					}

					for (int m = 0; m < cfig.mxCount[currentInd]; m++)
					{
						addRREmpty(req);
						addRRMXOne(req, m);

						if (!sendTCPmess(req))
						{
							closesocket(req->sock);
							return;
						}
						else
							records++;
					}

					addRREmpty(req);
					addRRSOA(req);

					if (sendTCPmess(req))
					{
						records++;
						sprintf(logBuff, "Zone %s with %d RRs Sent", req->query, records);
						logTCPMess(req, logBuff, 2);
					}
				}
				else if (req->qType == QTYPE_P_ZONE)
				{
					MYWORD records = 0;

					addRREmpty(req);
					addRRSOA(req);

					if (!sendTCPmess(req))
					{
						closesocket(req->sock);
						return;
					}
					else
						records++;

					addRREmpty(req);
					addRRNS(req);

					if (!sendTCPmess(req))
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

							if (!sendTCPmess(req))
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

					if (sendTCPmess(req))
					{
						records++;
						sprintf(logBuff, "Zone %s with %d RRs Sent", req->query, records);
						logTCPMess(req, logBuff, 2);
					}
				}
				else
				{
					addRRNone(req);
					req->dnsp->header.rcode = RCODE_NOTAUTH;
					sendTCPmess(req);
					sprintf(logBuff, "Server is not authority for zone %s", req->query);
					logTCPMess(req, logBuff, 1);
				}
				break;

				default:
					sprintf(logBuff, "%s Query type not supported", strquery(req));
					logTCPMess(req, logBuff, 1);
					addRRError(req, RCODE_NOTIMPL);
					sendTCPmess(req);
		}
	}

	closesocket(req->sock);
}

MYWORD sendTCPmess(data5 *req)
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
		req->dnsp->header.ra = 0;
		req->bytes = req->dp - req->raw;
		pUShort(req->raw, req->bytes - 2);

		if (req->bytes == send(req->sock, req->raw, req->bytes, 0) && !WSAGetLastError())
			return 1;
	}

	if (verbatim || cfig.dnsLogLevel >= 1)
	{
		sprintf(logBuff, "Failed to send %s", strquery(req));
		logTCPMess(req, logBuff, 1);
	}

	return 0;
}

MYWORD gdnmess(data5 *req, MYBYTE sockInd)
{
	//debug("gdnmess");
	char logBuff[512];
	memset(req, 0, sizeof(data5));
	req->sockLen = sizeof(req->remote);
	errno = 0;

	req->bytes = recvfrom(network.dnsUdpConn[sockInd].sock,
	                      req->raw,
	                      sizeof(req->raw),
	                      0,
	                      (sockaddr*)&req->remote,
	                      &req->sockLen);

	errno = WSAGetLastError();

	if (errno || req->bytes <= 0)
		return 0;

	req->sockInd = sockInd;
	req->dnsp = (dnsPacket*)req->raw;

/*
	if (req->dnsp->header.qr && req->dnsp->header.opcode == OPCODE_DYNAMIC_UPDATE && cfig.replication == 1 && dhcpService && req->remote.sin_addr.s_addr == cfig.zoneServers[1])
	{
		char localBuff[256];

		if (ntohs(req->dnsp->header.zcount) == 1 && ntohs(req->dnsp->header.prcount) == 1 && !req->dnsp->header.ucount && !req->dnsp->header.arcount)
		{
			char *dp = &req->dnsp->data;
			dp += fQu(localBuff, req->dnsp, dp);
			dp += 4; //type and class

			if (!strcasecmp(localBuff, cfig.zone))
			{
				dp += fQu(localBuff, req->dnsp, dp);
				MYWORD dnsType = fUShort(dp);
				dp += 4; //type and class
				dp += 4; //ttl
				dp += 2; //datalength
				MYDWORD ip = fIP(dp);

				if (dnsType == DNS_TYPE_A && ip == cfig.zoneServers[1] && makeLocal(localBuff) == QTYPE_A_LOCAL)
				{
					if (cfig.refresh > (MYDWORD)(INT_MAX - t))
						cfig.dnsRepl = INT_MAX;
					else
						cfig.dnsRepl = t + cfig.refresh + cfig.retry + cfig.retry;

					sprintf(cfig.nsS, "%s.%s", localBuff, cfig.zone);

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

	if (req->dnsp->header.qr)
		return 0;

	if (req->dnsp->header.opcode != OPCODE_STANDARD_QUERY)
	{
		if (verbatim || cfig.dnsLogLevel >= 1)
		{
			switch (req->dnsp->header.opcode)
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
					sprintf(logBuff, "OpCode %d not supported", req->dnsp->header.opcode);
			}

			logDNSMess(req, logBuff, 1);
		}

		addRRError(req, RCODE_NOTIMPL);
		return 0;
	}

	if (ntohs(req->dnsp->header.qdcount) != 1 || ntohs(req->dnsp->header.ancount))
	{
		if (verbatim || cfig.dnsLogLevel >= 1)
		{
			sprintf(logBuff, "DNS Query Format Error");
			logDNSMess(req, logBuff, 1);
		}

		addRRError(req, RCODE_FORMATERROR);
		return 0;
	}

	req->dp = &req->dnsp->data;

	for (int i = 1; i <= ntohs(req->dnsp->header.qdcount); i++)
	{
		req->dp += fQu(req->query, req->dnsp, req->dp);
		req->dnsType = fUShort(req->dp);
		req->dp += 2;
		req->qclass = fUShort(req->dp);
		req->dp += 2;
	}

	//debug(req->query);

	if (req->qclass != DNS_CLASS_IN)
	{
		if (verbatim || cfig.dnsLogLevel >= 1)
		{
			sprintf(logBuff, "DNS Class %d not supported", req->qclass);
			logDNSMess(req, logBuff, 1);
		}
		addRRError(req, RCODE_NOTIMPL);
		return 0;
	}

	if (!req->dnsType)
	{
		if (verbatim || cfig.dnsLogLevel >= 1)
		{
			sprintf(logBuff, "missing query type");
			logDNSMess(req, logBuff, 1);
		}

		addRRError(req, RCODE_FORMATERROR);
		return 0;
	}

	MYDWORD ip = req->remote.sin_addr.s_addr;
	MYDWORD iip = ntohl(ip);

	for (int i = 0; i < MAX_DNS_RANGES && cfig.dnsRanges[i].rangeStart; i++)
	{
		if (iip >= cfig.dnsRanges[i].rangeStart && iip <= cfig.dnsRanges[i].rangeEnd)
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

	if (verbatim || cfig.dnsLogLevel >= 1)
	{
		sprintf(logBuff, "DNS UDP Query, Access Denied");
		logDNSMess(req, logBuff, 1);
	}

	addRRError(req, RCODE_REFUSED);
	return 0;
}

MYWORD scanloc(data5 *req)
{
	//debug("scanloc");
	char logBuff[512];

	if (!req->query[0])
		return 0;

	strcpy(req->cname, req->query);
	strcpy(req->mapname, req->query);
	myLower(req->mapname);
	req->qType = makeLocal(req->mapname);
	//MYDWORD ip = req->remote.sin_addr.s_addr;
	//sprintf(logBuff, "qType=%u dnsType=%u query=%s mapname=%s", req->qType, req->dnsType, req->query, req->mapname);
	//logMess(logBuff, 2);

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
					if (!strcasecmp(req->query, cfig.zone) && (cfig.authorized || cfig.mxServers[currentInd][0].hostname[0]))
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
					if (cfig.authorized && (req->qType == QTYPE_A_ZONE || req->qType == QTYPE_P_ZONE || req->qType == QTYPE_A_BARE))
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
					if (cfig.authorized)
					{
						if (req->qType == QTYPE_P_ZONE)
						{
							if (cfig.replication == 1 && req->remote.sin_addr.s_addr == cfig.zoneServers[1] && (t - cfig.dnsCheck) < 2)
							{
								if (cfig.refresh > (MYDWORD)(INT_MAX - t))
									cfig.dnsRepl = INT_MAX;
								else
									cfig.dnsRepl = t + cfig.refresh + cfig.retry + cfig.retry;
							}

							cfig.dnsCheck = 0;
							addRRNone(req);
							addRRSOA(req);
							return 1;
						}
						else if (req->qType == QTYPE_A_ZONE)
						{
							cfig.dnsCheck = t;
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
					if (cfig.authorized)
					{
						if (verbatim || cfig.dnsLogLevel)
						{
							sprintf(logBuff, "%s, DNS Query Type not supported", strquery(req));
							logDNSMess(req, logBuff, 1);
						}
						addRRNone(req);
						addRRNS(req);
						addRRAd(req);
						req->dnsp->header.rcode = RCODE_NOTIMPL;
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
					strcpy(req->cname, cfig.zone);
				else if (strchr(cache->hostname, '.'))
					strcpy(req->cname, cache->hostname);
				else
					sprintf(req->cname, "%s.%s", cache->hostname, cfig.zone);

				//sprintf(logBuff, "cType=%u, name=%s, hostname=%s", cache->cType, cache->name, cache->hostname);
				//logMess(logBuff, 2);

				strcpy(req->mapname, cache->hostname);
				myLower(req->mapname);
				continue;

			default:
				break;
		}
	}

	//sprintf(logBuff, "cType=%u,dnsType=%u,query=%s,cname=%s", req->cType, req->dnsType, req->query, req->cname);
	//logMess(logBuff, 2);

	if (req->dnsType == DNS_TYPE_A && cfig.wildHosts[0].wildcard[0])
	{
		for (MYBYTE i = 0; i < MAX_WILD_HOSTS && cfig.wildHosts[i].wildcard[0]; i++)
		{
			if (wildcmp(req->mapname, cfig.wildHosts[i].wildcard))
			{
				addRRNone(req);

				if (cfig.wildHosts[i].ip)
					addRRWildA(req, cfig.wildHosts[i].ip);

				return 1;
			}
		}
	}

	if (req->cType == CTYPE_EXT_CNAME)
	{
		//debug(req->cname);
		req->qType = makeLocal(req->cname);
		req->dp = &req->dnsp->data;
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

MYWORD fdnmess(data5 *req)
{
	//debug("fdnmess");
	//debug(req->cname);
	//printf("before qType=%d %d\n", req->qType, QTYPE_A_SUBZONE);
	char ipbuff[32];
	char logBuff[512];
	req->qLen = strlen(req->cname);
	MYBYTE zoneDNS;
	int nRet = -1;

	char mapname[8];
	sprintf(mapname, "%u", req->dnsp->header.xid);
	CachedData *queue = findQueue(mapname);

	for (zoneDNS = 0; zoneDNS < MAX_COND_FORW && cfig.dnsRoutes[zoneDNS].zLen; zoneDNS++)
	{
		if (req->qLen == cfig.dnsRoutes[zoneDNS].zLen && !strcasecmp(req->cname, cfig.dnsRoutes[zoneDNS].zone))
			req->qType = QTYPE_CHILDZONE;
		else if (req->qLen > cfig.dnsRoutes[zoneDNS].zLen)
		{
			char *dp = req->cname + (req->qLen - cfig.dnsRoutes[zoneDNS].zLen - 1);

			if (*dp == '.' && !strcasecmp(dp + 1, cfig.dnsRoutes[zoneDNS].zone))
				req->qType = QTYPE_CHILDZONE;
		}

		if (req->qType == QTYPE_CHILDZONE)
		{
			if (queue && cfig.dnsRoutes[zoneDNS].dns[1])
				cfig.dnsRoutes[zoneDNS].currentDNS = 1 - cfig.dnsRoutes[zoneDNS].currentDNS;

			if (req->remote.sin_addr.s_addr != cfig.dnsRoutes[zoneDNS].dns[cfig.dnsRoutes[zoneDNS].currentDNS])
			{
				req->addr.sin_family = AF_INET;
				req->addr.sin_addr.s_addr = cfig.dnsRoutes[zoneDNS].dns[cfig.dnsRoutes[zoneDNS].currentDNS];
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
					if (verbatim || cfig.dnsLogLevel)
					{
						sprintf(logBuff, "Error Forwarding UDP DNS Message to Conditional Forwarder %s", IP2String(ipbuff, req->addr.sin_addr.s_addr));
						logDNSMess(req, logBuff, 1);
						addRRNone(req);
						req->dnsp->header.rcode = RCODE_SERVERFAIL;
					}

					if (cfig.dnsRoutes[zoneDNS].dns[1])
						cfig.dnsRoutes[zoneDNS].currentDNS = 1 - cfig.dnsRoutes[zoneDNS].currentDNS;

					return 0;
				}
				else
				{
					if (verbatim || cfig.dnsLogLevel >= 2)
					{
						sprintf(logBuff, "%s forwarded to Conditional Forwarder %s", strquery(req), IP2String(ipbuff, cfig.dnsRoutes[zoneDNS].dns[cfig.dnsRoutes[zoneDNS].currentDNS]));
						logDNSMess(req, logBuff, 2);
					}
				}
			}

			break;
		}
	}

	if (req->qType != QTYPE_CHILDZONE)
	{
		//sprintf(logBuff, "after qType=%d %d", req->qType, QTYPE_CHILDZONE);
		//logMess(logBuff, 2);

		if (cfig.authorized && (req->qType == QTYPE_A_LOCAL || req->qType == QTYPE_P_LOCAL))
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

		if (!req->dnsp->header.rd)
		{
			addRRNone(req);
			if (verbatim || cfig.dnsLogLevel)
			{
				sprintf(logBuff, "%s is not found (recursion not desired)", strquery(req));
				logDNSMess(req, logBuff, 2);
			}
			return 0;
		}

		if (!network.dns[0])
		{
			addRRNone(req);
			req->dnsp->header.ra = 0;
			if (verbatim || cfig.dnsLogLevel)
			{
				sprintf(logBuff, "%s not found (recursion not available)", strquery(req));
				logDNSMess(req, logBuff, 2);
			}
			return 0;
		}

		if (queue && network.dns[1] && queue->dnsIndex < MAX_SERVERS && network.currentDNS == queue->dnsIndex)
		{
			network.currentDNS++;

			if (network.currentDNS >= MAX_SERVERS || !network.dns[network.currentDNS])
				network.currentDNS = 0;
		}

		if (req->remote.sin_addr.s_addr != network.dns[network.currentDNS])
		{
			req->addr.sin_family = AF_INET;
			req->addr.sin_addr.s_addr = network.dns[network.currentDNS];
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
				if (verbatim || cfig.dnsLogLevel)
				{
					sprintf(logBuff, "Error forwarding UDP DNS Message to Forwarding Server %s", IP2String(ipbuff, network.dns[network.currentDNS]));
					logDNSMess(req, logBuff, 1);
					addRRNone(req);
					req->dnsp->header.rcode = RCODE_SERVERFAIL;
				}

				if (network.dns[1])
				{
					network.currentDNS++;

					if (network.currentDNS >= MAX_SERVERS || !network.dns[network.currentDNS])
						network.currentDNS = 0;
				}

				return 0;
			}
			else
			{
				if (verbatim || cfig.dnsLogLevel >= 2)
				{
					sprintf(logBuff, "%s forwarded to Forwarding Server %s", strquery(req), IP2String(ipbuff, network.dns[network.currentDNS]));
					logDNSMess(req, logBuff, 2);
				}
			}
		}
	}

	if (!queue)
	{
		memset(&lump, 0, sizeof(data71));
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
		queue->dnsIndex = 128 + (2 * zoneDNS) + cfig.dnsRoutes[zoneDNS].currentDNS;
	else
		queue->dnsIndex = network.currentDNS;

	//sprintf(logBuff, "queue created for %s", req->query);
	//debug(logBuff);

	return (nRet);
}

MYWORD frdnmess(data5 *req)
{
	//debug("frdnmess");
	char tempbuff[512];
	memset(req, 0, sizeof(data5));
	req->sockLen = sizeof(req->remote);
	errno = 0;
	MYBYTE dnsType = 0;

	req->bytes = recvfrom(network.forwConn.sock,
	                      req->raw,
	                      sizeof(req->raw),
	                      0,
	                      (sockaddr*)&req->remote,
	                      &req->sockLen);

	errno = WSAGetLastError();

	if (errno || req->bytes <= 0)
		return 0;

	req->dnsp = (dnsPacket*)req->raw;
	req->dp = &req->dnsp->data;

	for (int i = 1; i <= ntohs(req->dnsp->header.qdcount); i++)
	{
		req->dp += fQu(req->cname, req->dnsp, req->dp);
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

	if ((dnsType == DNS_TYPE_A || dnsType == DNS_TYPE_ANY || dnsType == DNS_TYPE_AAAA || dnsType == DNS_TYPE_PTR) && !req->dnsp->header.rcode && !req->dnsp->header.tc && req->dnsp->header.ancount)
	{
		time_t expiry = 0;
		bool resultFound = false;

		for (int i = 1; i <= ntohs(req->dnsp->header.ancount); i++)
		{
			resultFound = true;
			req->dp += fQu(tempbuff, req->dnsp, req->dp);
			//dnsType = fUShort(req->dp);

			//logDNSMess(tempbuff, 2);
			req->dp += 4; //type and class

			if (!expiry || fULong(req->dp) < (MYDWORD)expiry)
				expiry = fULong(req->dp);

			req->dp += 4; //ttl
			int zLen = fUShort(req->dp);
			req->dp += 2; //datalength
			req->dp += zLen;
		}

		if (resultFound)
		{
			MYWORD cacheSize = req->dp - req->raw;

			if (cfig.minCache && expiry < cfig.minCache)
				expiry = cfig.minCache;

			if (cfig.maxCache && expiry > cfig.maxCache)
				expiry = cfig.maxCache;

			if (expiry < INT_MAX - t)
				expiry += t;
			else
				expiry = INT_MAX;

			memset(&lump, 0, sizeof(data71));
			lump.cType = CTYPE_CACHED;
			lump.dnsType = dnsType;
			lump.mapname = req->mapname;
			lump.bytes = req->bytes;
			lump.response = (MYBYTE*)req->dnsp;
			CachedData* cache = createCache(&lump);

			if (cache)
			{
				cache->expiry = expiry;
				addEntry(cache);
			}
		}
	}

	char mapname[8];
	sprintf(mapname, "%u", req->dnsp->header.xid);
	CachedData *queue = findQueue(mapname);

	if (queue && queue->expiry)
	{
		queue->expiry = 0;

		if (queue->dnsIndex < MAX_SERVERS)
		{
			if (req->remote.sin_addr.s_addr != network.dns[network.currentDNS])
			{
				for (MYBYTE i = 0; i < MAX_SERVERS && network.dns[i]; i++)
				{
					if (network.dns[i] == req->remote.sin_addr.s_addr)
					{
						network.currentDNS = i;
						break;
					}
				}
			}
		}
		else if (queue->dnsIndex >= 128 && queue->dnsIndex < 192)
		{
			MYBYTE rid = (queue->dnsIndex - 128) / 2;
			data10 *dnsRoute = &cfig.dnsRoutes[rid];

			if (dnsRoute->dns[0] == req->remote.sin_addr.s_addr)
				dnsRoute->currentDNS = 0;
			else if (dnsRoute->dns[1] == req->remote.sin_addr.s_addr)
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

MYWORD sdnmess(data5 *req)
{
	//debug("sdnmess");

	errno = 0;
	req->bytes = req->dp - req->raw;
	req->bytes = sendto(network.dnsUdpConn[req->sockInd].sock,
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

void add2Cache(char *hostname, MYDWORD ip, time_t expiry, MYBYTE aType, MYBYTE pType)
{
	//sprintf(logBuff, "Adding %s=%s %u", hostname,IP2String(ipbuff, ip), expiry - t);
	//logMess(logBuff, 1);

	//memset(&lump, 0, sizeof(data71));

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
			memset(&lump, 0, sizeof(data71));
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
					logDNSMess(logBuff, 1);
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

				if (cfig.replication != 2 && (pType == CTYPE_LOCAL_PTR_AUTH || pType == CTYPE_SERVER_PTR_AUTH))
					cfig.serial2 = t;
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
			memset(&lump, 0, sizeof(data71));
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
					logDNSMess(logBuff, 1);
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

				if (cfig.replication != 2 && (aType == CTYPE_LOCAL_A || aType == CTYPE_SERVER_A_AUTH))
					cfig.serial1 = t;
			}

		}
		else if (cache->expiry < expiry)
		{
			cache->cType = aType;
			cache->expiry = expiry;
		}
	}
}

void expireEntry(MYDWORD ip)
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
	memset(&lump, 0, sizeof(data71));
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
			logDNSMess(logBuff, 1);
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

char* getResult(data5 *req)
{
	char buff[256];

	req->tempname[0] = 0;
	char *raw = &req->dnsp->data;
	MYWORD queueIndex;

	for (int i = 1; i <= ntohs(req->dnsp->header.qdcount); i++)
	{
		raw += fQu(buff, req->dnsp, raw);
		raw += 4;
	}

	for (int i = 1; i <= ntohs(req->dnsp->header.ancount); i++)
	{
		raw += fQu(buff, req->dnsp, raw);
		int type = fUShort(raw);
		raw += 2; //type
		raw += 2; //class
		raw += 4; //ttl
		int zLen = fUShort(raw);
		raw += 2; //datalength

		if (type == DNS_TYPE_A)
			return IP2String(req->tempname, fIP(raw));
		else if (type == DNS_TYPE_AAAA)
			return IP62String(req->tempname, (MYBYTE*)raw);
		else if (type == DNS_TYPE_PTR)
		{
			fQu(req->tempname, req->dnsp, raw);
			return req->tempname;
		}
		else if (type == DNS_TYPE_MX)
			fQu(req->tempname, req->dnsp, (raw + 2));
		else if (type == DNS_TYPE_CNAME)
			fQu(req->tempname, req->dnsp, raw);
		else if (type == DNS_TYPE_NS)
			fQu(req->tempname, req->dnsp, raw);

		raw += zLen;
	}

	if (req->tempname[0])
		return req->tempname;
	else
		return NULL;
}


bool checkRange(data17 *rangeData, char rangeInd)
{
	//debug("checkRange");

	if (!cfig.hasFilter)
		return true;

	MYBYTE rangeSetInd = cfig.dhcpRanges[rangeInd].rangeSetInd;
	data14 *rangeSet = &cfig.rangeSet[rangeSetInd];
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

MYDWORD resad(data9 *req)
{
	//debug("resad");
	char logBuff[512];
	char tempbuff[512];
	MYDWORD minRange = 0;
	MYDWORD maxRange = 0;

	if (req->dhcpp.header.bp_giaddr)
	{
		lockIP(req->dhcpp.header.bp_giaddr);
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
			if (verbatim || cfig.dhcpLogLevel)
			{
				sprintf(logBuff, "Static DHCP Host %s (%s) has No IP, DHCPDISCOVER ignored", req->chaddr, req->hostname);
				logDHCPMess(logBuff, 1);
			}
			return 0;
		}
	}

	MYDWORD iipNew = 0;
	MYDWORD iipExp = 0;
	MYDWORD rangeStart = 0;
	MYDWORD rangeEnd = 0;
	char rangeInd = -1;
	bool rangeFound = false;
	data17 rangeData;
	memset(&rangeData, 0, sizeof(data17));

	if (cfig.hasFilter)
	{
		for (MYBYTE rangeSetInd = 0; rangeSetInd < MAX_RANGE_SETS && cfig.rangeSet[rangeSetInd].active; rangeSetInd++)
		{
			data14 *rangeSet = &cfig.rangeSet[rangeSetInd];

			for (MYBYTE i = 0; i < MAX_RANGE_FILTERS && rangeSet->macSize[i]; i++)
			{
				//printf("%s\n", hex2String(tempbuff, rangeSet->macStart[i], rangeSet->macSize[i]));
				//printf("%s\n", hex2String(tempbuff, rangeSet->macEnd[i], rangeSet->macSize[i]));

				if(memcmp(req->dhcpp.header.bp_chaddr, rangeSet->macStart[i], rangeSet->macSize[i]) >= 0 && memcmp(req->dhcpp.header.bp_chaddr, rangeSet->macEnd[i], rangeSet->macSize[i]) <= 0)
				{
					rangeData.macArray[rangeSetInd] = 1;
					rangeData.macFound = true;
					//printf("mac Found, rangeSetInd=%i\n", rangeSetInd);
					break;
				}
			}

			for (MYBYTE i = 0; i < MAX_RANGE_FILTERS && req->vendClass.size && rangeSet->vendClassSize[i]; i++)
			{
				if(rangeSet->vendClassSize[i] == req->vendClass.size && !memcmp(req->vendClass.value, rangeSet->vendClass[i], rangeSet->vendClassSize[i]))
				{
					rangeData.vendArray[rangeSetInd] = 1;
					rangeData.vendFound = true;
					//printf("vend Found, rangeSetInd=%i\n", rangeSetInd);
					break;
				}
			}

			for (MYBYTE i = 0; i < MAX_RANGE_FILTERS && req->userClass.size && rangeSet->userClassSize[i]; i++)
			{
				if(rangeSet->userClassSize[i] == req->userClass.size && !memcmp(req->userClass.value, rangeSet->userClass[i], rangeSet->userClassSize[i]))
				{
					rangeData.userArray[rangeSetInd] = 1;
					rangeData.userFound = true;
					//printf("user Found, rangeSetInd=%i\n", rangeSetInd);
					break;
				}
			}

			for (MYBYTE i = 0; i < MAX_RANGE_FILTERS && req->subnetIP && rangeSet->subnetIP[i]; i++)
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

//	printArray("macArray", (char*)cfig.macArray);
//	printArray("vendArray", (char*)cfig.vendArray);
//	printArray("userArray", (char*)cfig.userArray);

	if (req->dhcpEntry)
	{
		req->dhcpEntry->rangeInd = getRangeInd(req->dhcpEntry->ip);

		if (req->dhcpEntry->rangeInd >= 0)
		{
			int ind = getIndex(req->dhcpEntry->rangeInd, req->dhcpEntry->ip);

			if (cfig.dhcpRanges[req->dhcpEntry->rangeInd].dhcpEntry[ind] == req->dhcpEntry && checkRange(&rangeData, req->dhcpEntry->rangeInd))
			{
				MYBYTE rangeSetInd = cfig.dhcpRanges[req->dhcpEntry->rangeInd].rangeSetInd;

				if (!cfig.rangeSet[rangeSetInd].subnetIP[0])
				{
					MYDWORD mask = cfig.dhcpRanges[req->dhcpEntry->rangeInd].mask;
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

	if (dnsService && req->hostname[0])
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
						data13 *range = &cfig.dhcpRanges[k];
						int ind = getIndex(k, cache->ip);

						if (ind >= 0 && range->expiry[ind] <= t)
						{
							MYDWORD iip = htonl(cache->ip);

							if (!cfig.rangeSet[range->rangeSetInd].subnetIP[0])
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

	if (!iipNew && req->reqIP)
	{
		char k = getRangeInd(req->reqIP);

		if (k >= 0)
		{
			if (checkRange(&rangeData, k))
			{
				data13 *range = &cfig.dhcpRanges[k];
				int ind = getIndex(k, req->reqIP);

				if (range->expiry[ind] <= t)
				{
					if (!cfig.rangeSet[range->rangeSetInd].subnetIP[0])
					{
						calcRangeLimits(req->subnetIP, range->mask, &minRange, &maxRange);
						MYDWORD iip = htonl(req->reqIP);

						if (iip >= minRange && iip <= maxRange)
						{
							iipNew = iip;
							rangeInd = k;
						}
					}
					else
					{
						MYDWORD iip = htonl(req->reqIP);
						iipNew = iip;
						rangeInd = k;
					}
				}
			}
		}
	}


	for (char k = 0; !iipNew && k < cfig.rangeCount; k++)
	{
		if (checkRange(&rangeData, k))
		{
			data13 *range = &cfig.dhcpRanges[k];
			rangeStart = range->rangeStart;
			rangeEnd = range->rangeEnd;

			if (!cfig.rangeSet[range->rangeSetInd].subnetIP[0])
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

				if (cfig.replication == 2)
				{
					for (MYDWORD m = rangeEnd; m >= rangeStart; m--)
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
					for (MYDWORD m = rangeStart; m <= rangeEnd; m++)
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
			memset(&lump, 0, sizeof(data71));
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
				logDHCPMess(logBuff, 1);
				return 0;
			}

			req->dhcpEntry->mapname = cloneString(req->chaddr);

			if (!req->dhcpEntry->mapname)
			{
				sprintf(logBuff, "Memory Allocation Error");
				logDHCPMess(logBuff, 1);
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

	if (verbatim || cfig.dhcpLogLevel)
	{
		if (rangeFound)
		{
			if (req->dhcpp.header.bp_giaddr)
				sprintf(logBuff, "No free leases for DHCPDISCOVER for %s (%s) from RelayAgent %s", req->chaddr, req->hostname, IP2String(tempbuff, req->dhcpp.header.bp_giaddr));
			else
				sprintf(logBuff, "No free leases for DHCPDISCOVER for %s (%s) from interface %s", req->chaddr, req->hostname, IP2String(tempbuff, network.dhcpConn[req->sockInd].server));
		}
		else
		{
			if (req->dhcpp.header.bp_giaddr)
				sprintf(logBuff, "No Matching DHCP Range for DHCPDISCOVER for %s (%s) from RelayAgent %s", req->chaddr, req->hostname, IP2String(tempbuff, req->dhcpp.header.bp_giaddr));
			else
				sprintf(logBuff, "No Matching DHCP Range for DHCPDISCOVER for %s (%s) from interface %s", req->chaddr, req->hostname, IP2String(tempbuff, network.dhcpConn[req->sockInd].server));
		}
		logDHCPMess(logBuff, 1);
	}
	return 0;
}

MYDWORD chad(data9 *req)
{
	req->dhcpEntry = findDHCPEntry(req->chaddr);
	//printf("dhcpEntry=%d\n", req->dhcpEntry);

	if (req->dhcpEntry && req->dhcpEntry->ip)
		return req->dhcpEntry->ip;
	else
		return 0;
}

MYDWORD sdmess(data9 *req)
{
	//sprintf(logBuff, "sdmess, Request Type = %u",req->req_type);
	//debug(logBuff);
	char logBuff[512];
	char tempbuff[512];

	if (req->req_type == DHCP_MESS_NONE)
	{
		req->dhcpp.header.bp_yiaddr = chad(req);

		if (!req->dhcpp.header.bp_yiaddr)
		{
			if (verbatim || cfig.dhcpLogLevel)
			{
				sprintf(logBuff, "No Static Entry found for BOOTPREQUEST from Host %s", req->chaddr);
				logDHCPMess(logBuff, 1);
			}

			return 0;
		}
	}
	else if (req->req_type == DHCP_MESS_DECLINE)
	{
		if (req->dhcpp.header.bp_ciaddr && chad(req) == req->dhcpp.header.bp_ciaddr)
		{
			lockIP(req->dhcpp.header.bp_ciaddr);

			req->dhcpEntry->ip = 0;
			req->dhcpEntry->expiry = INT_MAX;
			req->dhcpEntry->display = false;
			req->dhcpEntry->local = false;

			if (verbatim || cfig.dhcpLogLevel)
			{
				sprintf(logBuff, "IP Address %s declined by Host %s (%s), locked", IP2String(tempbuff, req->dhcpp.header.bp_ciaddr), req->chaddr, req->hostname);
				logDHCPMess(logBuff, 1);
			}
		}

		return 0;
	}
	else if (req->req_type == DHCP_MESS_RELEASE)
	{
		if (req->dhcpp.header.bp_ciaddr && chad(req) == req->dhcpp.header.bp_ciaddr)
		{
			req->dhcpEntry->display = false;
			req->dhcpEntry->local = false;
			req->lease = 0;
			setLeaseExpiry(req->dhcpEntry, 0);
			_beginthread(updateStateFile, 0, (void*)req->dhcpEntry);

			if (dnsService && cfig.replication != 2)
				expireEntry(req->dhcpEntry->ip);

			if (verbatim || cfig.dhcpLogLevel)
			{
				sprintf(logBuff, "IP Address %s released by Host %s (%s)", IP2String(tempbuff, req->dhcpp.header.bp_ciaddr), req->chaddr, req->hostname);
				logDHCPMess(logBuff, 1);
			}
		}

		return 0;
	}
	else if (req->req_type == DHCP_MESS_INFORM)
	{
		//printf("repl0=%s\n", IP2String(tempbuff, cfig.zoneServers[0]));
		//printf("repl1=%s\n", IP2String(tempbuff, cfig.zoneServers[1]));
		//printf("IP=%s bytes=%u replication=%i\n", IP2String(tempbuff, req->remote.sin_addr.s_addr), req->bytes, cfig.replication);

		if ((cfig.replication == 1 && req->remote.sin_addr.s_addr == cfig.zoneServers[1]) || (cfig.replication == 2 && req->remote.sin_addr.s_addr == cfig.zoneServers[0]))
			recvRepl(req);

		return 0;
	}
	else if (req->req_type == DHCP_MESS_DISCOVER && strcasecmp(req->hostname, cfig.servername))
	{
		req->dhcpp.header.bp_yiaddr = resad(req);

		if (!req->dhcpp.header.bp_yiaddr)
			return 0;

		req->resp_type = DHCP_MESS_OFFER;
	}
	else if (req->req_type == DHCP_MESS_REQUEST)
	{
		//printf("%s\n", IP2String(tempbuff, req->dhcpp.header.bp_ciaddr));

		if (req->server)
		{
			if (req->server == network.dhcpConn[req->sockInd].server)
			{
				if (req->reqIP && req->reqIP == chad(req) && req->dhcpEntry->expiry > t)
				{
					req->resp_type = DHCP_MESS_ACK;
					req->dhcpp.header.bp_yiaddr = req->reqIP;
				}
				else if (req->dhcpp.header.bp_ciaddr && req->dhcpp.header.bp_ciaddr == chad(req) && req->dhcpEntry->expiry > t)
				{
					req->resp_type = DHCP_MESS_ACK;
					req->dhcpp.header.bp_yiaddr = req->dhcpp.header.bp_ciaddr;
				}
				else
				{
					req->resp_type = DHCP_MESS_NAK;
					req->dhcpp.header.bp_yiaddr = 0;

					if (verbatim || cfig.dhcpLogLevel)
					{
						sprintf(logBuff, "DHCPREQUEST from Host %s (%s) without Discover, NAKed", req->chaddr, req->hostname);
						logDHCPMess(logBuff, 1);
					}
				}
			}
			else
				return 0;
		}
		else if (req->dhcpp.header.bp_ciaddr && req->dhcpp.header.bp_ciaddr == chad(req) && req->dhcpEntry->expiry > t)
		{
			req->resp_type = DHCP_MESS_ACK;
			req->dhcpp.header.bp_yiaddr = req->dhcpp.header.bp_ciaddr;
		}
		else if (req->reqIP && req->reqIP == chad(req) && req->dhcpEntry->expiry > t)
		{
			req->resp_type = DHCP_MESS_ACK;
			req->dhcpp.header.bp_yiaddr = req->reqIP;
		}
		else
		{
			req->resp_type = DHCP_MESS_NAK;
			req->dhcpp.header.bp_yiaddr = 0;

			if (verbatim || cfig.dhcpLogLevel)
			{
				sprintf(logBuff, "DHCPREQUEST from Host %s (%s) without Discover, NAKed", req->chaddr, req->hostname);
				logDHCPMess(logBuff, 1);
			}
		}
	}
	else
		return 0;

	addOptions(req);
	int packSize = req->vp - (MYBYTE*)&req->dhcpp;
	packSize++;

	if (req->req_type == DHCP_MESS_NONE)
		packSize = req->messsize;

	if ((req->dhcpp.header.bp_giaddr || !req->remote.sin_addr.s_addr) && req->dhcpEntry && req->dhcpEntry->rangeInd >= 0)
	{
		MYBYTE rangeSetInd = cfig.dhcpRanges[req->dhcpEntry->rangeInd].rangeSetInd;
		req->targetIP = cfig.rangeSet[rangeSetInd].targetIP;
	}

	if (req->targetIP)
	{
		req->remote.sin_port = htons(IPPORT_DHCPS);
		req->remote.sin_addr.s_addr = req->targetIP;
	}
	else if (req->dhcpp.header.bp_giaddr)
	{
		req->remote.sin_port = htons(IPPORT_DHCPS);
		req->remote.sin_addr.s_addr = req->dhcpp.header.bp_giaddr;
	}
	//else if (req->dhcpp.header.bp_broadcast || !req->remote.sin_addr.s_addr || req->reqIP)
	else if (req->dhcpp.header.bp_broadcast || !req->remote.sin_addr.s_addr)
	{
		req->remote.sin_port = htons(IPPORT_DHCPC);
		req->remote.sin_addr.s_addr = INADDR_BROADCAST;
	}
	else
	{
		req->remote.sin_port = htons(IPPORT_DHCPC);
	}

	req->dhcpp.header.bp_op = BOOTP_REPLY;
	errno = 0;

	if (req->req_type == DHCP_MESS_DISCOVER && !req->dhcpp.header.bp_giaddr)
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

	//printf("goes=%s %i\n",IP2String(tempbuff, req->dhcpp.header.bp_yiaddr),req->sockInd);
	return req->dhcpp.header.bp_yiaddr;
}

MYDWORD alad(data9 *req)
{
	//debug("alad");
	//printf("in alad hostname=%s\n", req->hostname);
	char logBuff[512];
	char tempbuff[512];

	if (req->dhcpEntry && (req->req_type == DHCP_MESS_NONE || req->resp_type == DHCP_MESS_ACK))
	{
		MYDWORD hangTime = req->lease;

		if (req->rebind > req->lease)
			hangTime = req->rebind;

		req->dhcpEntry->display = true;
		req->dhcpEntry->local = true;
		setLeaseExpiry(req->dhcpEntry, hangTime);

		_beginthread(updateStateFile, 0, (void*)req->dhcpEntry);

		if (dnsService && cfig.replication != 2)
			updateDNS(req);

		if (verbatim || cfig.dhcpLogLevel >= 1)
		{
			if (req->lease && req->reqIP)
			{
				sprintf(logBuff, "Host %s (%s) allotted %s for %u seconds", req->chaddr, req->hostname, IP2String(tempbuff, req->dhcpp.header.bp_yiaddr), req->lease);
			}
			else if (req->req_type)
			{
				sprintf(logBuff, "Host %s (%s) renewed %s for %u seconds", req->chaddr, req->hostname, IP2String(tempbuff, req->dhcpp.header.bp_yiaddr), req->lease);
			}
			else
			{
				sprintf(logBuff, "BOOTP Host %s (%s) allotted %s", req->chaddr, req->hostname, IP2String(tempbuff, req->dhcpp.header.bp_yiaddr));
			}
			logDHCPMess(logBuff, 1);
		}

		if (cfig.replication && cfig.dhcpRepl > t)
			sendRepl(req);

		return req->dhcpEntry->ip;
	}
	else if ((verbatim || cfig.dhcpLogLevel >= 2) && req->resp_type == DHCP_MESS_OFFER)
	{
		sprintf(logBuff, "Host %s (%s) offered %s", req->chaddr, req->hostname, IP2String(tempbuff, req->dhcpp.header.bp_yiaddr));
		logDHCPMess(logBuff, 2);
	}
	//printf("%u=out\n", req->resp_type);
	return 0;
}

void addOptions(data9 *req)
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
		strcpy(req->dhcpp.header.bp_sname, cfig.servername);

		if (req->dhcpEntry->fixed)
		{
			//printf("%u,%u\n", req->dhcpEntry->options, *req->dhcpEntry->options);
			MYBYTE *opPointer = req->dhcpEntry->options;

			if (opPointer)
			{
				MYBYTE requestedOnly = *opPointer;
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
				MYBYTE *opPointer = cfig.dhcpRanges[req->dhcpEntry->rangeInd].options;
				//printf("Range=%i Pointer=%u\n", req->dhcpEntry->rangeInd,opPointer);

				if (opPointer)
				{
					MYBYTE requestedOnly = *opPointer;
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

			MYBYTE *opPointer = cfig.options;

			if (opPointer)
			{
				MYBYTE requestedOnly = *opPointer;

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
			op.size = strlen(cfig.zone) + 1;
			memcpy(op.value, cfig.zone, op.size);
			pvdata(req, &op);

			if (!req->opAdded[DHCP_OPTION_IPADDRLEASE])
			{
				op.opt_code = DHCP_OPTION_IPADDRLEASE;
				op.size = 4;
				pULong(op.value, cfig.lease);
				pvdata(req, &op);
			}

			if (!req->opAdded[DHCP_OPTION_NETMASK])
			{
				op.opt_code = DHCP_OPTION_NETMASK;
				op.size = 4;

				if (req->dhcpEntry->rangeInd >= 0)
					pIP(op.value, cfig.dhcpRanges[req->dhcpEntry->rangeInd].mask);
				else
					pIP(op.value, cfig.mask);

				pvdata(req, &op);
			}

			if (!req->hostname[0])
				genHostName(req->hostname, req->dhcpp.header.bp_chaddr, req->dhcpp.header.bp_hlen);

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
				if (dnsService)
				{
					op.opt_code = DHCP_OPTION_DNS;

					if (cfig.dhcpRepl > t && cfig.dnsRepl > t)
					{
						if (cfig.replication == 1)
						{
							op.size = 8;
							pIP(op.value, cfig.zoneServers[0]);
							pIP(op.value + 4, cfig.zoneServers[1]);
							pvdata(req, &op);
						}
						else
						{
							op.size = 8;
							pIP(op.value, cfig.zoneServers[1]);
							pIP(op.value + 4, cfig.zoneServers[0]);
							pvdata(req, &op);
						}
					}
					else if (cfig.dnsRepl > t)
					{
						op.size = 8;
						pIP(op.value, cfig.zoneServers[1]);
						pIP(op.value + 4, cfig.zoneServers[0]);
						pvdata(req, &op);
					}
					else
					{
						op.size = 4;
						pIP(op.value, network.dhcpConn[req->sockInd].server);
						pvdata(req, &op);
					}
				}
				else if (cfig.dnsRepl > t && cfig.replication == 2)
				{
					op.opt_code = DHCP_OPTION_DNS;
					op.size = 4;
					pIP(op.value, cfig.zoneServers[0]);
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

void pvdata(data9 *req, data3 *op)
{
	//debug("pvdata");

	if (!req->opAdded[op->opt_code] && ((req->vp - (MYBYTE*)&req->dhcpp) + op->size < req->messsize))
	{
		if (op->opt_code == DHCP_OPTION_NEXTSERVER)
			req->dhcpp.header.bp_siaddr = fIP(op->value);
		else if (op->opt_code == DHCP_OPTION_BP_FILE)
		{
			if (op->size <= 128)
				memcpy(req->dhcpp.header.bp_file, op->value, op->size);
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

			MYWORD tsize = op->size + 2;
			memcpy(req->vp, op, tsize);
			(req->vp) += tsize;
		}
		req->opAdded[op->opt_code] = true;
	}
}

void updateDNS(data9 *req)
{
	MYDWORD expiry = INT_MAX;

	if (req->lease < (MYDWORD)(INT_MAX - t))
		expiry = t + req->lease;

	if (req->dhcpEntry && cfig.replication != 2)
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
			if (cfig.dhcpRanges[dhcpEntry->rangeInd].expiry[ind] != INT_MAX)
				cfig.dhcpRanges[dhcpEntry->rangeInd].expiry[ind] = dhcpEntry->expiry;

			cfig.dhcpRanges[dhcpEntry->rangeInd].dhcpEntry[ind] = dhcpEntry;
		}
	}
}

void setLeaseExpiry(CachedData *dhcpEntry, MYDWORD lease)
{
	//printf("%d=%d\n", t, lease);
	if (dhcpEntry && dhcpEntry->ip)
	{
		if (lease > (MYDWORD)(INT_MAX - t))
			dhcpEntry->expiry = INT_MAX;
		else
			dhcpEntry->expiry = t + lease;

		int ind = getIndex(dhcpEntry->rangeInd, dhcpEntry->ip);

		if (ind >= 0)
		{
			if (cfig.dhcpRanges[dhcpEntry->rangeInd].expiry[ind] != INT_MAX)
				cfig.dhcpRanges[dhcpEntry->rangeInd].expiry[ind] = dhcpEntry->expiry;

			cfig.dhcpRanges[dhcpEntry->rangeInd].dhcpEntry[ind] = dhcpEntry;
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
			if (cfig.dhcpRanges[dhcpEntry->rangeInd].expiry[ind] != INT_MAX)
				cfig.dhcpRanges[dhcpEntry->rangeInd].expiry[ind] = dhcpEntry->expiry;

			cfig.dhcpRanges[dhcpEntry->rangeInd].dhcpEntry[ind] = dhcpEntry;
		}
	}
}


void lockIP(MYDWORD ip)
{
	if (dhcpService && ip)
	{
		MYDWORD iip = htonl(ip);

		for (char rangeInd = 0; rangeInd < cfig.rangeCount; rangeInd++)
		{
			if (iip >= cfig.dhcpRanges[rangeInd].rangeStart && iip <= cfig.dhcpRanges[rangeInd].rangeEnd)
			{
				int ind = iip - cfig.dhcpRanges[rangeInd].rangeStart;

				if (cfig.dhcpRanges[rangeInd].expiry[ind] != INT_MAX)
					cfig.dhcpRanges[rangeInd].expiry[ind] = INT_MAX;

				break;
			}
		}
	}
}

void holdIP(MYDWORD ip)
{
	if (dhcpService && ip)
	{
		MYDWORD iip = htonl(ip);

		for (char rangeInd = 0; rangeInd < cfig.rangeCount; rangeInd++)
		{
			if (iip >= cfig.dhcpRanges[rangeInd].rangeStart && iip <= cfig.dhcpRanges[rangeInd].rangeEnd)
			{
				int ind = iip - cfig.dhcpRanges[rangeInd].rangeStart;

				if (cfig.dhcpRanges[rangeInd].expiry[ind] == 0)
					cfig.dhcpRanges[rangeInd].expiry[ind] = 1;

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

		sendto(cfig.dhcpReplConn.sock,
				token.raw,
				token.bytes,
				0,
				(sockaddr*)&token.remote,
				sizeof(token.remote));

//		errno = WSAGetLastError();
//
//		if (!errno && verbatim || cfig.dhcpLogLevel >= 2)
//		{
//			sprintf(logBuff, "Token Sent");
//			logDHCPMess(logBuff, 2);
//		}

		Sleep(1000 * 300);
	}

	_endthread();
	return;
}


MYDWORD sendRepl(data9 *req)
{
	char logBuff[512];
	char ipbuff[32];
	data3 op;

	MYBYTE *opPointer = req->dhcpp.vend_data;

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
//	pULong(op.value, cfig.serial1);
//	pvdata(req, &op);

	*(req->vp) = DHCP_OPTION_END;
	req->vp++;
	req->bytes = req->vp - (MYBYTE*)req->raw;

	req->dhcpp.header.bp_op = BOOTP_REQUEST;
	errno = 0;

	req->bytes = sendto(cfig.dhcpReplConn.sock,
	                    req->raw,
	                    req->bytes,
	                    0,
						(sockaddr*)&token.remote,
						sizeof(token.remote));

	errno = WSAGetLastError();

	if (errno || req->bytes <= 0)
	{
		cfig.dhcpRepl = 0;

		if (verbatim || cfig.dhcpLogLevel >= 1)
		{
			if (cfig.replication == 1)
				sprintf(logBuff, "WSAError %u Sending DHCP Update to Secondary Server", errno);
			else
				sprintf(logBuff, "WSAError %u Sending DHCP Update to Primary Server", errno);

			logDHCPMess(logBuff, 1);
		}

		return 0;
	}
	else if (verbatim || cfig.dhcpLogLevel >= 2)
	{
		if (cfig.replication == 1)
			sprintf(logBuff, "DHCP Update for host %s (%s) sent to Secondary Server", req->dhcpEntry->mapname, IP2String(ipbuff, req->dhcpEntry->ip));
		else
			sprintf(logBuff, "DHCP Update for host %s (%s) sent to Primary Server", req->dhcpEntry->mapname, IP2String(ipbuff, req->dhcpEntry->ip));

		logDHCPMess(logBuff, 2);
	}

	return req->dhcpp.header.bp_yiaddr;
}

/*
MYDWORD sendRepl(CachedData *dhcpEntry)
{
	data9 req;
	memset(&req, 0, sizeof(data9));
	req.vp = req.dhcpp.vend_data;
	req.messsize = sizeof(dhcp_packet);
	req.dhcpEntry = dhcpEntry;

	req.dhcpp.header.bp_op = BOOTP_REQUEST;
	req.dhcpp.header.bp_xid = t;
	req.dhcpp.header.bp_ciaddr = dhcpEntry->ip;
	req.dhcpp.header.bp_yiaddr = dhcpEntry->ip;
	req.dhcpp.header.bp_hlen = 16;
	getHexValue(req.dhcpp.header.bp_chaddr, req.dhcpEntry->mapname, &(req.dhcpp.header.bp_hlen));
	req.dhcpp.header.bp_magic_num[0] = 99;
	req.dhcpp.header.bp_magic_num[1] = 130;
	req.dhcpp.header.bp_magic_num[2] = 83;
	req.dhcpp.header.bp_magic_num[3] = 99;
	strcpy(req.hostname, dhcpEntry->hostname);

	return sendRepl(&req);
}
*/

void recvRepl(data9 *req)
{
	char ipbuff[32];
	char logBuff[512];
	cfig.dhcpRepl = t + 650;

	MYDWORD ip = req->dhcpp.header.bp_yiaddr ? req->dhcpp.header.bp_yiaddr : req->dhcpp.header.bp_ciaddr;

	if (!ip || !req->dhcpp.header.bp_hlen)
	{
//		if (verbatim || cfig.dhcpLogLevel >= 2)
//		{
//			sprintf(logBuff, "Token Received");
//			logDHCPMess(logBuff, 2);
//		}

		if (req->dns)
			cfig.dnsRepl = t + 650;

		if (cfig.replication == 1)
		{
			if (req->dhcpp.header.bp_sname[0])
			{
				sprintf(cfig.nsS, "%s.%s", req->dhcpp.header.bp_sname, cfig.zone);

				if (isLocal(cfig.zoneServers[1]))
					add2Cache(req->dhcpp.header.bp_sname, cfig.zoneServers[1], INT_MAX, CTYPE_SERVER_A_AUTH, CTYPE_SERVER_PTR_AUTH);
				else
					add2Cache(req->dhcpp.header.bp_sname, cfig.zoneServers[1], INT_MAX, CTYPE_SERVER_A_AUTH, CTYPE_SERVER_PTR_NAUTH);
			}

			errno = 0;

			sendto(cfig.dhcpReplConn.sock,
					token.raw,
					token.bytes,
					0,
					(sockaddr*)&token.remote,
					sizeof(token.remote));

//			errno = WSAGetLastError();
//
//			if (!errno && (verbatim || cfig.dhcpLogLevel >= 2))
//			{
//				sprintf(logBuff, "Token Responded");
//				logDHCPMess(logBuff, 2);
//			}
		}
		else if (cfig.replication == 2)
		{
			if (req->dhcpp.header.bp_sname[0])
				sprintf(cfig.nsP, "%s.%s", req->dhcpp.header.bp_sname, cfig.zone);
		}

		return;
	}

	char rInd = getRangeInd(ip);

	if (rInd >= 0)
	{
		int ind  = getIndex(rInd, ip);
		req->dhcpEntry = cfig.dhcpRanges[rInd].dhcpEntry[ind];

		if (req->dhcpEntry && !req->dhcpEntry->fixed && strcasecmp(req->dhcpEntry->mapname, req->chaddr))
			req->dhcpEntry->expiry = 0;
	}

	req->dhcpEntry = findDHCPEntry(req->chaddr);

	if (req->dhcpEntry && req->dhcpEntry->ip != ip)
	{
		if (req->dhcpEntry->fixed)
		{
			if (cfig.replication == 1)
				sprintf(logBuff, "DHCP Update ignored for %s (%s) from Secondary Server", req->chaddr, IP2String(ipbuff, ip));
			else
				sprintf(logBuff, "DHCP Update ignored for %s (%s) from Primary Server", req->chaddr, IP2String(ipbuff, ip));

			logDHCPMess(logBuff, 1);
			return;
		}
		else if (req->dhcpEntry->rangeInd >= 0)
		{
			int ind  = getIndex(req->dhcpEntry->rangeInd, req->dhcpEntry->ip);

			if (ind >= 0)
				cfig.dhcpRanges[req->dhcpEntry->rangeInd].dhcpEntry[ind] = 0;
		}
	}

	if (!req->dhcpEntry && rInd >= 0)
	{
		memset(&lump, 0, sizeof(data71));
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
			logDHCPMess(logBuff, 1);
			return;
		}

		req->dhcpEntry->mapname = cloneString(req->chaddr);

		if (!req->dhcpEntry->mapname)
		{
			sprintf(logBuff, "Memory Allocation Error");
			free(req->dhcpEntry);
			logDHCPMess(logBuff, 1);
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

		MYDWORD hangTime = req->lease;

		if (req->rebind > req->lease)
			hangTime = req->rebind;

		setLeaseExpiry(req->dhcpEntry, hangTime);
		strcpy(req->dhcpEntry->hostname, req->hostname);

		_beginthread(updateStateFile, 0, (void*)req->dhcpEntry);

		if (dnsService && cfig.replication != 2)
		{
			if (req->lease)
				updateDNS(req);
			else
				expireEntry(req->dhcpEntry->ip);
		}

		if (verbatim || cfig.dhcpLogLevel >= 2)
		{
			if (cfig.replication == 1)
				sprintf(logBuff, "DHCP Update received for %s (%s) from Secondary Server", req->chaddr, IP2String(ipbuff, ip));
			else
				sprintf(logBuff, "DHCP Update received for %s (%s) from Primary Server", req->chaddr, IP2String(ipbuff, ip));

			logDHCPMess(logBuff, 2);
		}
	}
	else
	{
		if (cfig.replication == 1)
			sprintf(logBuff, "DHCP Update ignored for %s (%s) from Secondary Server", req->chaddr, IP2String(ipbuff, ip));
		else
			sprintf(logBuff, "DHCP Update ignored for %s (%s) from Primary Server", req->chaddr, IP2String(ipbuff, ip));

		logDHCPMess(logBuff, 1);
		return;
	}
}

char getRangeInd(MYDWORD ip)
{
	if (ip)
	{
		MYDWORD iip = htonl(ip);

		for (char k = 0; k < cfig.rangeCount; k++)
			if (iip >= cfig.dhcpRanges[k].rangeStart && iip <= cfig.dhcpRanges[k].rangeEnd)
				return k;
	}
	return -1;
}

int getIndex(char rangeInd, MYDWORD ip)
{
	if (ip && rangeInd >= 0 && rangeInd < cfig.rangeCount)
	{
		MYDWORD iip = htonl(ip);
		if (iip >= cfig.dhcpRanges[rangeInd].rangeStart && iip <= cfig.dhcpRanges[rangeInd].rangeEnd)
			return (iip - cfig.dhcpRanges[rangeInd].rangeStart);
	}
	return -1;
}

void loadOptions(FILE *f, const char *sectionName, data20 *optionData)
{
	optionData->ip = 0;
	optionData->mask = 0;
	MYBYTE maxInd = sizeof(opData) / sizeof(data4);
	MYWORD buffsize = sizeof(dhcp_packet) - sizeof(dhcp_header);
	MYBYTE *dp = optionData->options;
	MYBYTE op_specified[256];

	memset(op_specified, 0, 256);
	*dp = 0;
	dp++;

	char raw[512];
	char name[512];
	char value[512];
	char logBuff[512];

	while (readSection(raw, f))
	{
		MYBYTE *ddp = dp;
		MYBYTE hoption[256];
		MYBYTE valSize = sizeof(hoption) - 1;
		MYBYTE opTag = 0;
		MYBYTE opType = 0;
		MYBYTE valType = 0;
		bool tagFound = false;

		mySplit(name, value, raw, '=');

		//printf("%s=%s\n", name, value);

		if (!name[0])
		{
			sprintf(logBuff, "Warning: section [%s] invalid option %s ignored", sectionName, raw);
			logDHCPMess(logBuff, 1);
			continue;
		}

		if (!strcasecmp(name, "DHCPRange"))
		{
			if (!strcasecmp(sectionName, RANGESET))
				addDHCPRange(value);
			else
			{
				sprintf(logBuff, "Warning: section [%s] option %s not allowed in this section, option ignored", sectionName, raw);
				logDHCPMess(logBuff, 1);
			}
			continue;
		}
		else if (!strcasecmp(name, "IP"))
		{
			if (!strcasecmp(sectionName, GLOBALOPTIONS) || !strcasecmp(sectionName, RANGESET))
			{
				sprintf(logBuff, "Warning: section [%s] option %s not allowed in this section, option ignored", sectionName, raw);
				logDHCPMess(logBuff, 1);
			}
			else if (!isIP(value) && strcasecmp(value, "0.0.0.0"))
			{
				sprintf(logBuff, "Warning: section [%s] option Invalid IP Addr %s option ignored", sectionName, value);
				logDHCPMess(logBuff, 1);
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
				logDHCPMess(logBuff, 1);
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
				logDHCPMess(logBuff, 1);
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
				logDHCPMess(logBuff, 1);
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
				logDHCPMess(logBuff, 1);
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
				logDHCPMess(logBuff, 1);
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
				logDHCPMess(logBuff, 1);
			}
			continue;
		}
		else if (!strcasecmp(name, "FilterSubnetSelection"))
		{
			if (valSize != 4)
			{
				sprintf(logBuff, "Warning: section [%s] invalid value %s, option ignored", sectionName, raw);
				logDHCPMess(logBuff, 1);
			}
			else if (!strcasecmp(sectionName, RANGESET))
			{
				addServer(cfig.rangeSet[optionData->rangeSetInd].subnetIP, MAX_RANGE_FILTERS, fIP(value));
				cfig.hasFilter = 1;
			}
			else
			{
				sprintf(logBuff, "Warning: section [%s] option %s not allowed in this section, option ignored", sectionName, raw);
				logDHCPMess(logBuff, 1);
			}
			continue;
		}
		else if (!strcasecmp(name, "TargetRelayAgent"))
		{
			if (valSize != 4)
			{
				sprintf(logBuff, "Warning: section [%s] invalid value %s, option ignored", sectionName, raw);
				logDHCPMess(logBuff, 1);
			}
			else if (!strcasecmp(sectionName, RANGESET))
			{
				cfig.rangeSet[optionData->rangeSetInd].targetIP = fIP(value);
				//printf("TARGET IP %s set RangeSetInd  %d\n", IP2String(ipbuff, cfig.rangeSet[optionData->rangeSetInd].targetIP), optionData->rangeSetInd);
			}
			else
			{
				sprintf(logBuff, "Warning: section [%s] option %s not allowed in this section, option ignored", sectionName, raw);
				logDHCPMess(logBuff, 1);
			}
			continue;
		}

		opTag = 0;

		if (isInt(name))
		{
			if (atoi(name) < 1 || atoi(name) >= 254)
			{
				sprintf(logBuff, "Warning: section [%s] invalid option %s, ignored", sectionName, raw);
				logDHCPMess(logBuff, 1);
				continue;
			}

			opTag = atoi(name);
			opType = 0;
		}

		for (MYBYTE i = 0; i < maxInd; i++)
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
			logDHCPMess(logBuff, 1);
			continue;
		}

		if (!opType)
			opType = valType;

		//sprintf(logBuff, "Tag %i ValType %i opType %i value=%s size=%u", opTag, valType, opType, value, valSize);
		//logDHCPMess(logBuff, 1);

		if (op_specified[opTag])
		{
			sprintf(logBuff, "Warning: section [%s] duplicate option %s, ignored", sectionName, raw);
			logDHCPMess(logBuff, 1);
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
				logDHCPMess(logBuff, 1);
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
					logDHCPMess(logBuff, 1);
				}
				else if (opTag == DHCP_OPTION_DOMAINNAME)
				{
					sprintf(logBuff, "Warning: section [%s] option %u should be under [DOMAIN_NAME], ignored", sectionName, opTag);
					logDHCPMess(logBuff, 1);
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
					logDHCPMess(logBuff, 1);
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
						logDHCPMess(logBuff, 1);
						continue;
					}
					else if (opType == 8 && valSize % 8)
					{
						sprintf(logBuff, "Warning: section [%s] option %s, some values not in IP/Mask form, option ignored", sectionName, raw);
						logDHCPMess(logBuff, 1);
						continue;
					}

					if (opTag == DHCP_OPTION_NETMASK)
					{
						if (valSize != 4 || !checkMask(fIP(value)))
						{
							sprintf(logBuff, "Warning: section [%s] Invalid subnetmask %s, option ignored", sectionName, raw);
							logDHCPMess(logBuff, 1);
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
						logDHCPMess(logBuff, 1);
					}
				}
				else
				{
					sprintf(logBuff, "Warning: section [%s] option %s, Invalid value, should be one or more IP/4 Bytes", sectionName, raw);
					logDHCPMess(logBuff, 1);
				}
			}
			break;

			case 4:
			{
				MYDWORD j;

				if (valType == 2 && valSize == 4)
					j = fULong(value);
				else if (valType >= 4 && valType <= 6)
					j = atol(value);
				else
				{
					sprintf(logBuff, "Warning: section [%s] option %s, value should be integer between 0 & %u or 4 bytes, option ignored", sectionName, name, UINT_MAX);
					logDHCPMess(logBuff, 1);
					continue;
				}

				if (opTag == DHCP_OPTION_IPADDRLEASE)
				{
					if (j == 0)
						j = UINT_MAX;

					if (!strcasecmp(sectionName, GLOBALOPTIONS))
					{
						sprintf(logBuff, "Warning: section [%s] option %s not allowed in this section, please set it in [TIMINGS] section", sectionName, raw);
						logDHCPMess(logBuff, 1);
						continue;
					}
					else if (j < cfig.lease)
					{
						sprintf(logBuff, "Warning: section [%s] option %s value should be more then %u (Default Lease), ignored", sectionName, name, cfig.lease);
						logDHCPMess(logBuff, 1);
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
					logDHCPMess(logBuff, 1);
				}
			}
			break;

			case 5:
			{
				MYWORD j;

				if (valType == 2 && valSize == 2)
					j = fUShort(value);
				else if (valType == 5 || valType == 6)
					j = atol(value);
				else
				{
					sprintf(logBuff, "Warning: section [%s] option %s, value should be between 0 & %u or 2 bytes, option ignored", sectionName, name, USHRT_MAX);
					logDHCPMess(logBuff, 1);
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
					logDHCPMess(logBuff, 1);
				}
			}
			break;

			case 6:
			{
				MYBYTE j;

				if (valType == 2 && valSize == 1)
					j = *value;
				else if (valType == 6)
					j = atol(value);
				else
				{
					sprintf(logBuff, "Warning: section [%s] option %s, value should be between 0 & %u or single byte, option ignored", sectionName, name, UCHAR_MAX);
					logDHCPMess(logBuff, 1);
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
					logDHCPMess(logBuff, 1);
				}
			}
			break;

			case 7:
			{
				MYBYTE j;

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
					logDHCPMess(logBuff, 1);
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
					logDHCPMess(logBuff, 1);
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
					logDHCPMess(logBuff, 1);
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
					logDHCPMess(logBuff, 1);
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
		MYBYTE n = sizeof(opData) / sizeof(data4);

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
				MYBYTE valueSize = 0;

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

				for (MYBYTE i = 0; i < valueSize; i += 4)
				{
					MYDWORD ip = *((MYDWORD*)&(hoption[i]));

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
	MYDWORD rs = 0;
	MYDWORD re = 0;
	char name[512];
	char value[512];
	mySplit(name, value, dp, '-');

	if (isIP(name) && isIP(value))
	{
		rs = htonl(inet_addr(name));
		re = htonl(inet_addr(value));

		if (rs && re && rs <= re)
		{
			data13 *range;
			MYBYTE m = 0;

			for (; m < MAX_DHCP_RANGES && cfig.dhcpRanges[m].rangeStart; m++)
			{
				range = &cfig.dhcpRanges[m];

				if ((rs >= range->rangeStart && rs <= range->rangeEnd)
						|| (re >= range->rangeStart && re <= range->rangeEnd)
						|| (range->rangeStart >= rs && range->rangeStart <= re)
						|| (range->rangeEnd >= rs && range->rangeEnd <= re))
				{
					sprintf(logBuff, "Warning: DHCP Range %s overlaps with another range, ignored", dp);
					logDHCPMess(logBuff, 1);
					return;
				}
			}

			if (m < MAX_DHCP_RANGES)
			{
				cfig.dhcpSize += (re - rs + 1);
				range = &cfig.dhcpRanges[m];
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
					logDHCPMess(logBuff, 1);
					return;
				}
			}
		}
		else
		{
			sprintf(logBuff, "Section [%s] Invalid DHCP range %s in ini file, ignored", RANGESET, dp);
			logDHCPMess(logBuff, 1);
		}
	}
	else
	{
		sprintf(logBuff, "Section [%s] Invalid DHCP range %s in ini file, ignored", RANGESET, dp);
		logDHCPMess(logBuff, 1);
	}
}

void addVendClass(MYBYTE rangeSetInd, char *vendClass, MYBYTE vendClassSize)
{
	char logBuff[512];
	data14 *rangeSet = &cfig.rangeSet[rangeSetInd];

	MYBYTE i = 0;

	for (; i <= MAX_RANGE_FILTERS && rangeSet->vendClassSize[i]; i++);

	if (i >= MAX_RANGE_FILTERS || !vendClassSize)
		return;

	rangeSet->vendClass[i] = (MYBYTE*)calloc(vendClassSize, 1);

	if(!rangeSet->vendClass[i])
	{
		sprintf(logBuff, "Vendor Class Load, Memory Allocation Error");
		logDHCPMess(logBuff, 1);
	}
	else
	{
		cfig.hasFilter = true;
		rangeSet->vendClassSize[i] = vendClassSize;
		memcpy(rangeSet->vendClass[i], vendClass, vendClassSize);
		//printf("Loaded Vendor Class %s Size=%i rangeSetInd=%i Ind=%i\n", rangeSet->vendClass[i], rangeSet->vendClassSize[i], rangeSetInd, i);
		//printf("Loaded Vendor Class %s Size=%i rangeSetInd=%i Ind=%i\n", hex2String(tempbuff, rangeSet->vendClass[i], rangeSet->vendClassSize[i], ':'), rangeSet->vendClassSize[i], rangeSetInd, i);
	}
}

void addUserClass(MYBYTE rangeSetInd, char *userClass, MYBYTE userClassSize)
{
	char logBuff[512];
	data14 *rangeSet = &cfig.rangeSet[rangeSetInd];

	MYBYTE i = 0;

	for (; i <= MAX_RANGE_FILTERS && rangeSet->userClassSize[i]; i++);

	if (i >= MAX_RANGE_FILTERS || !userClassSize)
		return;

	rangeSet->userClass[i] = (MYBYTE*)calloc(userClassSize, 1);

	if(!rangeSet->userClass[i])
	{
		sprintf(logBuff, "Vendor Class Load, Memory Allocation Error");
		logDHCPMess(logBuff, 1);
	}
	else
	{
		cfig.hasFilter = true;
		rangeSet->userClassSize[i] = userClassSize;
		memcpy(rangeSet->userClass[i], userClass, userClassSize);
		//printf("Loaded User Class %s Size=%i rangeSetInd=%i Ind=%i\n", hex2String(tempbuff, rangeSet->userClass[i], rangeSet->userClassSize[i], ':'), rangeSet->vendClassSize[i], rangeSetInd, i);
	}
}

void addMacRange(MYBYTE rangeSetInd, char *macRange)
{
	char logBuff[512];

	if (macRange[0])
	{
		data14 *rangeSet = &cfig.rangeSet[rangeSetInd];

		MYBYTE i = 0;

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
			logDHCPMess(logBuff, 1);
		}
		else
		{
			MYBYTE macSize1 = 16;
			MYBYTE macSize2 = 16;
			MYBYTE *macStart = (MYBYTE*)calloc(1, macSize1);
			MYBYTE *macEnd = (MYBYTE*)calloc(1, macSize2);

			if(!macStart || !macEnd)
			{
				sprintf(logBuff, "DHCP Range Load, Memory Allocation Error");
				logDHCPMess(logBuff, 1);
			}
			else if (getHexValue(macStart, name, &macSize1) || getHexValue(macEnd, value, &macSize2))
			{
				sprintf(logBuff, "Section [%s], Invalid character in Filter_Mac_Range %s", RANGESET, macRange);
				logDHCPMess(logBuff, 1);
				free(macStart);
				free(macEnd);
			}
			else if (memcmp(macStart, macEnd, 16) > 0)
			{
				sprintf(logBuff, "Section [%s], Invalid Filter_Mac_Range %s, (higher bound specified on left), ignored", RANGESET, macRange);
				logDHCPMess(logBuff, 1);
				free(macStart);
				free(macEnd);
			}
			else if (macSize1 != macSize2)
			{
				sprintf(logBuff, "Section [%s], Invalid Filter_Mac_Range %s, (start/end size mismatched), ignored", RANGESET, macRange);
				logDHCPMess(logBuff, 1);
				free(macStart);
				free(macEnd);
			}
			else
			{
				cfig.hasFilter = true;
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
		data20 optionData;
		loadOptions(f, GLOBALOPTIONS, &optionData);
		cfig.options = (MYBYTE*)calloc(1, optionData.optionSize);
		memcpy(cfig.options, optionData.options, optionData.optionSize);
		cfig.mask = optionData.mask;
	}

	if (!cfig.mask)
		cfig.mask = inet_addr("255.255.255.0");

	for (MYBYTE i = 1; i <= MAX_RANGE_SETS ; i++)
	{
		if (f = openSection(RANGESET, i))
		{
			MYBYTE m = cfig.rangeCount;
			data20 optionData;
			optionData.rangeSetInd = i - 1;
			loadOptions(f, RANGESET, &optionData);
			MYBYTE *options = NULL;
			cfig.rangeSet[optionData.rangeSetInd].active = true;

			if (optionData.optionSize > 3)
			{
				options = (MYBYTE*)calloc(1, optionData.optionSize);
				memcpy(options, optionData.options, optionData.optionSize);
			}

			for (; m < MAX_DHCP_RANGES && cfig.dhcpRanges[m].rangeStart; m++)
			{
				cfig.dhcpRanges[m].rangeSetInd = optionData.rangeSetInd;
				cfig.dhcpRanges[m].options = options;
				cfig.dhcpRanges[m].mask = optionData.mask;
			}
			cfig.rangeCount = m;
		}
		else
			break;
	}

	//printf("%s\n", IP2String(ipbuff, cfig.mask));

	for (char rangeInd = 0; rangeInd < cfig.rangeCount; rangeInd++)
	{
		if (!cfig.dhcpRanges[rangeInd].mask)
			cfig.dhcpRanges[rangeInd].mask = cfig.mask;

		for (MYDWORD iip = cfig.dhcpRanges[rangeInd].rangeStart; iip <= cfig.dhcpRanges[rangeInd].rangeEnd; iip++)
		{
			MYDWORD ip = htonl(iip);

			if ((cfig.dhcpRanges[rangeInd].mask | (~ip)) == UINT_MAX || (cfig.dhcpRanges[rangeInd].mask | ip) == UINT_MAX)
				cfig.dhcpRanges[rangeInd].expiry[iip - cfig.dhcpRanges[rangeInd].rangeStart] = INT_MAX;
		}
	}

	if (f = openSection(GLOBALOPTIONS, 1))
		lockOptions(f);

	for (MYBYTE i = 1; i <= MAX_RANGE_SETS ;i++)
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

			MYBYTE hexValue[UCHAR_MAX];
			MYBYTE hexValueSize = sizeof(hexValue);
			data20 optionData;

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
							memset(&lump, 0, sizeof(data71));
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
								logDHCPMess(logBuff, 1);
								return;
							}

							dhcpEntry->mapname = cloneString(mapname);

							if (!dhcpEntry->mapname)
							{
								sprintf(logBuff, "Host Data Load, Memory Allocation Error");
								logDHCPMess(logBuff, 1);
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
							logDHCPMess(logBuff, 1);
						}
					}
					else
					{
						sprintf(logBuff, "Duplicate Static DHCP Host [%s] ignored", sectionName);
						logDHCPMess(logBuff, 1);
					}
				}
				else
				{
					sprintf(logBuff, "Invalid Static DHCP Host MAC Addr size, ignored", sectionName);
					logDHCPMess(logBuff, 1);
				}
			}
			else
			{
				sprintf(logBuff, "Invalid Static DHCP Host MAC Addr [%s] ignored", sectionName);
				logDHCPMess(logBuff, 1);
			}

			if (!optionData.ip)
			{
				sprintf(logBuff, "Warning: No IP Address for DHCP Static Host %s specified", sectionName);
				logDHCPMess(logBuff, 1);
			}
		}

		fclose(ff);
	}

	ff = fopen(leaFile, "rb");

	if (ff)
	{
		data8 dhcpData;

		while (fread(&dhcpData, sizeof(data8), 1, ff))
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
					memset(&lump, 0, sizeof(data71));
					lump.cType = CTYPE_DHCP_ENTRY;
					lump.mapname = mapname;
					dhcpEntry = createCache(&lump);
/*
					dhcpEntry = (CachedData*)calloc(1, sizeof(CachedData));

					if (!dhcpEntry)
					{
						sprintf(logBuff, "Loading Existing Leases, Memory Allocation Error");
						logDHCPMess(logBuff, 1);
						return;
					}

					dhcpEntry->mapname = cloneString(mapname);

					if (!dhcpEntry->mapname)
					{
						sprintf(logBuff, "Loading Existing Leases, Memory Allocation Error");
						free(dhcpEntry);
						logDHCPMess(logBuff, 1);
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

					if (dnsService && dhcpData.hostname[0] && cfig.replication != 2 && dhcpData.expiry > t)
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
		cfig.dhcpInd = 0;

		if (ff)
		{
			dhcpMap::iterator p = dhcpCache.begin();

			for (; p != dhcpCache.end(); p++)
			{
				if ((dhcpEntry = p->second) && (dhcpEntry->expiry > t || !dhcpEntry->fixed))
				{
					memset(&dhcpData, 0, sizeof(data8));
					dhcpData.bp_hlen = 16;
					getHexValue(dhcpData.bp_chaddr, dhcpEntry->mapname, &dhcpData.bp_hlen);
					dhcpData.ip = dhcpEntry->ip;
					dhcpData.expiry = dhcpEntry->expiry;
					dhcpData.local = dhcpEntry->local;

					if (dhcpEntry->hostname)
						strcpy(dhcpData.hostname, dhcpEntry->hostname);

					cfig.dhcpInd++;
					dhcpData.dhcpInd = cfig.dhcpInd;
					dhcpEntry->dhcpInd = cfig.dhcpInd;
					fwrite(&dhcpData, sizeof(data8), 1, ff);
				}
			}
			fclose(ff);
		}
	}
}

bool getSection(const char *sectionName, char *buffer, MYBYTE serial, char *fileName)
{
	//printf("%s=%s\n",fileName,sectionName);
	char section[128];
	sprintf(section, "[%s]", sectionName);
	myUpper(section);
	FILE *f = fopen(fileName, "rt");
	char buff[512];
	MYBYTE found = 0;

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

FILE *openSection(const char *sectionName, MYBYTE serial)
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
		MYBYTE found = 0;

		while (fgets(buff, 511, f))
		{
			myUpper(buff);
			myTrim(buff, buff);

			if (strstr(buff, section) == buff)
			{
				found++;

				if (found == serial)
				{
					MYDWORD fpos = ftell(f);

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
								logMess(logBuff, 1);
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

char* myGetToken(char* buff, MYBYTE index)
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

MYWORD myTokenize(char *target, char *source, const char *sep, bool whiteSep)
{
	bool found = true;
	char *dp = target;
	MYWORD kount = 0;

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

char *strquery(data5 *req)
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

MYDWORD getClassNetwork(MYDWORD ip)
{
	data15 data;
	data.ip = ip;
	data.octate[3] = 0;

	if (data.octate[0] < 192)
		data.octate[2] = 0;

	if (data.octate[0] < 128)
		data.octate[1] = 0;

	return data.ip;
}

/*
char *IP2Auth(MYDWORD ip)
{
data15 data;
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

char *IP2String(char *target, MYDWORD ip, MYBYTE dnsType)
{
	char *dp = target;
	(*dp) = dnsType;
	dp++;
	data15 inaddr;
	inaddr.ip = ip;
	sprintf(dp, "%u.%u.%u.%u", inaddr.octate[0], inaddr.octate[1], inaddr.octate[2], inaddr.octate[3]);
	//MYBYTE *octate = (MYBYTE*)&ip;
	//sprintf(target, "%u.%u.%u.%u", octate[0], octate[1], octate[2], octate[3]);
	return target;
}

char *IP2String(char *target, MYDWORD ip)
{
	data15 inaddr;
	inaddr.ip = ip;
	sprintf(target, "%u.%u.%u.%u", inaddr.octate[0], inaddr.octate[1], inaddr.octate[2], inaddr.octate[3]);
	//MYBYTE *octate = (MYBYTE*)&ip;
	//sprintf(target, "%u.%u.%u.%u", octate[0], octate[1], octate[2], octate[3]);
	return target;
}

MYBYTE addServer(MYDWORD *array, MYBYTE maxServers, MYDWORD ip)
{
	if (ip)
	{
		for (MYBYTE i = 0; i < maxServers; i++)
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

MYDWORD *findServer(MYDWORD *array, MYBYTE maxServers, MYDWORD ip)
{
	if (ip)
	{
		for (MYBYTE i = 0; i < maxServers && array[i]; i++)
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

	MYDWORD ip = inet_addr(str);

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
char *toBase64(MYBYTE *source, MYBYTE length)
{
	MYBYTE a = 0, b = 0, i = 0;
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

MYBYTE getBaseValue(MYBYTE a)
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

MYBYTE fromBase64(MYBYTE *target, char *source)
{
	//printf("SOURCE=%s\n", source);
	MYBYTE b = 0;
	MYBYTE shift = 4;
	MYBYTE bp_hlen = (3 * strlen(source))/4;
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

char *toUUE(char *tempbuff, MYBYTE *source, MYBYTE length)
{
	MYBYTE a = 0, b = 0, i = 0;
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

MYBYTE fromUUE(MYBYTE *target, char *source)
{
	//printf("SOURCE=%s\n", source);
	MYBYTE b = 0;
	MYBYTE shift = 4;
	MYBYTE bp_hlen = (3 * strlen(source))/4;
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
char *hex2String(char *target, MYBYTE *hex, MYBYTE bytes)
{
	char *dp = target;

	if (bytes)
		dp += sprintf(target, "%02x", *hex);
	else
		*target = 0;

	for (MYBYTE i = 1; i < bytes; i++)
			dp += sprintf(dp, ":%02x", *(hex + i));

	return target;
}

char *genHostName(char *target, MYBYTE *hex, MYBYTE bytes)
{
	char *dp = target;

	if (bytes)
		dp += sprintf(target, "Host%02x", *hex);
	else
		*target = 0;

	for (MYBYTE i = 1; i < bytes; i++)
			dp += sprintf(dp, "%02x", *(hex + i));

	return target;
}

/*
char *IP62String(char *target, MYBYTE *source)
{
	MYWORD *dw = (MYWORD*)source;
	char *dp = target;
	MYBYTE markbyte;

	for (markbyte = 4; markbyte > 0 && !dw[markbyte - 1]; markbyte--);

	for (MYBYTE i = 0; i < markbyte; i++)
		dp += sprintf(dp, "%x:", ntohs(dw[i]));

	for (markbyte = 4; markbyte < 8 && !dw[markbyte]; markbyte++);

	for (MYBYTE i = markbyte; i < 8; i++)
		dp += sprintf(dp, ":%x", htons(dw[i]));

	return target;
}
*/

char *IP62String(char *target, MYBYTE *source)
{
	char *dp = target;
	bool zerostarted = false;
	bool zeroended = false;

	for (MYBYTE i = 0; i < 16; i += 2, source += 2)
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

char *getHexValue(MYBYTE *target, char *source, MYBYTE *size)
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
	MYWORD len = strlen(string);
	for (int i = 0; i < len; i++)
		if (string[i] >= 'a' && string[i] <= 'z')
			string[i] -= diff;
	return string;
}

char *myLower(char *string)
{
	char diff = 'a' - 'A';
	MYWORD len = strlen(string);
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

bool isLocal(MYDWORD ip)
{
	if (cfig.rangeStart && htonl(ip) >= cfig.rangeStart && htonl(ip) <= cfig.rangeEnd)
		return true;
//	else if (getRangeInd(ip) >= 0)
//		return true;
	else
		return false;
}

char *setMapName(char *tempbuff, char *mapname, MYBYTE dnsType)
{
	char *dp = tempbuff;
	(*dp) = dnsType;
	dp++;
	strcpy(dp, mapname);
	myLower(dp);
	return tempbuff;
}

MYBYTE makeLocal(char *mapname)
{
	if (!strcasecmp(mapname, cfig.zone))
	{
		mapname[0] = 0;
		return QTYPE_A_ZONE;
	}
	else if (!strcasecmp(mapname, cfig.authority))
	{
		//char *dp = strstr(mapname, arpa);
		//(*dp) = 0;
		return QTYPE_P_ZONE;
	}
	else if (char *dp = strchr(mapname, '.'))
	{
		if (!strcasecmp(dp + 1, cfig.zone))
		{
			*dp = 0;
			return QTYPE_A_LOCAL;
		}
		else if (dp = strstr(mapname, arpa))
		{
			if (strstr(mapname, cfig.authority))
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

		logDNSMess(logBuff, 1);
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
		logDHCPMess(logBuff, 1);
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
	//MYBYTE maxDelete = 3;

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
			//logMess(logBuff, 1);
		}
		else if (cache)
		{
			if (cache->cType == CTYPE_QUEUE && cache->expiry)
			{
				if (cache->dnsIndex < MAX_SERVERS)
				{
					if (network.currentDNS == cache->dnsIndex)
					{
						if (network.dns[1])
						{
							network.currentDNS++;

							if (network.currentDNS >= MAX_SERVERS || !network.dns[network.currentDNS])
								network.currentDNS = 0;
						}
					}
				}
				else if (cache->dnsIndex >= 128 && cache->dnsIndex < 192)
				{
					data10 *dnsRoute = &cfig.dnsRoutes[(cache->dnsIndex - 128) / 2];
					MYBYTE currentDNS = cache->dnsIndex % 2;

					if (dnsRoute->currentDNS == currentDNS && dnsRoute->dns[1])
						dnsRoute->currentDNS = 1 - dnsRoute->currentDNS;
				}
			}

			if (cfig.replication != 2)
			{
				if (cache->cType == CTYPE_LOCAL_A)
					cfig.serial1 = t;
				else if (cache->cType == CTYPE_LOCAL_PTR_AUTH)
					cfig.serial2 = t;
			}

			//sprintf(logBuff, "Data Type=%u Cache Size=%u, Age Size=%u, Entry %s being deleted", cache->cType, dnsCache[currentInd].size(), dnsAge[currentInd].size(), cache->name);
			//logMess(logBuff, 1);
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

void calcRangeLimits(MYDWORD ip, MYDWORD mask, MYDWORD *rangeStart, MYDWORD *rangeEnd)
{
	*rangeStart = htonl(ip & mask) + 1;
	*rangeEnd = htonl(ip | (~mask)) - 1;
}

bool checkMask(MYDWORD mask)
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

MYDWORD calcMask(MYDWORD rangeStart, MYDWORD rangeEnd)
{
	data15 ip1, ip2, mask;

	ip1.ip = htonl(rangeStart);
	ip2.ip = htonl(rangeEnd);

	for (MYBYTE i = 0; i < 4; i++)
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

char *findHost(char *tempbuff, MYDWORD ip)
{
	IP2String(tempbuff, htonl(ip));
	CachedData *cache = findEntry(tempbuff, DNS_TYPE_PTR);

	if (cache)
		strcpy(tempbuff, cache->hostname);
	else
		tempbuff[0] = 0;

	return tempbuff;
}

CachedData *findEntry(char *key, MYBYTE dnsType, MYBYTE cType)
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

CachedData *findEntry(char *key, MYBYTE dnsType)
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


MYDWORD getSerial(char *zone)
{
	char tempbuff[512];
	char logBuff[512];
	char ipbuff[32];
	MYDWORD serial1 = 0;
	data5 req;
	memset(&req, 0, sizeof(data5));
	req.remote.sin_family = AF_INET;
	req.remote.sin_port = htons(IPPORT_DNS);
	timeval tv1;
	fd_set readfds1;

	if (cfig.replication == 2)
		req.remote.sin_addr.s_addr = cfig.zoneServers[0];
	else
		req.remote.sin_addr.s_addr = cfig.zoneServers[1];

	req.sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	req.dnsp = (dnsPacket*)req.raw;
	req.dnsp->header.qdcount = htons(1);
	req.dnsp->header.rd = false;
	req.dnsp->header.xid = (t % USHRT_MAX);
	req.dp = &req.dnsp->data;
	req.dp += pQu(req.dp, zone);
	req.dp += pUShort(req.dp, DNS_TYPE_SOA);
	req.dp += pUShort(req.dp, DNS_CLASS_IN);
	req.bytes = req.dp - req.raw;
	//pUShort(req.raw, req.bytes - 2);

	if ((req.bytes = sendto(req.sock, req.raw, req.bytes, 0, (sockaddr*)&req.remote, sizeof(req.remote))) <= 0)
	{
		closesocket(req.sock);
		sprintf(logBuff, "Failed to send request to Primary Server %s", IP2String(ipbuff, req.remote.sin_addr.s_addr));
		logDNSMess(logBuff, 1);
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

		if (req.bytes > 0 && !req.dnsp->header.rcode && req.dnsp->header.qr && ntohs(req.dnsp->header.ancount))
		{
			req.dp = &req.dnsp->data;

			for (int j = 1; j <= ntohs(req.dnsp->header.qdcount); j++)
			{
				req.dp += fQu(tempbuff, req.dnsp, req.dp);
				req.dp += 4;
			}

			for (int i = 1; i <= ntohs(req.dnsp->header.ancount); i++)
			{
				req.dp += fQu(tempbuff, req.dnsp, req.dp);
				req.dnsType = fUShort(req.dp);
				req.dp += 2; //type
				req.qclass = fUShort(req.dp);
				req.dp += 2; //class
				fULong(req.dp);
				req.dp += 4; //ttl
				req.dp += 2; //datalength

				if (req.dnsType == DNS_TYPE_SOA)
				{
					req.dp += fQu(tempbuff, req.dnsp, req.dp);
					req.dp += fQu(tempbuff, req.dnsp, req.dp);
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
			//logDNSMess(logBuff, 1);
			return 0;
		}
	}

	closesocket(req.sock);
	sprintf(logBuff, "Failed to contact the Primary Server %s", IP2String(ipbuff, req.remote.sin_addr.s_addr));
	logDNSMess(logBuff, 1);
	return 0;
}

void sendServerName()
{
	errno = 0;
	data5 req;
	memset(&req, 0, sizeof(data5));
	req.remote.sin_family = AF_INET;
	req.remote.sin_port = htons(IPPORT_DNS);
	req.remote.sin_addr.s_addr = cfig.zoneServers[0];

	timeval tv1;
	fd_set readfds1;

	req.sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	req.dnsp = (dnsPacket*)req.raw;
	req.dnsp->header.opcode = OPCODE_DYNAMIC_UPDATE;
	req.dnsp->header.qr = true;
	req.dnsp->header.zcount = htons(1);
	req.dnsp->header.prcount = htons(1);
	req.dnsp->header.xid = (t % USHRT_MAX);
	req.dp = &req.dnsp->data;
	req.dp += pQu(req.dp, cfig.zone);
	req.dp += pUShort(req.dp, DNS_TYPE_SOA);
	req.dp += pUShort(req.dp, DNS_CLASS_IN);
	req.dp += pQu(req.dp, cfig.servername_fqn);
	req.dp += pUShort(req.dp, DNS_TYPE_A);
	req.dp += pUShort(req.dp, DNS_CLASS_IN);
	req.dp += pULong(req.dp, 0);
	req.dp += pUShort(req.dp, 4);
	req.dp += pIP(req.dp, cfig.zoneServers[1]);
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

MYWORD recvTcpDnsMess(char *target, SOCKET sock, MYWORD targetSize)
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
			MYWORD rcd = chunk;
			MYWORD bytes = fUShort(target) + rcd;

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

void emptyCache(MYBYTE ind)
{
	//debug("emptyCache");
	char logBuff[512];
	CachedData *cache = NULL;

	//sprintf(logBuff, "Emptying cache[%d] Start %d=%d",ind, dnsCache[ind].size(), dnsAge[ind].size());
	//logMess(logBuff, 2);

	cfig.mxCount[ind] = 0;
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
	Sleep(1000*(cfig.refresh));

	while (kRunning)
	{
//		//if (!dhcpService && !findEntry(IP2String(ipbuff, htonl(cfig.zoneServers[1])), DNS_TYPE_PTR))
//		if (!dhcpService)
//			sendServerName();

		MYBYTE updateInd = !magin->currentInd;
		emptyCache(updateInd);
		sprintf(logBuff, "Checking Serial from Primary Server %s", IP2String(ipbuff, cfig.zoneServers[0]));
		logDNSMess(logBuff, 2);

		MYDWORD serial1 = getSerial(cfig.zone);
		MYDWORD serial2 = 0;

		if (serial1)
			serial2 = getSerial(cfig.authority);

		if (!serial1 || !serial2)
		{
			//cfig.dnsRepl = 0;
			//cfig.dhcpRepl = 0;
			sprintf(logBuff, "Failed to get SOA from Primary Server, waiting %i seconds to retry", cfig.retry);
			logDNSMess(logBuff, 1);
			Sleep(1000*(cfig.retry));
			continue;
		}
		else if (cfig.serial1 && cfig.serial1 == serial1 && cfig.serial2 && cfig.serial2 == serial2)
		{
			if (cfig.refresh > (MYDWORD)(INT_MAX - t))
				cfig.dnsRepl = INT_MAX;
			else
				cfig.dnsRepl = t + cfig.refresh + cfig.retry + cfig.retry;

			if (cfig.expire > (MYDWORD)(INT_MAX - t))
				cfig.expireTime = INT_MAX;
			else
				cfig.expireTime = t + cfig.expire;

			sprintf(logBuff, "Zone Refresh not required");
			logDNSMess(logBuff, 2);
			Sleep(1000*(cfig.refresh));
		}
		else
		{
			//WaitForSingleObject(rEvent, INFINITE);
			serial1 = getZone(updateInd, cfig.zone);
			Sleep(5*1000);

			if (serial1)
				serial2 = getZone(updateInd, cfig.authority);
			//SetEvent(rEvent);

			if (!serial1 || !serial2)
			{
				sprintf(logBuff, "Waiting %u seconds to retry", cfig.retry);
				logDNSMess(logBuff, 1);
				Sleep(1000*(cfig.retry));
			}
			else
			{
				if (cfig.refresh > (MYDWORD)(INT_MAX - t))
					cfig.dnsRepl = INT_MAX;
				else
					cfig.dnsRepl = t + cfig.refresh + cfig.retry + cfig.retry;

				magin->currentInd = updateInd;
				magin->done = true;
				cfig.serial1 = serial1;
				cfig.serial2 = serial2;

				if (cfig.expire > (MYDWORD)(INT_MAX - t))
					cfig.expireTime = INT_MAX;
				else
					cfig.expireTime = t + cfig.expire;

				Sleep(1000*(cfig.refresh));
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

MYDWORD getZone(MYBYTE ind, char *zone)
{
	data71 lump;
	char tempbuff[512];
	char ipbuff[16];
	char logBuff[512];
	char localhost[] = "localhost";
	char localhost_ip[] = "1.0.0.127";
	MYDWORD serial1 = 0;
	MYDWORD serial2 = 0;
	MYDWORD hostExpiry = 0;
	MYDWORD refresh = 0;
	MYDWORD retry = 0;
	MYDWORD expire = 0;
	MYDWORD expiry;
	MYDWORD minimum = 0;
	int added = 0;
	char *data;
	char *dp;
	MYDWORD ip;
	data5 req;
	CachedData *cache = NULL;

	memset(&lump, 0, sizeof(data71));
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

	memset(&lump, 0, sizeof(data71));
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

	memset(&req, 0, sizeof(data5));
	req.sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (req.sock == INVALID_SOCKET)
	{
		sprintf(logBuff, "Failed to Create Socket, Zone Transfer Failed");
		logDNSMess(logBuff, 1);
		return 0;
	}

	req.addr.sin_family = AF_INET;
	req.addr.sin_addr.s_addr = cfig.zoneServers[1];
	req.addr.sin_port = 0;

	int nRet = bind(req.sock, (sockaddr*)&req.addr, sizeof(req.addr));

	if (nRet == SOCKET_ERROR)
	{
		closesocket(req.sock);
		sprintf(logBuff, "Error: Interface %s not ready, Zone Transfer Failed", IP2String(ipbuff, req.addr.sin_addr.s_addr));
		logDNSMess(logBuff, 1);
		return 0;
	}

	req.remote.sin_family = AF_INET;
	req.remote.sin_port = htons(IPPORT_DNS);
	req.remote.sin_addr.s_addr = cfig.zoneServers[0];

	req.sockLen = sizeof(req.remote);

	if (connect(req.sock, (sockaddr*)&req.remote, req.sockLen) >= 0)
	{
		req.dp = req.raw;
		req.dp += 2;
		req.dnsp = (dnsPacket*)req.dp;
		req.dnsp->header.qdcount = htons(1);
		req.dnsp->header.xid = (t % USHRT_MAX);
		req.dp = &req.dnsp->data;
		req.dp += pQu(req.dp, zone);
		req.dp += pUShort(req.dp, DNS_TYPE_AXFR);
		req.dp += pUShort(req.dp, DNS_CLASS_IN);
		req.bytes = req.dp - req.raw;
		pUShort(req.raw, req.bytes - 2);

		if (send(req.sock, req.raw, req.bytes, 0) < req.bytes)
		{
			closesocket(req.sock);
			sprintf(logBuff, "Failed to contact Primary Server %s, Zone Transfer Failed", IP2String(ipbuff, req.remote.sin_addr.s_addr));
			logDNSMess(logBuff, 1);
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

			MYWORD pktSize = fUShort(req.raw);

			req.bytes = fread(req.raw, 1, pktSize, f);

			if ((MYWORD)req.bytes != pktSize)
			{
				fclose(f);
				return 0;
			}

			req.dnsp = (dnsPacket*)(req.raw);
			req.dp = &req.dnsp->data;
			char *dataend = req.raw + pktSize;

			if (req.dnsp->header.rcode)
			{
				sprintf(logBuff, "Primary Server %s, zone %s refused", IP2String(ipbuff, req.remote.sin_addr.s_addr), zone);
				logDNSMess(logBuff, 1);
				fclose(f);
				return 0;
			}

			if (!req.dnsp->header.qr || !ntohs(req.dnsp->header.ancount))
			{
				fclose(f);
				return 0;
			}

			for (int j = 1; j <= ntohs(req.dnsp->header.qdcount); j++)
			{
				req.dp += fQu(req.query, req.dnsp, req.dp);
				req.dp += 4;
			}

			for (int i = 1; i <= ntohs(req.dnsp->header.ancount); i++)
			{
				//char *dp = req.dp;
				req.dp += fQu(req.mapname, req.dnsp, req.dp);

				if (!req.mapname[0])
				{
					fclose(f);
					return 0;
				}

				//sprintf(logBuff, "%u=%s\n", pktSize, req.mapname);
				//logMess(logBuff, 2);

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

						data += fQu(req.cname, req.dnsp, data);
						data += fQu(tempbuff, req.dnsp, data);

						if (!cfig.nsP[0])
							strcpy(cfig.nsP, req.cname);

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
						memset(&lump, 0, sizeof(data71));
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
							fQu(req.cname, req.dnsp, data);
							makeLocal(req.cname);
							memset(&lump, 0, sizeof(data71));
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
							cfig.mxServers[ind][cfig.mxCount[ind]].pref = fUShort(data);
							data += sizeof(MYWORD);
							fQu(req.cname, req.dnsp, data);
							strcpy(cfig.mxServers[ind][cfig.mxCount[ind]].hostname, req.cname);
							cfig.mxCount[ind]++;
							added++;
						}
						break;

					case DNS_TYPE_NS:

						fQu(req.cname, req.dnsp, data);

						if (!cfig.nsS[0] && strcasecmp(cfig.nsP, req.cname))
							strcpy(cfig.nsS, req.cname);

						break;

					case DNS_TYPE_CNAME:

						makeLocal(req.mapname);
						fQu(req.cname, req.dnsp, data);
						memset(&lump, 0, sizeof(data71));

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
						//logDNSMess(logBuff, 2);

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
			if (cfig.replication == 2)
			{
				cfig.lease = hostExpiry;
				cfig.refresh = refresh;
				cfig.retry = retry;
				cfig.expire = expire;
				cfig.minimum = minimum;
			}

			//printf("Refresh ind %i serial %u size %i\n", ind, serial1, dnsCache[ind].size());
			sprintf(logBuff, "Zone %s Transferred from Primary Server, %u RRs imported", zone, added);
			logDNSMess(logBuff, 1);
			return serial1;
		}
		else
		{
			sprintf(logBuff, "Primary Server %s, zone %s Invalid AXFR data", IP2String(ipbuff, req.remote.sin_addr.s_addr), zone);
			logDNSMess(logBuff, 1);
		}
	}
	else
	{
		sprintf(logBuff, "Failed to contact Primary Server %s, Zone Transfer Failed", IP2String(ipbuff, req.remote.sin_addr.s_addr));
		logDNSMess(logBuff, 1);
		closesocket(req.sock);
		return 0;
	}
}

bool getSecondary()
{
	char logBuff[512];
	MYDWORD ip;
	MYDWORD hostExpiry = 0;
	MYDWORD expiry = 0;
	char *data = NULL;
	char *dp = NULL;
	MYWORD rr = 0;
	data5 req;
	MYDWORD serial = 0;

	memset(&req, 0, sizeof(data5));
	req.sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (req.sock == INVALID_SOCKET)
		return false;

	req.addr.sin_family = AF_INET;
	req.addr.sin_addr.s_addr = cfig.zoneServers[0];
	req.addr.sin_port = 0;

	int nRet = bind(req.sock, (sockaddr*)&req.addr, sizeof(req.addr));

	if (nRet == SOCKET_ERROR)
	{
		closesocket(req.sock);
		return false;
	}

	req.remote.sin_family = AF_INET;
	req.remote.sin_port = htons(IPPORT_DNS);

	if (dhcpService && cfig.replication == 1)
		req.remote.sin_addr.s_addr = cfig.zoneServers[1];
	else
		return false;

	req.sockLen = sizeof(req.remote);
	time_t t = time(NULL);

	if (connect(req.sock, (sockaddr*)&req.remote, req.sockLen) == 0)
	{
		req.dp = req.raw;
		req.dp += 2;
		req.dnsp = (dnsPacket*)req.dp;
		req.dnsp->header.qdcount = htons(1);
		req.dnsp->header.xid = (t % USHRT_MAX);
		req.dp = &req.dnsp->data;
		req.dp += pQu(req.dp, cfig.authority);
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

			MYWORD pktSize = fUShort(req.raw);
			req.bytes = fread(req.raw, 1, pktSize, f);

			if ((MYWORD)req.bytes != pktSize)
			{
				fclose(f);
				return false;
			}

			req.dnsp = (dnsPacket*)(req.raw);
			req.dp = &req.dnsp->data;
			char *dataend = req.raw + pktSize;

			if (req.dnsp->header.rcode)
			{
				fclose(f);
				return false;
			}

			if (!req.dnsp->header.qr || !ntohs(req.dnsp->header.ancount))
			{
				fclose(f);
				return false;
			}

			for (int j = 1; j <= ntohs(req.dnsp->header.qdcount); j++)
			{
				req.dp += fQu(req.query, req.dnsp, req.dp);
				req.dp += 4;
			}

			for (int i = 1; i <= ntohs(req.dnsp->header.ancount); i++)
			{
				//char *dp = req.dp;
				req.dp += fQu(req.mapname, req.dnsp, req.dp);

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
						fQu(req.cname, req.dnsp, data);
						makeLocal(req.cname);

						dhcpMap::iterator p = dhcpCache.begin();
						CachedData *dhcpEntry = NULL;

						for (; p != dhcpCache.end(); p++)
						{
							if ((dhcpEntry = p->second) && dhcpEntry->ip && dhcpEntry->hostname)
							{
								if (ip == dhcpEntry->ip && !strcasecmp(req.cname, dhcpEntry->hostname))
								{
									if (expiry < (MYDWORD)(INT_MAX - t))
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
		logDNSMess(logBuff, 2);
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

	memset(&cfig, 0, sizeof(cfig));
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

	cfig.dnsLogLevel = 1;
	cfig.dhcpLogLevel = 1;

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
		logDHCPMess(logBuff, 0);
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
						cfig.dnsLogLevel = 0;
					else if (!strcasecmp(value, "Normal"))
						cfig.dnsLogLevel = 1;
					else if (!strcasecmp(value, "All"))
						cfig.dnsLogLevel = 2;
					else
						sprintf(tempbuff, "Section [LOGGING], Invalid DNSLogLevel: %s", value);
				}
				else if (!strcasecmp(name, "DHCPLogLevel"))
				{
					if (!strcasecmp(value, "None"))
						cfig.dhcpLogLevel = 0;
					else if (!strcasecmp(value, "Normal"))
						cfig.dhcpLogLevel = 1;
					else if (!strcasecmp(value, "All"))
						cfig.dhcpLogLevel = 2;
//					else if (!strcasecmp(value, "Debug"))
//						cfig.dhcpLogLevel = 3;
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
			logMess(tempbuff, 1);

		sprintf(logBuff, "%s Starting...", sVersion);
		logMess(logBuff, 1);
	}
	else
	{
		sprintf(logBuff, "%s Starting...", sVersion);
		logMess(logBuff, 1);
	}

	MYWORD wVersionRequested = MAKEWORD(1, 1);
	WSAStartup(wVersionRequested, &cfig.wsaData);

	if (cfig.wsaData.wVersion != wVersionRequested)
	{
		sprintf(logBuff, "WSAStartup Error");
		logMess(logBuff, 1);
	}

	if (f = openSection("SERVICES", 1))
	{
		dhcpService = false;
		dnsService = false;

		while(readSection(raw, f))
			if (!strcasecmp(raw, "DNS"))
				dnsService = true;
			else if (!strcasecmp(raw, "DHCP"))
				dhcpService = true;
			else
			{
				sprintf(logBuff, "Section [SERVICES] invalid entry %s ignored", raw);
				logMess(logBuff, 1);
			}

		if (!dhcpService && !dnsService)
		{
			dhcpService = true;
			dnsService = true;
		}
	}

	if (dnsService)
	{
		sprintf(logBuff, "Starting DNS Service");
		logDNSMess(logBuff, 1);

		if (FILE *f = openSection("FORWARDING_SERVERS", 1))
		{
			while (readSection(raw, f))
			{
				if (isIP(raw))
				{
					MYDWORD addr = inet_addr(raw);
					addServer(cfig.specifiedDnsServers, MAX_SERVERS, addr);
				}
				else
				{
					sprintf(logBuff, "Section [FORWARDING_SERVERS] Invalid Entry: %s ignored", raw);
					logDNSMess(logBuff, 1);
				}
			}
		}
	}

	if (dhcpService)
	{
		sprintf(logBuff, "Starting DHCP Service");
		logDHCPMess(logBuff, 1);
	}

	if (dnsService)
	{
		if (cfig.dnsLogLevel == 3)
			sprintf(logBuff, "DNS Logging: All");
		else if (cfig.dnsLogLevel == 2)
			sprintf(logBuff, "DNS Logging: All");
		else if (cfig.dnsLogLevel == 1)
			sprintf(logBuff, "DNS Logging: Normal");
		else
			sprintf(logBuff, "DNS Logging: None");

		logDNSMess(logBuff, 1);
	}

	if (dhcpService)
	{
		if (cfig.dhcpLogLevel == 3)
			sprintf(logBuff, "DHCP Logging: Debug");
		else if (cfig.dhcpLogLevel == 2)
			sprintf(logBuff, "DHCP Logging: All");
		else if (cfig.dhcpLogLevel == 1)
			sprintf(logBuff, "DHCP Logging: Normal");
		else
			sprintf(logBuff, "DHCP Logging: None");

		logDHCPMess(logBuff, 1);
	}

	if (f = openSection("LISTEN_ON", 1))
	{
		while (readSection(raw, f))
		{
			if (isIP(raw))
			{
				MYDWORD addr = inet_addr(raw);
				addServer(cfig.specifiedServers, MAX_SERVERS, addr);
			}
			else
			{
				sprintf(logBuff, "Warning: Section [LISTEN_ON], Invalid Interface Address %s, ignored", raw);
				logMess(logBuff, 1);
			}
		}
	}

	cfig.lease = 36000;

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
						cfig.lease = atol(value);

						if (!cfig.lease)
							cfig.lease = UINT_MAX;
					}
					else if (!strcasecmp(name, "Refresh"))
						cfig.refresh = atol(value);
					else if (!strcasecmp(name, "Retry"))
						cfig.retry = atol(value);
					else if (!strcasecmp(name, "Expire"))
						cfig.expire = atol(value);
					else if (!strcasecmp(name, "Minimum"))
						cfig.minimum = atol(value);
					else if (!strcasecmp(name, "MinCacheTime"))
						cfig.minCache = atol(value);
					else if (!strcasecmp(name, "MaxCacheTime"))
						cfig.maxCache = atol(value);
					else
					{
						sprintf(logBuff, "Section [TIMINGS], Invalid Entry: %s ignored", raw);
						logDNSMess(logBuff, 1);
					}
				}
				else
				{
					sprintf(logBuff, "Section [TIMINGS], Invalid value: %s ignored", value);
					logDNSMess(logBuff, 1);
				}
			}
			else
			{
				sprintf(logBuff, "Section [TIMINGS], Missing value, entry %s ignored", raw);
				logDNSMess(logBuff, 1);
			}
		}
	}

	if (!cfig.refresh)
	{
		cfig.refresh = cfig.lease / 10;

		if (cfig.refresh > 3600)
			cfig.refresh = 3600;

		if (cfig.refresh < 300)
			cfig.refresh = 300;
	}

	if (!cfig.retry || cfig.retry > cfig.refresh)
	{
		cfig.retry = cfig.refresh / 5;

		if (cfig.retry > 600)
			cfig.retry = 600;

		if (cfig.retry < 60)
			cfig.retry = 60;
	}

	if (!cfig.expire)
	{
		if (UINT_MAX/24 > cfig.lease)
			cfig.expire = 24 * cfig.lease;
		else
			cfig.expire = UINT_MAX;
	}

	if (!cfig.minimum)
		cfig.minimum = cfig.retry;

	if (f = openSection("DOMAIN_NAME", 1))
	{
		while (readSection(raw, f))
		{
			mySplit(name, value, raw, '=');

			if (name[0] && value[0])
			{
				data15 mask;
				data15 network;
				char left[64];

				cfig.authority[0] = 0;
				myLower(value);
				mask.ip = 0;
				network.ip = 0;

				for (MYBYTE octateNum = 0; octateNum < 3; octateNum++)
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
						strcat(cfig.authority, left);
						strcat(cfig.authority, ".");
					}
					else
						break;

					if (!strcasecmp(value, arpa + 1))
						break;
				}

				if (!strcasecmp(value, arpa + 1))
				{
					strcat(cfig.authority, arpa + 1);
					cfig.aLen = strlen(cfig.authority);
					calcRangeLimits(network.ip, mask.ip, &cfig.rangeStart, &cfig.rangeEnd);
					//IP2String(logBuff, htonl(cfig.rangeStart));
					//logMess(logBuff, 1);
					//IP2String(logBuff, htonl(cfig.rangeEnd));
					//logMess(logBuff, 1);
					cfig.authorized = 1;
				}
				else
				{
					sprintf(logBuff, "Warning: Invalid Domain Name (Part %s), ignored", cfig.authority);
					cfig.aLen = 0;
					cfig.authority[0] = 0;
					logDNSMess(logBuff, 1);
				}
			}

			if (chkQu(name))
			{
				strcpy(cfig.zone, name);
				cfig.zLen = strlen(cfig.zone);
			}
			else
			{
				cfig.aLen = 0;
				cfig.authority[0] = 0;
				sprintf(logBuff, "Warning: Invalid Domain Name %s, ignored", raw);
				logDNSMess(logBuff, 1);
			}
		}
	}

	getInterfaces(&network);
	sprintf(cfig.servername_fqn, "%s.%s", cfig.servername, cfig.zone);

	if (f = openSection("ZONE_REPLICATION", 1))
	{
		int i = 2;
		while (readSection(raw, f))
		{
			if(i < MAX_TCP_CLIENTS)
			{
				if (dnsService && !cfig.authorized)
				{
					sprintf(logBuff, "Section [ZONE_REPLICATION], Server is not an authority, entry %s ignored", raw);
					logDNSMess(logBuff, 1);
					continue;
				}

				mySplit(name, value, raw, '=');

				if (name[0] && value[0])
				{
					if (chkQu(name) && !isIP(name) && isIP(value))
					{
						if (!strcasecmp(name, "Primary"))
							cfig.zoneServers[0] = inet_addr(value);
						else if (!strcasecmp(name, "Secondary"))
							cfig.zoneServers[1] = inet_addr(value);
						else if (dnsService && !strcasecmp(name, "AXFRClient"))
						{
							cfig.zoneServers[i] = inet_addr(value);
							i++;
						}
						else
						{
							sprintf(logBuff, "Section [ZONE_REPLICATION] Invalid Entry: %s ignored", raw);
							logDNSMess(logBuff, 1);
						}
					}
					else
					{
						sprintf(logBuff, "Section [ZONE_REPLICATION] Invalid Entry: %s ignored", raw);
						logDNSMess(logBuff, 1);
					}
				}
				else
				{
					sprintf(logBuff, "Section [ZONE_REPLICATION], Missing value, entry %s ignored", raw);
					logDNSMess(logBuff, 1);
				}
			}
		}
	}

	if (!cfig.zoneServers[0] && cfig.zoneServers[1])
	{
		sprintf(logBuff, "Section [ZONE_REPLICATION] Missing Primary Server");
		logDNSMess(logBuff, 1);
	}
	else if (cfig.zoneServers[0] && !cfig.zoneServers[1])
	{
		sprintf(logBuff, "Section [ZONE_REPLICATION] Missing Secondary Server");
		logDNSMess(logBuff, 1);
	}
	else if (cfig.zoneServers[0] && cfig.zoneServers[1])
	{
		if (findServer(network.staticServers, MAX_SERVERS, cfig.zoneServers[0]) && findServer(network.staticServers, MAX_SERVERS, cfig.zoneServers[1]))
		{
			sprintf(logBuff, "Section [ZONE_REPLICATION] Primary & Secondary should be Different Boxes");
			logDNSMess(logBuff, 1);
		}
		else if (findServer(network.staticServers, MAX_SERVERS, cfig.zoneServers[0]))
			cfig.replication = 1;
		else if (findServer(network.staticServers, MAX_SERVERS, cfig.zoneServers[1]))
			cfig.replication = 2;
		else
		{
			sprintf(logBuff, "Section [ZONE_REPLICATION] No Server IP not found on this Machine");
			logDNSMess(logBuff, 1);
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
			logDHCPMess(logBuff, 0);
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
			logDHCPMess(logBuff, 0);
			exit(-1);
		}
		//SetEvent(rEvent);
*/
		for (int i = 0; i < cfig.rangeCount; i++)
		{
			char *logPtr = logBuff;
			logPtr += sprintf(logPtr, "DHCP Range: ");
			logPtr += sprintf(logPtr, "%s", IP2String(ipbuff, htonl(cfig.dhcpRanges[i].rangeStart)));
			logPtr += sprintf(logPtr, "-%s", IP2String(ipbuff, htonl(cfig.dhcpRanges[i].rangeEnd)));
			logPtr += sprintf(logPtr, "/%s", IP2String(ipbuff, cfig.dhcpRanges[i].mask));
			logDHCPMess(logBuff, 1);
		}

		if (cfig.replication)
		{
			lockIP(cfig.zoneServers[0]);
			lockIP(cfig.zoneServers[1]);
		}
	}

	if (dnsService)
	{
		if (f = openSection("DNS_ALLOWED_HOSTS", 1))
		{
			int i = 0;

			while (readSection(raw, f))
			{
				if(i < MAX_DNS_RANGES)
				{
					MYDWORD rs = 0;
					MYDWORD re = 0;
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
						cfig.dnsRanges[i].rangeStart = rs;
						cfig.dnsRanges[i].rangeEnd = re;
						i++;
					}
					else
					{
						sprintf(logBuff, "Section [DNS_ALLOWED_HOSTS] Invalid entry %s in ini file, ignored", raw);
						logDNSMess(logBuff, 1);
					}
				}
			}
		}

		if (cfig.replication != 2 && (f = openSection("DNS_HOSTS", 1)))
		{
			while (readSection(raw, f))
			{
				mySplit(name, value, raw, '=');

				if (name[0] && value[0])
				{
					if (chkQu(name) && !isIP(name))
					{
						MYDWORD ip = inet_addr(value);
						MYBYTE nameType = makeLocal(name);
						bool ipLocal = isLocal(ip);

						if (!strcasecmp(value, "0.0.0.0"))
						{
							addHostNotFound(name);
							continue;
						}
						else if (!ip)
						{
							sprintf(logBuff, "Section [DNS_HOSTS] Invalid Entry %s ignored", raw);
							logDNSMess(logBuff, 1);
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
								if (cfig.replication)
								{
									sprintf(logBuff, "Section [DNS_HOSTS] forward entry for %s not in Forward Zone, ignored", raw);
									logDNSMess(logBuff, 1);
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
						else if (cfig.replication)
						{
							sprintf(logBuff, "Section [DNS_HOSTS] reverse entry for %s not in Reverse Zone, ignored", raw);
							logDNSMess(logBuff, 1);
						}
						else
							add2Cache(name, ip, INT_MAX, 0, CTYPE_STATIC_PTR_NAUTH);
					}
					else
					{
						sprintf(logBuff, "Section [DNS_HOSTS] Invalid Entry: %s ignored", raw);
						logDNSMess(logBuff, 1);
					}
				}
				else
				{
					sprintf(logBuff, "Section [DNS_HOSTS], Missing value, entry %s ignored", raw);
					logDNSMess(logBuff, 1);
				}
			}
		}

		if (cfig.replication != 2 && (f = openSection("ALIASES", 1)))
		{
			int i = 0;

			while (readSection(raw, f))
			{
				mySplit(name, value, raw, '=');

				if (name[0] && value[0])
				{
					MYBYTE nameType = makeLocal(name);
					MYBYTE aliasType = makeLocal(value);

					if (chkQu(name) && chkQu(value) && strcasecmp(value, cfig.zone))
					{
						if ((nameType == QTYPE_A_BARE || nameType == QTYPE_A_LOCAL || nameType == QTYPE_A_ZONE))
						{
							CachedData *cache = findEntry(name, DNS_TYPE_A);

							if (!cache)
							{
								memset(&lump, 0, sizeof(data71));

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
								logDNSMess(logBuff, 1);
							}
						}
						else
						{
							sprintf(logBuff, "Section [ALIASES] alias %s should be bare/local name, entry ignored", name);
							logDNSMess(logBuff, 1);
						}
					}
					else
					{
						sprintf(logBuff, "Section [ALIASES] Invalid Entry: %s ignored", raw);
						logDNSMess(logBuff, 1);
					}
				}
				else
				{
					sprintf(logBuff, "Section [ALIASES], Missing value, entry %s ignored", raw);
					logDNSMess(logBuff, 1);
				}
			}
		}

		if (cfig.replication != 2 && (f = openSection("MAIL_SERVERS", 1)))
		{
			cfig.mxCount[0] = 0;

			while (readSection(raw, f))
			{
				if (cfig.mxCount[0] < MAX_SERVERS)
				{
					mySplit(name, value, raw, '=');
					if (name[0] && value[0])
					{
						if (chkQu(name) && atoi(value))
						{
							cfig.mxServers[0][cfig.mxCount[0]].pref = atoi(value);
							cfig.mxServers[1][cfig.mxCount[0]].pref = atoi(value);

							if (!strchr(name, '.'))
							{
								strcat(name, ".");
								strcat(name, cfig.zone);
							}

							strcpy(cfig.mxServers[0][cfig.mxCount[0]].hostname, name);
							strcpy(cfig.mxServers[1][cfig.mxCount[0]].hostname, name);
							cfig.mxCount[0]++;
						}
						else
						{
							sprintf(logBuff, "Section [MAIL_SERVERS] Invalid Entry: %s ignored", raw);
							logDNSMess(logBuff, 1);
						}
					}
					else
					{
						sprintf(logBuff, "Section [MAIL_SERVERS], Missing value, entry %s ignored", raw);
						logDNSMess(logBuff, 1);
					}
				}
				//cfig.mxCount[1] = cfig.mxCount[0];
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

						for (; j < MAX_COND_FORW && cfig.dnsRoutes[j].zone[0]; j++)
						{
							if (!strcasecmp(cfig.dnsRoutes[j].zone, name))
							{
								sprintf(logBuff, "Section [CONDITIONAL_FORWARDERS], Duplicate Entry for Child Zone %s ignored", raw);
								logDNSMess(logBuff, 1);
								break;
							}
						}

						if (j < MAX_COND_FORW && !cfig.dnsRoutes[j].zone[0])
						{
							if (name[0] && chkQu(name) && value[0])
							{
								char *value1 = strchr(value, ',');

								if (value1)
								{
									*value1 = 0;
									value1++;

									MYDWORD ip = inet_addr(myTrim(value, value));
									MYDWORD ip1 = inet_addr(myTrim(value1, value1));

									if (isIP(value) && isIP(value1))
									{
										strcpy(cfig.dnsRoutes[i].zone, name);
										cfig.dnsRoutes[i].zLen = strlen(cfig.dnsRoutes[i].zone);
										cfig.dnsRoutes[i].dns[0] = ip;
										cfig.dnsRoutes[i].dns[1] = ip1;
										i++;
									}
									else
									{
										sprintf(logBuff, "Section [CONDITIONAL_FORWARDERS] Invalid Entry: %s ignored", raw);
										logDNSMess(logBuff, 1);
									}
								}
								else
								{
									MYDWORD ip = inet_addr(value);

									if (isIP(value))
									{
										strcpy(cfig.dnsRoutes[i].zone, name);
										cfig.dnsRoutes[i].zLen = strlen(cfig.dnsRoutes[i].zone);
										cfig.dnsRoutes[i].dns[0] = ip;
										i++;
									}
									else
									{
										sprintf(logBuff, "Section [CONDITIONAL_FORWARDERS] Invalid Entry: %s ignored", raw);
										logDNSMess(logBuff, 1);
									}
								}
							}
							else
							{
								sprintf(logBuff, "Section [CONDITIONAL_FORWARDERS] Invalid Entry: %s ignored", raw);
								logDNSMess(logBuff, 1);
							}
						}
					}
					else
					{
						sprintf(logBuff, "Section [CONDITIONAL_FORWARDERS], Missing value, entry %s ignored", raw);
						logDNSMess(logBuff, 1);
					}
				}
			}
		}

		if (f = openSection("WILD_HOSTS", 1))
		{
			int i = 0;

			while (readSection(raw, f))
			{
				if (i < MAX_WILD_HOSTS)
				{
					mySplit(name, value, raw, '=');

					if (name[0] && value[0])
					{
						if (chkQu(name) && (isIP(value) || !strcasecmp(value, "0.0.0.0")))
						{
							MYDWORD ip = inet_addr(value);
							strcpy(cfig.wildHosts[i].wildcard, name);
							myLower(cfig.wildHosts[i].wildcard);
							cfig.wildHosts[i].ip = ip;
							i++;
						}
						else
						{
							sprintf(logBuff, "Section [WILD_HOSTS] Invalid Entry: %s ignored", raw);
							logDNSMess(logBuff, 1);
						}
					}
					else
					{
						sprintf(logBuff, "Section [WILD_HOSTS], Missing value, entry %s ignored", raw);
						logDNSMess(logBuff, 1);
					}
				}
			}
		}

		if (cfig.replication == 2)
		{
//			if (dhcpService)
//				strcpy(cfig.nsS, cfig.servername_fqn);

			while (kRunning)
			{
//				//if (!dhcpService && !findEntry(IP2String(ipbuff, htonl(cfig.zoneServers[1])), DNS_TYPE_PTR))
//				if (!dhcpService)
//				{
//					sendServerName();
//					Sleep(1000);
//				}

				MYDWORD serial1 = getSerial(cfig.zone);
				MYDWORD serial2 = 0;

				if (serial1)
					serial2 = getSerial(cfig.authority);

				if (serial1 && serial2)
				{
					cfig.serial1 = getZone(0, cfig.zone);
					Sleep(5*1000);

					if (cfig.serial1)
						cfig.serial2 = getZone(0, cfig.authority);
				}

				if (cfig.serial1 && cfig.serial2)
				{
					if (cfig.refresh > (MYDWORD)(INT_MAX - t))
						cfig.dnsRepl = INT_MAX;
					else
						cfig.dnsRepl = t + cfig.refresh + cfig.retry + cfig.retry;

					break;
				}

				sprintf(logBuff, "Failed to get Zone(s) from Primary Server, waiting %d seconds to retry", cfig.retry);
				logDNSMess(logBuff, 1);

				Sleep(cfig.retry*1000);
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

			if (cfig.expire > (MYDWORD)(INT_MAX - t))
				cfig.expireTime = INT_MAX;
			else
				cfig.expireTime = t + cfig.expire;

			magin.currentInd = 0;
			magin.done = false;
			_beginthread(checkZone, 0, &magin);
		}
		else if (cfig.replication == 1)
		{
			strcpy(cfig.nsP, cfig.servername_fqn);

			if (!dhcpService)
			{
				findHost(cfig.nsS, cfig.zoneServers[1]);

				if (cfig.nsS[0])
				{
					strcat(cfig.nsS, ".");
					strcat(cfig.nsS, cfig.zone);
				}
			}

			cfig.serial1 = t;
			cfig.serial2 = t;
			cfig.expireTime = INT_MAX;
			char localhost[] = "localhost";
			add2Cache(localhost, inet_addr("127.0.0.1"), INT_MAX, CTYPE_LOCALHOST_A, CTYPE_LOCALHOST_PTR);

			if (isLocal(cfig.zoneServers[0]))
				add2Cache(cfig.servername, cfig.zoneServers[0], INT_MAX, CTYPE_SERVER_A_AUTH, CTYPE_SERVER_PTR_AUTH);
			else
				add2Cache(cfig.servername, cfig.zoneServers[0], INT_MAX, CTYPE_SERVER_A_AUTH, CTYPE_SERVER_PTR_NAUTH);

			if (dhcpService)
				getSecondary();
		}
		else
		{
			strcpy(cfig.nsP, cfig.servername_fqn);
			cfig.serial1 = t;
			cfig.serial2 = t;
			cfig.expireTime = INT_MAX;
			char localhost[] = "localhost";
			add2Cache(localhost, inet_addr("127.0.0.1"), INT_MAX, CTYPE_LOCALHOST_A, CTYPE_LOCALHOST_PTR);

			bool ifspecified = false;

			for (int i = 0; i < MAX_SERVERS && network.listenServers[i]; i++)
			{
				if (isLocal(network.listenServers[i]))
					add2Cache(cfig.servername, network.listenServers[i], INT_MAX, CTYPE_SERVER_A_AUTH, CTYPE_SERVER_PTR_AUTH);
				else
					add2Cache(cfig.servername, network.listenServers[i], INT_MAX, CTYPE_SERVER_A_AUTH, CTYPE_SERVER_PTR_NAUTH);
			}
		}
	}

	if (dhcpService)
	{
		if (cfig.replication)
		{
			cfig.dhcpReplConn.sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

			if (cfig.dhcpReplConn.sock == INVALID_SOCKET)
			{
				sprintf(logBuff, "Failed to Create DHCP Replication Socket");
				logDHCPMess(logBuff, 1);
			}
			else
			{
				//printf("Socket %u\n", cfig.dhcpReplConn.sock);

				if (cfig.replication == 1)
					cfig.dhcpReplConn.server = cfig.zoneServers[0];
				else
					cfig.dhcpReplConn.server = cfig.zoneServers[1];

				cfig.dhcpReplConn.addr.sin_family = AF_INET;
				cfig.dhcpReplConn.addr.sin_addr.s_addr = cfig.dhcpReplConn.server;
				cfig.dhcpReplConn.addr.sin_port = 0;

				int nRet = bind(cfig.dhcpReplConn.sock, (sockaddr*)&cfig.dhcpReplConn.addr, sizeof(struct sockaddr_in));

				if (nRet == SOCKET_ERROR)
				{
					cfig.dhcpReplConn.ready = false;
					sprintf(logBuff, "DHCP Replication Server, Bind Failed");
					logDHCPMess(logBuff, 1);
				}
				else
				{
					cfig.dhcpReplConn.port = IPPORT_DHCPS;
					cfig.dhcpReplConn.loaded = true;
					cfig.dhcpReplConn.ready = true;

					data3 op;
					memset(&token, 0, sizeof(data9));
					token.vp = token.dhcpp.vend_data;
					token.messsize = sizeof(dhcp_packet);

					token.remote.sin_port = htons(IPPORT_DHCPS);
					token.remote.sin_family = AF_INET;

					if (cfig.replication == 1)
						token.remote.sin_addr.s_addr = cfig.zoneServers[1];
					else if (cfig.replication == 2)
						token.remote.sin_addr.s_addr = cfig.zoneServers[0];

					token.dhcpp.header.bp_op = BOOTP_REQUEST;
					token.dhcpp.header.bp_xid = t;
					strcpy(token.dhcpp.header.bp_sname, cfig.servername);
					token.dhcpp.header.bp_magic_num[0] = 99;
					token.dhcpp.header.bp_magic_num[1] = 130;
					token.dhcpp.header.bp_magic_num[2] = 83;
					token.dhcpp.header.bp_magic_num[3] = 99;

					op.opt_code = DHCP_OPTION_MESSAGETYPE;
					op.size = 1;
					op.value[0] = DHCP_MESS_INFORM;
					pvdata(&token, &op);

					if (dnsService)
					{
						op.opt_code = DHCP_OPTION_DNS;
						op.size = 4;

						if (cfig.replication == 1)
							pIP(op.value, cfig.zoneServers[0]);
						else
							pIP(op.value, cfig.zoneServers[1]);

						pvdata(&token, &op);
					}

					//op.opt_code = DHCP_OPTION_HOSTNAME;
					//op.size = strlen(cfig.servername);
					//memcpy(op.value, cfig.servername, op.size);
					//pvdata(&token, &op);

					token.vp[0] = DHCP_OPTION_END;
					token.vp++;
					token.bytes = token.vp - (MYBYTE*)token.raw;

 					if (cfig.replication == 2)
						_beginthread(sendToken, 0, 0);
				}
			}
		}

		if (cfig.lease >= INT_MAX)
			sprintf(logBuff, "Default Lease: Infinity");
		else
			sprintf(logBuff, "Default Lease: %u (sec)", cfig.lease);

		logDHCPMess(logBuff, 1);
	}

	if (cfig.replication == 1)
		sprintf(logBuff, "Server Name: %s (Primary)", cfig.servername);
	else if (cfig.replication == 2)
		sprintf(logBuff, "Server Name: %s (Secondary)", cfig.servername);
	else
		sprintf(logBuff, "Server Name: %s", cfig.servername);

	logDNSMess(logBuff, 1);

	if (dnsService)
	{
		if (cfig.authorized)
			sprintf(logBuff, "Authority for Zone: %s (%s)", cfig.zone, cfig.authority);
		else
			sprintf(logBuff, "Domain Name: %s", cfig.zone);

		logDNSMess(logBuff, 1);

		if (cfig.lease >= INT_MAX)
			sprintf(logBuff, "Default Host Expiry: Infinity");
		else
			sprintf(logBuff, "Default Host Expiry: %u (sec)", cfig.lease);

		logDNSMess(logBuff, 1);

		if (cfig.replication)
		{
			sprintf(logBuff, "Refresh: %u (sec)", cfig.refresh);
			logDNSMess(logBuff, 1);
			sprintf(logBuff, "Retry: %u (sec)", cfig.retry);
			logDNSMess(logBuff, 1);

			if (cfig.expire == UINT_MAX)
				sprintf(logBuff, "Expire: Infinity");
			else
				sprintf(logBuff, "Expire: %u (sec)", cfig.expire);

			logDNSMess(logBuff, 1);
			sprintf(logBuff, "Min: %u (sec)", cfig.minimum);
			logDNSMess(logBuff, 1);
		}

		for (int i = 0; i < MAX_COND_FORW && cfig.dnsRoutes[i].dns[0]; i++)
		{
			char temp[256];

			if (!cfig.dnsRoutes[i].dns[1])
				sprintf(logBuff, "Conditional Forwarder: %s for %s", IP2String(ipbuff, cfig.dnsRoutes[i].dns[0]), cfig.dnsRoutes[i].zone);
			else
				sprintf(logBuff, "Conditional Forwarder: %s, %s for %s", IP2String(temp, cfig.dnsRoutes[i].dns[0]), IP2String(ipbuff, cfig.dnsRoutes[i].dns[1]), cfig.dnsRoutes[i].zone);

			logDNSMess(logBuff, 1);
		}

		for (int i = 0; i < MAX_SERVERS && network.dns[i]; i++)
		{
			sprintf(logBuff, "Default Forwarding Server: %s", IP2String(ipbuff, network.dns[i]));
			logDNSMess(logBuff, 1);
		}

		//char temp[128];

		for (int i = 0; i <= MAX_DNS_RANGES && cfig.dnsRanges[i].rangeStart; i++)
		{
			char *logPtr = logBuff;
			logPtr += sprintf(logPtr, "%s", "DNS Service Permitted Hosts: ");
			logPtr += sprintf(logPtr, "%s-", IP2String(ipbuff, htonl(cfig.dnsRanges[i].rangeStart)));
			logPtr += sprintf(logPtr, "%s", IP2String(ipbuff, htonl(cfig.dnsRanges[i].rangeEnd)));
			logDNSMess(logBuff, 1);
		}
	}
	else
	{
		sprintf(logBuff, "Domain Name: %s", cfig.zone);
		logDNSMess(logBuff, 1);
	}

	sprintf(logBuff, "Detecting Static Interfaces..");
	logMess(logBuff, 1);

	do
	{
		closeConn();
		getInterfaces(&network);

		network.maxFD = cfig.dhcpReplConn.sock;

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
					logDHCPMess(logBuff, 1);
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
					logDHCPMess(logBuff, 1);
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

			network.httpConn.port = 6789;
			network.httpConn.server = inet_addr("127.0.0.1");

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
							network.httpConn.server = inet_addr(name);
						}
						else
						{
							network.httpConn.loaded = false;
							sprintf(logBuff, "Warning: Section [HTTP_INTERFACE], Invalid IP Address %s, ignored", name);
							logDHCPMess(logBuff, 1);
						}

						if (value[0])
						{
							if (atoi(value))
								network.httpConn.port = atoi(value);
							else
							{
								network.httpConn.loaded = false;
								sprintf(logBuff, "Warning: Section [HTTP_INTERFACE], Invalid port %s, ignored", value);
								logDHCPMess(logBuff, 1);
							}
						}

						if (network.httpConn.server != inet_addr("127.0.0.1") && !findServer(network.allServers, MAX_SERVERS, network.httpConn.server))
						{
							bindfailed = true;
							network.httpConn.loaded = false;
							sprintf(logBuff, "Warning: Section [HTTP_INTERFACE], %s not available, ignored", raw);
							logDHCPMess(logBuff, 1);
						}
					}
					else if (!strcasecmp(name, "HTTPClient"))
					{
						if (isIP(value))
							addServer(cfig.httpClients, 8, inet_addr(value));
						else
						{
							sprintf(logBuff, "Warning: Section [HTTP_INTERFACE], invalid client IP %s, ignored", raw);
							logDHCPMess(logBuff, 1);
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
						logDHCPMess(logBuff, 1);
					}
				}
			}

			if (!htmlTitle[0])
				sprintf(htmlTitle, "Dual Server on %s", cfig.servername);

			network.httpConn.sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

			if (network.httpConn.sock == INVALID_SOCKET)
			{
				bindfailed = true;
				sprintf(logBuff, "Failed to Create Socket");
				logDHCPMess(logBuff, 1);
			}
			else
			{
				//printf("Socket %u\n", network.httpConn.sock);

				network.httpConn.addr.sin_family = AF_INET;
				network.httpConn.addr.sin_addr.s_addr = network.httpConn.server;
				network.httpConn.addr.sin_port = htons(network.httpConn.port);

				int nRet = bind(network.httpConn.sock, (sockaddr*)&network.httpConn.addr, sizeof(struct sockaddr_in));

				if (nRet == SOCKET_ERROR)
				{
					bindfailed = true;
					sprintf(logBuff, "Http Interface %s TCP Port %u not available", IP2String(ipbuff, network.httpConn.server), network.httpConn.port);
					logDHCPMess(logBuff, 1);
					closesocket(network.httpConn.sock);
				}
				else
				{
					nRet = listen(network.httpConn.sock, SOMAXCONN);

					if (nRet == SOCKET_ERROR)
					{
						bindfailed = true;
						sprintf(logBuff, "%s TCP Port %u Error on Listen", IP2String(ipbuff, network.httpConn.server), network.httpConn.port);
						logDHCPMess(logBuff, 1);
						closesocket(network.httpConn.sock);
					}
					else
					{
						network.httpConn.loaded = true;
						network.httpConn.ready = true;

						if (network.httpConn.sock > network.maxFD)
							network.maxFD = network.httpConn.sock;
					}
				}
			}
		}

		if (dnsService)
		{
			int i = 0;

			for (int j = 0; j < MAX_SERVERS && network.listenServers[j]; j++)
			{
				network.dnsUdpConn[i].sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

				if (network.dnsUdpConn[i].sock == INVALID_SOCKET)
				{
					bindfailed = true;
					sprintf(logBuff, "Failed to Create Socket");
					logDNSMess(logBuff, 1);
					continue;
				}

				//printf("Socket %u\n", network.dnsUdpConn[i].sock);

				network.dnsUdpConn[i].addr.sin_family = AF_INET;
				network.dnsUdpConn[i].addr.sin_addr.s_addr = network.listenServers[j];
				network.dnsUdpConn[i].addr.sin_port = htons(IPPORT_DNS);

				int nRet = bind(network.dnsUdpConn[i].sock,
								(sockaddr*)&network.dnsUdpConn[i].addr,
								sizeof(struct sockaddr_in)
							   );

				if (nRet == SOCKET_ERROR)
				{
					bindfailed = true;
					closesocket(network.dnsUdpConn[i].sock);
					sprintf(logBuff, "Warning: %s UDP Port 53 already in use", IP2String(ipbuff, network.listenServers[j]));
					logDNSMess(logBuff, 1);
					continue;
				}

				network.dnsUdpConn[i].loaded = true;
				network.dnsUdpConn[i].ready = true;

				if (network.maxFD < network.dnsUdpConn[i].sock)
					network.maxFD = network.dnsUdpConn[i].sock;

				network.dnsUdpConn[i].server = network.listenServers[j];
				network.dnsUdpConn[i].port = IPPORT_DNS;

				i++;
			}

			network.forwConn.sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

			if (network.forwConn.sock == INVALID_SOCKET)
			{
				bindfailed = true;
				sprintf(logBuff, "Failed to Create Socket");
				logDNSMess(logBuff, 1);
			}
			else
			{
				network.forwConn.addr.sin_family = AF_INET;
				network.forwConn.server = network.dns[0];
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
				network.dnsTcpConn[i].sock = socket( PF_INET, SOCK_STREAM, IPPROTO_TCP);

				if (network.dnsTcpConn[i].sock == INVALID_SOCKET)
				{
					bindfailed = true;
					sprintf(logBuff, "Failed to Create Socket");
					logDNSMess(logBuff, 1);
				}
				else
				{
					//printf("Socket %u\n", network.dnsTcpConn[i].sock);
					network.dnsTcpConn[i].addr.sin_family = AF_INET;
					network.dnsTcpConn[i].addr.sin_addr.s_addr = network.listenServers[j];
					network.dnsTcpConn[i].addr.sin_port = htons(IPPORT_DNS);

					int nRet = bind(network.dnsTcpConn[i].sock,
									(sockaddr*)&network.dnsTcpConn[i].addr,
									sizeof(struct sockaddr_in));

					if (nRet == SOCKET_ERROR)
					{
						bindfailed = true;
						closesocket(network.dnsTcpConn[i].sock);
						sprintf(logBuff, "Warning: %s TCP Port 53 already in use", IP2String(ipbuff, network.listenServers[j]));
						logDNSMess(logBuff, 1);
					}
					else
					{
						nRet = listen(network.dnsTcpConn[i].sock, SOMAXCONN);

						if (nRet == SOCKET_ERROR)
						{
							closesocket(network.dnsTcpConn[i].sock);
							sprintf(logBuff, "TCP Port 53 Error on Listen");
							logDNSMess(logBuff, 1);
						}
						else
						{
							network.dnsTcpConn[i].server = network.listenServers[j];
							network.dnsTcpConn[i].port = IPPORT_DNS;

							network.dnsTcpConn[i].loaded = true;
							network.dnsTcpConn[i].ready = true;

							if (network.maxFD < network.dnsTcpConn[i].sock)
								network.maxFD = network.dnsTcpConn[i].sock;

							i++;
						}
					}
				}
			}
		}

		network.maxFD++;

		if (dhcpService)
		{
			for (MYBYTE m = 0; m < MAX_SERVERS && network.allServers[m]; m++)
				lockIP(network.allServers[m]);

			for (MYBYTE m = 0; m < MAX_SERVERS && network.dns[m]; m++)
				lockIP(network.dns[m]);
		}

		if (bindfailed)
			cfig.failureCount++;
		else
			cfig.failureCount = 0;

		//printf("%i %i %i\n", network.dhcpConn[0].ready, network.dnsUdpConn[0].ready, network.dnsTcpConn[0].ready);

		if ((dhcpService && !network.dhcpConn[0].ready) || (dnsService && !(network.dnsUdpConn[0].ready && network.dnsTcpConn[0].ready)))
		{
			sprintf(logBuff, "No Static Interface ready, Waiting...");
			logMess(logBuff, 1);
			continue;
		}

		if (dhcpService && network.httpConn.ready)
		{
			sprintf(logBuff, "Lease Status URL: http://%s:%u", IP2String(ipbuff, network.httpConn.server), network.httpConn.port);
			logDHCPMess(logBuff, 1);
			FILE *f = fopen(htmFile, "wt");

			if (f)
			{
				fprintf(f, "<html><head><meta http-equiv=\"refresh\" content=\"0;url=http://%s:%u\"</head></html>", IP2String(ipbuff, network.httpConn.server), network.httpConn.port);
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
			for (MYBYTE j = 0; j < MAX_SERVERS; j++)
			{
				if (network.dhcpConn[j].server == network.staticServers[i] || network.dnsUdpConn[j].server == network.staticServers[i])
				{
					sprintf(logBuff, "Listening On: %s", IP2String(ipbuff, network.staticServers[i]));
					logMess(logBuff, 1);
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

	if (cfig.failureCount)
	{
		MYDWORD eventWait = (MYDWORD)(10000 * pow(2, cfig.failureCount));
		Sleep(eventWait);
		sprintf(logBuff, "Retrying failed Listening Interfaces..");
		logDHCPMess(logBuff, 1);
		network.ready = false;

		while (network.busy)
			Sleep(500);

		return true;
	}

	DWORD ret = NotifyAddrChange(NULL, NULL);

	if ((errno = WSAGetLastError()) && errno != WSA_IO_PENDING)
	{
		sprintf(logBuff, "NotifyAddrChange error...%d", errno);
		logDHCPMess(logBuff, 1);
	}

	Sleep(1000);
	sprintf(logBuff, "Network changed, re-detecting Static Interfaces..");
	logDHCPMess(logBuff, 1);
	network.ready = false;

	while (network.busy)
		Sleep(500);

	return true;
}

void getInterfaces(data1 *network)
{
	char logBuff[512];
	char ipbuff[32];

	memset(network, 0, sizeof(data1));

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
					MYDWORD iaddr = inet_addr(sList->IpAddress.String);

					if (iaddr)
					{
						for (MYBYTE k = 0; k < MAX_SERVERS; k++)
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
//					MYDWORD trouter = inet_addr(rList->IpAddress.String);
//					addServer(cfig.routers, trouter);
//					rList = rList->Next;
//				}
			}
			pAdapter = pAdapter->Next;
		}
		free(pAdapterInfo);
	}

	if (cfig.specifiedServers[0])
	{
		for (MYBYTE i = 0; i < MAX_SERVERS && cfig.specifiedServers[i]; i++)
		{
			MYBYTE j = 0;

			for (; j < MAX_SERVERS && network->staticServers[j]; j++)
			{
				if (network->staticServers[j] == cfig.specifiedServers[i])
				{
					MYBYTE k = addServer(network->listenServers, MAX_SERVERS, network->staticServers[j]);

					if (k < MAX_SERVERS)
						network->listenMasks[k] = network->staticMasks[j];

					break;
				}
			}

			if (j == MAX_SERVERS || !network->staticServers[j])
			{
				if (findServer(network->allServers, MAX_SERVERS, cfig.specifiedServers[i]))
					sprintf(logBuff, "Warning: Section [LISTEN_ON] Interface %s is not static, ignored", IP2String(ipbuff, cfig.specifiedServers[i]));
				else
					sprintf(logBuff, "Warning: Section [LISTEN_ON] Interface %s is not found, ignored", IP2String(ipbuff, cfig.specifiedServers[i]));

				logMess(logBuff, 2);
			}
		}
	}
	else
	{
		for (MYBYTE i = 0; i < MAX_SERVERS && network->allServers[i]; i++)
		{
			MYBYTE j = 0;

			for (; j < MAX_SERVERS && network->staticServers[j]; j++)
			{
				if (network->staticServers[j] == network->allServers[i])
				{
					MYBYTE k = addServer(network->listenServers, MAX_SERVERS, network->staticServers[j]);

					if (k < MAX_SERVERS)
						network->listenMasks[k] = network->staticMasks[j];

					break;
				}
			}

			if (j == MAX_SERVERS || !network->staticServers[j])
			{
				sprintf(logBuff, "Warning: Interface %s is not Static, ignored", IP2String(ipbuff, network->allServers[i]));
				logMess(logBuff, 2);
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
		if (!cfig.servername[0])
			strcpy(cfig.servername, FixedInfo->HostName);

		//printf("d=%u=%s", strlen(FixedInfo->DomainName), FixedInfo->DomainName);

		if (!cfig.zone[0])
		{
			strcpy(cfig.zone, FixedInfo->DomainName);
			cfig.zLen = strlen(cfig.zone);
		}

		if (!cfig.zone[0] || cfig.zone[0] == NBSP)
		{
			strcpy(cfig.zone, "workgroup");
			cfig.zLen = strlen(cfig.zone);
		}

		if (!cfig.specifiedDnsServers[0])
		{
			pIPAddr = &FixedInfo->DnsServerList;

			while (pIPAddr)
			{
				MYDWORD addr = inet_addr(pIPAddr->IpAddress.String);

				if (!dnsService || !findServer(network->allServers, MAX_SERVERS, addr))
					addServer(network->dns, MAX_SERVERS, addr);

				pIPAddr = pIPAddr->Next;
			}
		}
		GlobalFree(FixedInfo);
	}

	for (int i = 0; i < MAX_SERVERS && cfig.specifiedDnsServers[i]; i++)
	{
		if (!dnsService || !findServer(network->allServers, MAX_SERVERS, cfig.specifiedDnsServers[i]))
			addServer(network->dns, MAX_SERVERS, cfig.specifiedDnsServers[i]);
	}
	return;
}

void __cdecl updateStateFile(void *lpParam)
{
	CachedData *dhcpEntry = (CachedData*)lpParam;
	data8 dhcpData;
	memset(&dhcpData, 0, sizeof(data8));
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
			if (fseek(f, (dhcpData.dhcpInd - 1)*sizeof(data8), SEEK_SET) >= 0)
				fwrite(&dhcpData, sizeof(data8), 1, f);

			fclose(f);
		}
	}
	else
	{
		cfig.dhcpInd++;
		dhcpEntry->dhcpInd = cfig.dhcpInd;
		dhcpData.dhcpInd = cfig.dhcpInd;
		FILE *f = fopen(leaFile, "ab");

		if (f)
		{
			fwrite(&dhcpData, sizeof(data8), 1, f);
			fclose(f);
		}
	}

	SetEvent(fEvent);
	_endthread();
	return;
}

MYWORD gdmess(data9 *req, MYBYTE sockInd)
{
	//debug("gdmess");
	char ipbuff[32];
	char logBuff[512];
	memset(req, 0, sizeof(data9));
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

	if (errno || req->bytes <= 0 || req->dhcpp.header.bp_op != BOOTP_REQUEST)
		return 0;

	hex2String(req->chaddr, req->dhcpp.header.bp_chaddr, req->dhcpp.header.bp_hlen);

	data3 *op;
	MYBYTE *raw = req->dhcpp.vend_data;
	MYBYTE *rawEnd = raw + (req->bytes - sizeof(dhcp_header));

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
				req->reqIP = fIP(op->value);
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
				req->dns = fULong(op->value);
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
		if (req->dhcpp.header.bp_giaddr)
			req->subnetIP = req->dhcpp.header.bp_giaddr;
		else
			req->subnetIP = network.dhcpConn[req->sockInd].server;
	}

	if (!req->messsize)
	{
		if (req->req_type == DHCP_MESS_NONE)
			req->messsize = req->bytes;
		else
			req->messsize = sizeof(dhcp_packet);
	}

//	if (!req->hostname[0] && req->dhcpp.header.bp_ciaddr)
//	{
//		CachedData* cache = findEntry(IP2String(ipbuff, htonl(req->dhcpp.header.bp_ciaddr)), DNS_TYPE_PTR);
//
//		if (cache)
//			strcpy(req->hostname, cache->hostname);
//	}
//
//	if ((req->req_type == 1 || req->req_type == 3) && cfig.dhcpLogLevel == 3)
//	{
//		data9 *req1 = (data9*)calloc(1, sizeof(data9));
//		memcpy(req1, req, sizeof(data9));
//		_beginthread(logDebug, 0, req1);
//	}

	if (verbatim || cfig.dhcpLogLevel >= 2)
	{
		if (req->req_type == DHCP_MESS_NONE)
		{
			if (req->dhcpp.header.bp_giaddr)
				sprintf(logBuff, "BOOTPREQUEST for %s (%s) from RelayAgent %s received", req->chaddr, req->hostname, IP2String(ipbuff, req->dhcpp.header.bp_giaddr));
			else
				sprintf(logBuff, "BOOTPREQUEST for %s (%s) from interface %s received", req->chaddr, req->hostname, IP2String(ipbuff, network.dhcpConn[req->sockInd].server));

			logDHCPMess(logBuff, 2);
		}
		else if (req->req_type == DHCP_MESS_DISCOVER)
		{
			if (req->dhcpp.header.bp_giaddr)
				sprintf(logBuff, "DHCPDISCOVER for %s (%s) from RelayAgent %s received", req->chaddr, req->hostname, IP2String(ipbuff, req->dhcpp.header.bp_giaddr));
			else
				sprintf(logBuff, "DHCPDISCOVER for %s (%s) from interface %s received", req->chaddr, req->hostname, IP2String(ipbuff, network.dhcpConn[req->sockInd].server));

			logDHCPMess(logBuff, 2);
		}
		else if (req->req_type == DHCP_MESS_REQUEST)
		{
			if (req->dhcpp.header.bp_giaddr)
				sprintf(logBuff, "DHCPREQUEST for %s (%s) from RelayAgent %s received", req->chaddr, req->hostname, IP2String(ipbuff, req->dhcpp.header.bp_giaddr));
			else
				sprintf(logBuff, "DHCPREQUEST for %s (%s) from interface %s received", req->chaddr, req->hostname, IP2String(ipbuff, network.dhcpConn[req->sockInd].server));

			logDHCPMess(logBuff, 2);
		}
	}

	req->vp = req->dhcpp.vend_data;
	memset(req->vp, 0, sizeof(dhcp_packet) - sizeof(dhcp_header));
	//printf("end bytes=%u\n", req->bytes);

	return 1;
}

void debug(int i)
{
	char t[254];
	sprintf(t, "%i", i);
	logMess(t, 1);
}

void debug(const char *mess)
{
	char t[254];
	strcpy(t, mess);
	logMess(t, 1);
}

void logDirect(char *mess)
{
	tm *ttm = localtime(&t);
	char buffer[_MAX_PATH];
	strftime(buffer, sizeof(buffer), logFile, ttm);

	if (strcmp(cfig.logFileName, buffer))
	{
		if (cfig.logFileName[0])
		{
			FILE *f = fopen(cfig.logFileName, "at");

			if (f)
			{
				fprintf(f, "Logging Continued on file %s\n", buffer);
				fclose(f);
			}

			strcpy(cfig.logFileName, buffer);
			f = fopen(cfig.logFileName, "at");

			if (f)
			{
				fprintf(f, "%s\n\n", sVersion);
				fclose(f);
			}
		}

		strcpy(cfig.logFileName, buffer);
		WritePrivateProfileString("InternetShortcut","URL", buffer, lnkFile);
		WritePrivateProfileString("InternetShortcut","IconIndex", "0", lnkFile);
		WritePrivateProfileString("InternetShortcut","IconFile", buffer, lnkFile);
	}

	FILE *f = fopen(cfig.logFileName, "at");

	if (f)
	{
		strftime(buffer, sizeof(buffer), "%d-%b-%y %X", ttm);
		fprintf(f, "[%s] %s\n", buffer, mess);
		fclose(f);
	}
	else
	{
		cfig.dnsLogLevel = 0;
		cfig.dhcpLogLevel = 0;
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

	if (strcmp(cfig.logFileName, buffer))
	{
		if (cfig.logFileName[0])
		{
			FILE *f = fopen(cfig.logFileName, "at");

			if (f)
			{
				fprintf(f, "Logging Continued on file %s\n", buffer);
				fclose(f);
			}

			strcpy(cfig.logFileName, buffer);
			f = fopen(cfig.logFileName, "at");

			if (f)
			{
				fprintf(f, "%s\n\n", sVersion);
				fclose(f);
			}
		}

		strcpy(cfig.logFileName, buffer);
		WritePrivateProfileString("InternetShortcut","URL", buffer, lnkFile);
		WritePrivateProfileString("InternetShortcut","IconIndex", "0", lnkFile);
		WritePrivateProfileString("InternetShortcut","IconFile", buffer, lnkFile);
	}

	FILE *f = fopen(cfig.logFileName, "at");

	if (f)
	{
		strftime(buffer, sizeof(buffer), "%d-%b-%y %X", ttm);
		fprintf(f, "[%s] %s\n", buffer, mess);
		fclose(f);
	}
	else
	{
		cfig.dnsLogLevel = 0;
		cfig.dhcpLogLevel = 0;
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
	data9 *req = (data9*)lpParam;
	genHostName(localBuff, req->dhcpp.header.bp_chaddr, req->dhcpp.header.bp_hlen);
	sprintf(localreq->extbuff, cliFile, localBuff);
	FILE *f = fopen(localreq->extbuff, "at");

	if (f)
	{
		tm *ttm = localtime(&t);
		strftime(localreq->extbuff, sizeof(localreq->extbuff), "%d-%m-%y %X", ttm);

		char *s = localBuff;
		s += sprintf(s, localreq->extbuff);
		s += sprintf(s, " SourceMac=%s", req->chaddr);
		s += sprintf(s, " ClientIP=%s", IP2String(localreq->extbuff, req->dhcpp.header.bp_ciaddr));
		s += sprintf(s, " SourceIP=%s", IP2String(localreq->extbuff, req->remote.sin_addr.s_addr));
		s += sprintf(s, " RelayAgent=%s", IP2String(localreq->extbuff, req->dhcpp.header.bp_giaddr));
		fprintf(f, "%s\n", localBuff);

		data3 *op;
		MYBYTE *raw = req->dhcpp.vend_data;
		MYBYTE *rawEnd = raw + (req->bytes - sizeof(dhcp_header));
		MYBYTE maxInd = sizeof(opData) / sizeof(data4);

		for (; raw < rawEnd && *raw != DHCP_OPTION_END;)
		{
			op = (data3*)raw;

			BYTE opType = 2;
			char opName[40] = "Private";

			for (MYBYTE i = 0; i < maxInd; i++)
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

void logMess(char *logBuff, MYBYTE logLevel)
{
	if (verbatim)
		printf("%s\n", logBuff);

	if (logLevel <= cfig.dnsLogLevel || logLevel <= cfig.dhcpLogLevel)
	{
		char *mess = cloneString(logBuff);
		_beginthread(logThread, 0, mess);
	}
}

void logDHCPMess(char *logBuff, MYBYTE logLevel)
{
	if (verbatim)
		printf("%s\n", logBuff);

	if (logLevel <= cfig.dhcpLogLevel)
	{
		char *mess = cloneString(logBuff);
		_beginthread(logThread, 0, mess);
	}
}

void logDNSMess(char *logBuff, MYBYTE logLevel)
{
	if (verbatim)
		printf("%s\n", logBuff);

	if (logLevel <= cfig.dnsLogLevel)
	{
		char *mess = cloneString(logBuff);
		_beginthread(logThread, 0, mess);
	}
}

void logDNSMess(data5 *req, char *logBuff, MYBYTE logLevel)
{
	if (verbatim)
		printf("%s\n", logBuff);

	if (logLevel <= cfig.dnsLogLevel)
	{
		char *mess = (char*)calloc(1, 512);
		sprintf(mess, "Client %s, %s", inet_ntoa(req->remote.sin_addr), logBuff);
		_beginthread(logThread, 0, mess);
	}
}

void logTCPMess(data5 *req, char *logBuff, MYBYTE logLevel)
{
	if (verbatim)
		printf("%s\n", logBuff);

	if (logLevel <= cfig.dnsLogLevel)
	{
		char *mess = (char*)calloc(1, 512);
		sprintf(mess, "TCP Client %s, %s", inet_ntoa(req->remote.sin_addr), logBuff);
		_beginthread(logThread, 0, mess);
	}
}

CachedData *createCache(data71 *lump)
{
	MYWORD dataSize = 4 + sizeof(CachedData) + strlen(lump->mapname);
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

			MYBYTE *dp = &cache->data;
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
			MYBYTE *dp = &cache->data;
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
			MYBYTE *dp = &cache->data;
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
			MYBYTE *dp = &cache->data;
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
			MYBYTE *dp = &cache->data;
			cache->mapname = (char*)dp;
			setMapName(cache->mapname, lump->mapname, lump->dnsType);
			dp++;
			cache->name = (char*)dp;
			break;
		}
	}

	//sprintf(logBuff, "New Cache cType=%d dnsType=%u name=%s", cache->cType, cache->dnsType, cache->name);
	//logMess(logBuff, 1);
	return cache;
}
