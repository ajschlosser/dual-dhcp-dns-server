# Dual DHCP DNS Server

As the name implies. This is a fork of the following project by Achal Dhir:

https://sourceforge.net/projects/dhcp-dns-server/

The goal is to clean up, continue to maintain, and extend as needed.

## Building

In order to build for Windows, this requires the Windows 7 SDK. The SDK can be
obtained from Microsoft here:

https://www.microsoft.com/en-us/download/details.aspx?id=3138

Using your preferred IDE, use the GCC compiler (i.e. MinGW) to compile this with
the following linked libraries: `-lws2_32 -lwsock32 -liphlpapi`.
