
#pragma once

#include <arpa/inet.h>
#include "dht.h"


typedef void DhtLogCallback(int level, char const* str);
extern DhtLogCallback* g_logger;

// http://fuckingclangwarnings.com
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-security"
template<typename ... Args>
static void dht_log(DHTLogLevel level, char const* fmt, Args ... args)
{
	size_t size = snprintf(nullptr, 0, fmt, args ...) + 1;
	std::unique_ptr<char[]> buf(new char[size]);

	snprintf(buf.get(), size, fmt, args ...);
	std::string formatted(buf.get(), buf.get() + size - 1);

	(*g_logger)(static_cast<int>(level), formatted.c_str());
}
#pragma clang diagnostic pop

template<typename ... Args>
static void error_log(char const* fmt, Args ... args)
{
	dht_log(DHTLogLevel::EDhtError, fmt, args ...);
}

template<typename ... Args>
static void warnings_log(char const* fmt, Args ... args)
{
	dht_log(DHTLogLevel::EDhtWarnings, fmt, args ...);
}

template<typename ... Args>
static void trace_log(char const* fmt, Args ... args)
{
	dht_log(DHTLogLevel::EDhtTrace, fmt, args ...);
}

template<typename ... Args>
static void debug_log(char const* fmt, Args ... args)
{
	dht_log(DHTLogLevel::EDhtDebug, fmt, args ...);
}

template<typename ... Args>
static void verbose_log(char const* fmt, Args ... args)
{
	dht_log(DHTLogLevel::EDhtVerbose, fmt, args ...);
}


// TODO: factor this into btutils sockaddr
inline std::string print_sockaddr(SockAddr const& addr)
{
	char address[255]; // INET_ADDRSTRLEN
	memset(&address, 0, sizeof(address));
	int port = 0;
	size_t end = 0;
	sockaddr_storage const& sa = addr.get_sockaddr_storage();
	if (sa.ss_family == AF_INET6) {
		address[0]='[';
		inet_ntop( AF_INET6, &(((struct sockaddr_in6 const *)&sa)->sin6_addr), address+1, sizeof(address)-1 );
		address[strlen(address)]=']';
		port = ((struct sockaddr_in6 const *)&sa)->sin6_port;
	}
	if (sa.ss_family == AF_INET) {
		inet_ntop( AF_INET, &(((struct sockaddr_in const *)&sa)->sin_addr), address, sizeof(address) );
		port = ((struct sockaddr_in const *)&sa)->sin_port;
	}

	end = strlen(address);
	snprintf(address+end, sizeof(address)-end, ":%u", ntohs(port));
	return address;

}


inline std::string print_sockip(SockAddr const& addr)
{
	char buf[256];
	if (addr.isv6()) {
		in6_addr a = addr.get_addr6();
		int offset = 0;
		buf[offset++] = '[';
		for (int i = 0; i < 16; ++i)
			offset += snprintf(buf + offset,
							   sizeof(buf) - offset,
							   ":%02x",
							   a.s6_addr[i]);
	} else {
		uint a = addr.get_addr4();
		snprintf(buf, sizeof(buf), "%u.%u.%u.%u"
				, (a >> 24) & 0xff
				, (a >> 16) & 0xff
				, (a >> 8) & 0xff
				, a & 0xff);
	}
	return buf;
}

