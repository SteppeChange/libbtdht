/*
Copyright 2016 BitTorrent Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef __EXTERNAL_IP_COUNTER_H__
#define __EXTERNAL_IP_COUNTER_H__

// A voting heat ends after the max number of votes have
// been counted or the heat duration (in seconds) expires,
// whichever comes last
#define EXTERNAL_IP_HEAT_DURATION	600	// 10 minutes
#define EXTERNAL_IP_HEAT_MAX_VOTES	50

#include <map>
#include "sockaddr.h"
#include "bloom_filter.h"

// allows the dht client to define what SHA-1 implementation to use
typedef sha1_hash SHACallback(byte const* buf, int len);

class IPEvents {
	public:
		virtual void symmetric_NAT_detected() = 0;
		virtual void dht_callback_public_ip_changed() = 0;
};

struct voter_info {
	SockAddr _reported_ip;
	uint64_t _voting_time;
};

class ExternalIPCounter
{
public:
	ExternalIPCounter(SHACallback* sha, IPEvents* events);
	// return tru if addr cahnged
	bool CountIP( const SockAddr& addr, const SockAddr& voter, uint64_t now);
	void SetFixedPublicIp(const SockAddr &addr);
	std::pair<SockAddr,int> GetIP() const;
	void Reset();
	void EraseOutdated(uint64_t valid_time_ms);
	bool IpChanged(const SockAddr& addr, const SockAddr& voter, uint64_t now);
	void DumpStatistics();

private:
	typedef std::map<SockAddr, int> candidate_map; // <my ip, voters count>
	typedef std::map<SockAddr, voter_info> voters_map; // <voter ip, voter_info>

	voters_map _voters;
	candidate_map _ip_rating;
	candidate_map::const_iterator _winnerV4;
	bool _fixed;

	IPEvents* _events;
};


#endif //__EXTERNAL_IP_COUNTER_H__
