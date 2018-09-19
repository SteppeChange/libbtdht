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

#include "ExternalIPCounter.h"
#include "sockaddr.h" // for SockAddr, is_ip_local
#include "logger.h"

#include <utility> // for std::make_pair
#include <time.h>


std::string print_sockaddr(SockAddr const& addr);


ExternalIPCounter::ExternalIPCounter(SHACallback* sha, IPEvents* events)
	: _fixed(false)
	, _events(events)
{
	Reset();
}

void ExternalIPCounter::Reset()
{
       _map.clear();
       _voters.clear();
       _winnerV4 = _map.end();
}

void ExternalIPCounter::SetFixedPubliIp(const SockAddr& addr)
{
	_fixed = true;
	std::pair<candidate_map::iterator, bool> inserted = _map.insert(std::make_pair(addr, 1));
	_winnerV4 = inserted.first;

}

bool ExternalIPCounter::CountIP( const SockAddr& addr, const SockAddr& voter) {

	if(_fixed)
		return false;

	// ignore anyone who claims our external IP is
	// INADDR_ANY or on a local network
	if(addr.is_addr_any() || is_ip_local(addr))
		return false;

	// all public internet addresses are v4
	if(addr.isv6())
		return false;

	voters_map::const_iterator vit = _voters.find(voter);
	if(vit==_voters.end()) {
		_voters[voter] = addr;
		debug_log("PublicIP: Update Voter: %s Ip:%s\n", print_sockaddr(voter).c_str(), print_sockaddr(addr).c_str());

		// _HeatStarted = time(NULL);

		// attempt to insert this vote
		std::pair<candidate_map::iterator, bool> inserted = _map.insert(std::make_pair(addr, 1));

		// check Symmetric NAT
		size_t ex_ips = _map.size();
		if(ex_ips>1) // 2 different ip's
		{
			warnings_log("PublicIP: May be symmetric NAT detected\n");
			for (auto it=_map.begin(), end=_map.end(); it!=end; ++it) {
				debug_log("PublicIP: Unique external IP: %s\n", print_sockaddr(it->first).c_str());
			}
			if(ex_ips==4 && _events)
				_events->symmetric_NAT_detected();
		};

		// increase voter's counter
		if (!inserted.second)
			inserted.first->second += 1;

		if(_winnerV4 == _map.end()) {
			_winnerV4 = inserted.first;
			// dont call IpChanged because its first voter
			return true;
		}

		// if the IP vout count exceeds the current leader, replace it
		if(inserted.first->second > _winnerV4->second) {
			warnings_log("PublicIP: Detected new ip %s from voter %s voting: %d %d\n",
					print_sockaddr(addr).c_str(),
					print_sockaddr(voter).c_str(),
					_winnerV4->second, inserted.first->second);
			IpChanged(addr, voter);
			return true;
		}

		return false;
	}
	else
	{
		if(vit->second == addr)
			// already voted with te same address
			return false;
		else {
			// new IP detected. Old voter reports new my ip.
			warnings_log("PublicIP: New IP was detected. Old voter reports new ip, new ip is %s from voter %s, old ip is %s\n",
						 print_sockaddr(addr).c_str(),
						 print_sockaddr(voter).c_str(),
						 print_sockaddr(vit->second).c_str());

			if(_winnerV4->first == addr)
			{
				error_log("PublicIP: Something strange!!! Old ip\n");
				assert(false);
			} else
				IpChanged(addr, voter);
			return true;
		}
	}

	return false;
}

void ExternalIPCounter::IpChanged(const SockAddr& addr, const SockAddr& voter)
{
	Reset();
	CountIP(addr, voter);
}

SockAddr ExternalIPCounter::GetIP() const {
	if(_winnerV4 == _map.end())
		return SockAddr();
	else
		return _winnerV4->first;
}

