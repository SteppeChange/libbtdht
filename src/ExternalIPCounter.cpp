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
       _ip_rating.clear();
       _voters.clear();
       _winnerV4 = _ip_rating.end();
}


void ExternalIPCounter::EraseOutdated(uint64_t valid_time_ms)
{
	SockAddr pub_ip = _winnerV4->first;

	// delete expired voters
	for(auto it = _voters.begin(); it != _voters.end(); ) {
		if (it->second._voting_time < valid_time_ms) {
			_voters.erase(it++);
		} else {
			++it;
		}
	}

	// fill new _ip_rating
	_ip_rating.clear();
	for(auto it = _voters.begin(); it != _voters.end(); ++it) {
		debug_log("PublicIP: last 60 sec, voter: %s ip: %s", print_sockaddr(it->first).c_str(), print_sockaddr(it->second._reported_ip).c_str());
		_ip_rating[it->second._reported_ip]++;
	}

	for(auto it = _ip_rating.begin(); it != _ip_rating.end(); ++it) {
		debug_log("PublicIP: last 60 sec, ip: %s rating: %d", print_sockaddr(it->first).c_str(), it->second);
	}

	_winnerV4 = _ip_rating.find(pub_ip);

// it happens if there is no internet	assert(_winnerV4 != _ip_rating.end());

}

void ExternalIPCounter::SetFixedPublicIp(const SockAddr &addr)
{
    info_log("Set Fixed Public IP: %s", print_sockaddr(addr).c_str());
	_fixed = true;
    Reset();
	std::pair<candidate_map::iterator, bool> inserted = _ip_rating.insert(std::make_pair(addr, 1));
	_winnerV4 = inserted.first;

}

bool ExternalIPCounter::CountIP( const SockAddr& addr, const SockAddr& voter, uint64_t now) {

	if(_fixed)
		return false;

	// ignore anyone who claims our external IP is
	// INADDR_ANY or on a local network
	if(addr.is_addr_any() || is_ip_local(addr))
		return false;

	// all public internet addresses are v4
	if(addr.isv6())
		return false;

	voters_map::iterator vit = _voters.find(voter);
	if(vit ==_voters.end()) {
		// new voter
		_voters[voter] = { addr, now};
		debug_log("PublicIP: New voter: %s reports ip:%s", print_sockaddr(voter).c_str(), print_sockaddr(addr).c_str());

		// _HeatStarted = time(NULL);

		// attempt to insert this vote
		std::pair<candidate_map::iterator, bool> inserted = _ip_rating.insert(std::make_pair(addr, 1));
		// increase voter's counter
		if (!inserted.second)
			inserted.first->second += 1;

		// check Symmetric NAT
		size_t ex_ips = _ip_rating.size();
		if(ex_ips>1) // 2 different ip's
		{
			warnings_log("PublicIP: May be symmetric NAT");
			for (auto it=_ip_rating.begin(), end=_ip_rating.end(); it!=end; ++it) {
				debug_log("PublicIP: Unique external IP: %s", print_sockaddr(it->first).c_str());
			}
            if(ex_ips==4 && _events) {
                warnings_log("PublicIP: Symmetric NAT");
				_events->symmetric_NAT_detected();
				// fix IP to prevent dht id changing for symmetric NAT
                SetFixedPublicIp(_winnerV4->first);
                return false;
            }
		};


		if(_winnerV4 == _ip_rating.end()) {
			_winnerV4 = inserted.first;
			// dont call IpChanged because its first voter
			warnings_log("PublicIP: First time ip detected new ip %s from voter %s voting: %d %d",
						 print_sockaddr(addr).c_str(),
						 print_sockaddr(voter).c_str(),
						 _winnerV4->second, inserted.first->second);
			return true;
		}

		// if the IP vout count exceeds the current leader, replace it
		if(inserted.first->second > _winnerV4->second) {
			warnings_log("PublicIP: Detected new ip %s from voter %s voting: %d %d",
					print_sockaddr(addr).c_str(),
					print_sockaddr(voter).c_str(),
					_winnerV4->second, inserted.first->second);
			return IpChanged(addr, voter, now); // // return true for restart lib
		}

		return false;
	}
	else
	{
		// old voter
		vit->second._voting_time = now;
		if(vit->second._reported_ip == addr)
			// already voted with te same address
			return false;
		else {
			// new IP detected. Old voter reports new my ip.
			warnings_log("PublicIP: New IP was detected. Old voter reports new ip, new ip is %s from voter %s, old ip is %s",
						 print_sockaddr(addr).c_str(),
						 print_sockaddr(voter).c_str(),
						 print_sockaddr(vit->second._reported_ip).c_str());

			DumpStatistics();

			if(_winnerV4->first == addr) {
				debug_log("PublicIP: old voter reports new ip, but this ip is reported by other voters too, its winner");
				return false;
			} else {

				candidate_map::iterator old_ip = _ip_rating.find(vit->second._reported_ip);
				// candidate_map::iterator new_ip = _ip_rating.find(addr);
				std::pair<candidate_map::iterator, bool> new_ip = _ip_rating.insert(std::make_pair(addr, 1));
				if(old_ip ==_ip_rating.end())
				{
					// если нам репортят новый ip то значит старый точно есть в мапе
					error_log("PublicIP: old ip %s not found at raiting ", print_sockaddr(vit->second._reported_ip).c_str());
					assert(false);
					return false;
				} else {
					// -1 for old ip voter's count
					old_ip->second--;
					// +1 for new ip voter's count
					if(new_ip.second == false)
						new_ip.first->second++;

					// new voter -> ip link
					vit->second._reported_ip = addr;

					// if the IP vout count exceeds the current leader, replace it
					if(new_ip.first->second > _winnerV4->second) {
						warnings_log("PublicIP: Detected new ip %s from voter %s voting: %d %d",
									 print_sockaddr(addr).c_str(),
									 print_sockaddr(voter).c_str(),
									 _winnerV4->second, vit->second);
						return IpChanged(addr, voter, now); // // return true for restart lib
					} else
						return false;

				}

			}

		}
	}

	return false;
}

void ExternalIPCounter::DumpStatistics()
{

	debug_log("PublicIP: *** Dump:");
	for (auto it=_ip_rating.begin(), end=_ip_rating.end(); it!=end; ++it)
		debug_log("PublicIP: *** external IP: %s voters: %d", print_sockaddr(it->first).c_str(), it->second);

	for(auto it = _voters.begin(); it != _voters.end(); ++it)
		debug_log("PublicIP: *** voter IP: %s reported: %s time: %ld"
				, print_sockaddr(it->first).c_str()
				, print_sockaddr(it->second._reported_ip).c_str()
				, it->second._voting_time );

}


bool ExternalIPCounter::IpChanged(const SockAddr& addr, const SockAddr& voter, uint64_t now)
{
	warnings_log("PublicIP: ip or ip:port was changed %s -> %s",
				 print_sockaddr(_winnerV4->first).c_str(),
				 print_sockaddr(addr).c_str());

	bool port_changed = _winnerV4->first.get_port() != addr.get_port();
	bool ip_changed = !addr.ip_eq(_winnerV4->first);

	DumpStatistics();

	// clear all tables and setup new voter like first voter
	Reset();
	bool res = CountIP(addr, voter, now);
	assert(res == true); // first vote always returns true

	// optimization:
//	There are two variants:
//	1. Ip was changed.
//	2. Only port was changed.
//  Port important for dht internal mechanisms
// 		(see // never add yourself to the routing table)
//		(see // local and public transport addresses for punch_test)
//	But port is not important for system at all
//	We don't use the port to sign dht_id
//  We don't use the port and ip for announce. Announce operation announces only dht_id
// So idea: - we will change winner always, but restart dht lib only if ip was changed.

	if(ip_changed)
	{
		// inform other libs that ip was changed
		_events->dht_callback_public_ip_changed();
		// return true for restart DHT for new dht id
		return true;
	}
	else
	{
		assert(port_changed);
		return false;
	}
}

std::pair<SockAddr,int> ExternalIPCounter::GetIP() const {
	if(_winnerV4 == _ip_rating.end())
		return std::make_pair(SockAddr(),0);
	else
		return *_winnerV4;
}

