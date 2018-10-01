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
		_ip_rating[it->second._reported_ip]++;
	}

	for(auto it = _ip_rating.begin(); it != _ip_rating.end(); ++it) {
		debug_log("PublicIP: last 60 sec, ip: %s rating: %d", print_sockaddr(it->first).c_str(), it->second);
	}

	_winnerV4 = _ip_rating.find(pub_ip);

	assert(_winnerV4 != _ip_rating.end());

}

void ExternalIPCounter::SetFixedPubliIp(const SockAddr& addr)
{
	_fixed = true;
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
			warnings_log("PublicIP: May be symmetric NAT detected");
			for (auto it=_ip_rating.begin(), end=_ip_rating.end(); it!=end; ++it) {
				debug_log("PublicIP: Unique external IP: %s", print_sockaddr(it->first).c_str());
			}
			if(ex_ips==4 && _events)
				_events->symmetric_NAT_detected();
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
			IpChanged(addr, voter, now);
			return true;
		}

		return false;
	}
	else
	{
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

			if(_winnerV4->first == addr) {
				debug_log("PublicIP: old voter reports new ip, but this ip is reported by other voters too, its winner");
				return false;
			} else {

				candidate_map::iterator old_ip = _ip_rating.find(vit->second._reported_ip);
				candidate_map::iterator new_ip = _ip_rating.find(addr);
				if(old_ip==_ip_rating.end())
				{
					// если нам репортят новый ip то значит старый точно есть в мапе
					assert(false);
					return false;
				} else {
					// -1 for old ip voter's count
					old_ip->second--;
					// +1 for new ip voter's count
					if(new_ip ==_ip_rating.end()) {
						_ip_rating[vit->second._reported_ip] = 1;
						new_ip = _ip_rating.find(addr);
					}
					else
						new_ip->second++;

					// new voter -> ip link
					vit->second._reported_ip = addr;

					// if the IP vout count exceeds the current leader, replace it
					if(new_ip->second > _winnerV4->second) {
						warnings_log("PublicIP: Detected new ip %s from voter %s voting: %d %d",
									 print_sockaddr(addr).c_str(),
									 print_sockaddr(voter).c_str(),
									 _winnerV4->second, vit->second);
						IpChanged(addr, voter, now);
						return true;
					} else
						return false;

				}

			}

		}
	}

	return false;
}

void ExternalIPCounter::IpChanged(const SockAddr& addr, const SockAddr& voter, uint64_t now)
{
	warnings_log("PublicIP: ip was changed %s -> %s",
				 print_sockaddr(_winnerV4->first).c_str(),
				 print_sockaddr(addr).c_str());

	_events->ip_changed(_winnerV4->first.get_sockaddr_storage() , addr.get_sockaddr_storage());
	Reset();
	CountIP(addr, voter, now);
}

std::pair<SockAddr,int> ExternalIPCounter::GetIP() const {
	if(_winnerV4 == _ip_rating.end())
		return std::make_pair(SockAddr(),0);
	else
		return *_winnerV4;
}

