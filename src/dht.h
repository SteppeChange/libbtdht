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

#ifndef __DHT_H__
#define __DHT_H__

/**
 * @ingroup dht
 */

#include <stddef.h> // for size_t
#include <vector>
#include <list>
#include "utypes.h"
#include "sha1_hash.h"
#include "sockaddr.h"
#include "RefBase.h"
#include "smart_ptr.h"
#include <functional>
#include <netdb.h>


class UDPSocketInterface;
class ExternalIPCounter;
class BencEntity;


enum DHTLogLevel {
    EDhtError = 0,
	EDhtWarnings,
	EDhtInfo,
    EDhtTrace,
    EDhtDebug,
    EDhtVerbose
};

enum DhtProcessFlags
{
	EMPTY           = 0x00,
	NORMAL_RESPONSE = 0x01,
	PROCESS_AS_SLOW = 0x02,
	ICMP_ERROR      = 0x04,
	TIMEOUT_ERROR   = 0x08,
	ID_MISMATCH   	= 0x10,
	ANY_ERROR       = ICMP_ERROR | TIMEOUT_ERROR | ID_MISMATCH
};

enum BootState {
	EBootUnknown = - 1,
	EBootStart = 0,
	EBootSuccess = 1,
	EBootFailed = 2,
};

enum OpenChannelCodes {
	EOpenChannelUnInitialized = 0,
	EOpenChannelWrongDestination = 1,
	EOpenChannelInternalError = 2,
	EOpenChannelCustom = 100 // All custom codes should be 100+
};

inline const char* boot_to_string(BootState st)
{
	switch(st)
	{
		case EBootUnknown: return "EBootUnknown";
		case EBootStart: return "EBootStart";
		case EBootSuccess: return "EBootSuccess";
		case EBootFailed: return "EBootFailed";
	}
	return "Unknown";
}

struct channel_info {
	sha1_hash _translation_id;
};

struct announce_info {
	announce_info() : _time_of_announce(0), _vacant(0), _peer_type(0)
	{
	}
	sha1_hash _announcer_id;
	time_t _time_of_announce;
	uint16_t _vacant;
    uint8_t _peer_type;
};

typedef std::list<announce_info> announcers_list;

class DHTEvents {
public:
	virtual void bootstrap_state_changed(BootState state, sha1_hash new_id, sockaddr_storage const& public_address, sockaddr_storage const& local_address) = 0;
	virtual void dht_recv_punch_test(int punch_id, sockaddr_storage const &src_addr) = 0;
	virtual void dht_recv_punch_request_relay(int punch_id, sockaddr_storage const &src_addr, const byte *target) = 0;

	virtual void dht_recv_pong(sha1_hash const& id, sockaddr_storage const &src_addr, int rtt, DhtProcessFlags flag) = 0;
	virtual void dht_recv_ping(sha1_hash const& from_id, sockaddr_storage const &src_addr) = 0;

	virtual uint32_t dht_recv_open_channel(sha1_hash const& from_id, sockaddr_storage const &src_addr, channel_info const& info) = 0;
	virtual void dht_recv_open_channel_response(sha1_hash const &id, sockaddr_storage const &src_addr, int rtt, DhtProcessFlags flag, int response_code) = 0;
};

// callback types used in the DHT
typedef void DhtVoteCallback(void *ctx, const byte *target, int const* votes);
typedef void DhtHashFileNameCallback(void *ctx, const byte *info_hash, const byte *file_name);
typedef void DhtAddNodesCallback(void *ctx, const byte *info_hash, const byte *peers, uint num_peers, bool complete_process);
typedef void DhtGetPeersCallback(void *ctx, const byte *info_hash, announcers_list const& peers, bool complete_process);
typedef void DhtAddNodeResponseCallback(void*& userdata, bool is_response, SockAddr const& addr);
typedef void DhtScrapeCallback(void *ctx, const byte *target, int downloaders, int seeds);
typedef int DhtPutCallback(void * ctx, std::vector<char>& buffer, int64& seq, SockAddr src);
typedef int DhtPutDataCallback(void * ctx, std::vector<char> const& buffer, int64 seq, SockAddr src);
typedef void DhtPutCompletedCallback(void * ctx);
typedef void DhtGetCallback(void* ctx, std::vector<char> const& buffer);


typedef void DhtLogWriteCallback(int level, char const* str);
typedef int DhtLogLevelCallback();
struct DhtLogCallbacks {
	DhtLogCallbacks()
			: write(0)
			, level(0)
	{}
	DhtLogWriteCallback* write;
	DhtLogLevelCallback* level;
};

// asks the client to save the DHT state
typedef void DhtSaveCallback(void* user_data, const byte* buf, int len);

// asks the client to load the DHT state into ent
typedef void DhtLoadCallback(void* user_data, BencEntity* ent);

// called for all incoming and outgoing packets
typedef void DhtPacketCallback(void const* buffer, size_t len, bool incoming);

// allows the dht client to define what SHA-1 implementation to use
typedef sha1_hash DhtSHACallback(byte const* buf, int len);

// callback to ed25519 crypto_sign_open used for message verification
typedef bool Ed25519VerifyCallback(const unsigned char *signature,
		const unsigned char *message, size_t message_len,
		const unsigned char *key);

typedef void Ed25519SignCallback(unsigned char *signature,
		const unsigned char *message, size_t message_len,
		const unsigned char *key);

typedef void DhtPunchCallback(int punch_id, SockAddr const& source);



/**
 * DHT public interface
 */

class IDht : public RefBase
{
public:
	// Resolve gcc warning about nonvirtual destructor with virtual methods
	virtual ~IDht();

	enum announce_flags_t
	{
		announce_seed = 1,
		announce_non_aggressive = 2,
		announce_only_get = 4,
		with_cas = 8, // use cas for DHT put
	};

	// load from cache
	//virtual bool LoadBindIp(BencEntity &data, sockaddr_storage& bind_addr) = 0;
	virtual bool handleReadEvent(UDPSocketInterface *socket, byte *buffer, size_t len, const SockAddr& addr) = 0;
	virtual bool handleICMP(UDPSocketInterface *socket, byte *buffer, size_t len, const SockAddr& addr) = 0;
	virtual void Tick() = 0;
	virtual void Vote(void *ctx, const sha1_hash* info_hash, int vote, DhtVoteCallback* callb) = 0;
	
	virtual void Put(
		//pkey points to a 32-byte ed25519 public.
		const byte * pkey,
		const byte * skey,

		// This method is called in DhtSendRPC for Put. It takes v (from get
		// responses) as an input and may or may not change v to place in Put
		// messages. if the callback function returns a non-zero value, the
		// DhtProcess is aborted and the value is not stored back in the DHT.
		DhtPutCallback* put_callback,

		//called in CompleteThisProcess
		DhtPutCompletedCallback * put_completed_callback,

		// called every time we receive a blob from a node. This cannot be used
		// to modify and write back the data, this is just a sneak-peek of what's
		// likely to be in the final blob that's passed to put_callback if the
		// callback function returns a non-zero value, the DhtProcess is aborted
		// and the value is not stored back in the DHT.
		DhtPutDataCallback* put_data_callback,
		void *ctx,
		int flags = 0,

		// seq is an optional provided monotonically increasing sequence number to be
		// used in a Put request if the requester is keeping sequence number state
		// this number will be used if higher than any numbers gotten from peers
		int64 seq = 0) = 0;

	virtual sha1_hash ImmutablePut(
			const byte * data,
			size_t data_len,
			DhtPutCompletedCallback* put_completed_callback = nullptr,
			void *ctx = nullptr) = 0;

	virtual void ImmutableGet(sha1_hash target, DhtGetCallback* cb
		, void* ctx = nullptr) = 0;

	/* announce_peer classic wrapper
	 *
	 * Announce that the peer, controlling the querying node, is downloading a torrent on a port.
	 * "info_hash" containing the infohash of the torrent
	 *
	 */
	virtual void AnnounceInfoHash(
		const byte *info_hash,
		DhtAddNodesCallback *addnodes_callback,
		void *ctx,
		int flags,
		int vacant,
		uint8_t peer_type) = 0;

	/* get_peers classic wrapper
	 * There is one diff between classic and ResolveName: classic get_peers returns ip:port,  ResolveName returns dht_id
	 *
	 * Get peers associated with a torrent infohash. "q" = "get_peers"
	 * A get_peers query has two arguments, "id" containing the node ID of the querying node,
	 * and "info_hash" containing the infohash of the torrent.
	 *
	 */
	virtual void ResolveName(sha1_hash const& infohash, DhtGetPeersCallback* callb, void *ctx, int flags = 0) = 0;

	/*
	 * sockaddr_storage const& node_addr - found node ip:port
	 * sha1_hash const& source_id - found node hash id
	 * sockaddr_storage const& source_addr - neighbor of the found node, that have reported about it, (empty if found node is our neighbour)
	 * int rtt - round trip time of this node if its known
	 * */
	typedef std::function<void(sockaddr_storage const& node_addr, sha1_hash const& source_id, sockaddr_storage const& source_addr, int rtt)> find_node_success;
	/*
	 * classic find_node wrapper
	 *
	 * Find node is used to find the contact information for a node given its ID.
	 * "target" containing the ID of the node sought by the queryer.
	 *
	 */
	virtual void FindNode(sha1_hash const& target,
						  find_node_success const& success_fun,
						  std::function<void(std::string const& error_reason)> const& failed_fun)  = 0;

	/*  Address (ip/port) restricted NAT hole punching

		Theory:
		There are A, B, C nodes
		There are AB and BC connections
		We need AС connection
		A->С punching requires 2 packets - there and back
		First A->С (punch("test"), will be lost, but it's open the NAT to one side
		Second С->A (punch("test") will pass


		Algorithm:
		A sends packet to С - punch("test", punch_id)
					punch_id - unique punch command id
		A sends packet to B - punch("relay", target_addres, executor_addr, punch_id).
					target_address - ip:port A
					executor_addr - ip:port C
		B sends packet to C - punch("request",target_address, punch_id)
		C sends packet to A - punch("test", punch_id)

		Success indicator is receiving punch_test( punch_id )


			┌──────────> B (node relay) ────────────┐
			│										│
			│										│
		punch_relay							punch_request
			│										│
			│										˅
	 A (node target) <──────punch_test────── C (node executor)

	*/
	virtual void punch_test(int punch_id, sha1_hash const& target_id, SockAddr const& target) = 0;
	virtual void punch_relay(int punch_id,
							 SockAddr const& target_local, SockAddr const& target_public, SockAddr const& target_relay,
							 sha1_hash const& executor_id, SockAddr const& executor,
							 SockAddr const& relay) = 0;

	// just regular ping pong (measuring RTT and NAT hole refreshing)
	virtual void ping(sockaddr_storage const& node_addr, sha1_hash const& node_id) = 0;

	/*
	 * open translation channel request (response)
	 * node_addr - target node ip
	 * node_id - target node DHT ID
	 */
	virtual void open_channel(sockaddr_storage const& node_addr, sha1_hash const& node_id, channel_info const&  info) = 0;

	virtual void SetId(byte new_id_bytes[20]) = 0;
	virtual void Enable(bool enabled, int rate) = 0;

	enum {
		DHT_ORIGIN_FROM_PEER = 1, // Find Node results
		DHT_ORIGIN_INCOMING_QUERY,
		DHT_ORIGIN_RESPONSE,
		DHT_ORIGIN_CACHE
	};

	virtual sockaddr_storage get_public_ip() const = 0;

	virtual void SetVersion(char const* client, int major, int minor) = 0;
	virtual void SetRate(int bytes_per_second) = 0;

	virtual void SetExternalIPCounter(ExternalIPCounter* ip) = 0;
	virtual void SetAddNodeResponseCallback(DhtAddNodeResponseCallback* cb) = 0;
	virtual void SetSHACallback(DhtSHACallback* cb) = 0;
	virtual void SetEd25519VerifyCallback(Ed25519VerifyCallback* cb) = 0;
	virtual void SetEd25519SignCallback(Ed25519SignCallback* cb) = 0;
	virtual void AddBootstrapNode(SockAddr const& addr) = 0;

	// userdata pointer is passed on to the AddNodeReponseCallback
	virtual void AddNode(const SockAddr& addr, void* userdata, uint origin) = 0;
	virtual void Close() = 0;
	virtual void Shutdown() = 0;
	virtual void Initialize(void* user_data, UDPSocketInterface *, UDPSocketInterface *) = 0;
	virtual bool IsEnabled() = 0;
	virtual void ForceRefresh() = 0;
	// do not respond to queries - for mobile nodes with data constraints
	virtual void SetReadOnly(bool readOnly) = 0;
	virtual void SetPingFrequency(int seconds) = 0;
	virtual void SetPingBatching(int num_pings) = 0;
	virtual void EnableQuarantine(bool e) = 0;

	virtual bool ProcessIncoming(byte *buffer, size_t len, const SockAddr& addr) = 0;

	virtual void SaveState(void* user_data) = 0;
#ifdef _DEBUG_MEM_LEAK
	virtual int FreeRequests() = 0;
#endif
	virtual void DumpTracked() = 0;
	virtual void DumpBuckets() = 0;

#ifdef DHT_SEARCH_TEST
	void RunSearches() = 0;
#endif

	//
	// Linker
	//
	virtual int GetProbeQuota() = 0;
	virtual bool CanAddNode() = 0;
	virtual int GetNumPeers() = 0;
	virtual bool IsBusy() = 0;
	virtual int GetRate() = 0;
	virtual int GetQuota() = 0;
	virtual int GetProbeRate() = 0;
	virtual int GetNumPeersTracked() = 0;
	virtual void Restart() = 0;
	virtual void GenerateId() = 0;

	// So we can be pointed to by a smart pointer.
	// Implementation can derive from RefBase.
	virtual ULONG STDMETHODCALLTYPE AddRef(void) = 0;
	virtual ULONG STDMETHODCALLTYPE Release(void) = 0;
};

smart_ptr<IDht> create_dht(UDPSocketInterface *udp_socket_mgr, UDPSocketInterface *udp6_socket_mgr
	, DhtSaveCallback* save, DhtLoadCallback* load, void* callbacks_user_data
	, ExternalIPCounter* eip = NULL
	, DHTEvents* dht_events = NULL
	, bool boot_mode = false);

void set_log_callback(DhtLogCallbacks log);


// ipv6 support
inline sockaddr_storage ipv4ipv6_resolve(sockaddr_storage const& peer, int family)
{
	in_port_t port = 0;

	// we cant address ipv4 ip from ipv6 network
	if(peer.ss_family !=  family)
	{
		// resolve target address (peer) to bind interface family
		std::string addr_name;
		if (peer.ss_family == AF_INET6) {
			char buffer[INET6_ADDRSTRLEN];
			int error = getnameinfo((struct sockaddr const *) &peer, sizeof(sockaddr_in6), buffer, sizeof(buffer), 0, 0,
									NI_NUMERICHOST);
			if (error == 0) {
				addr_name = buffer;
				port = ((struct sockaddr_in6 const *) &peer)->sin6_port;
			}
		}
		if (peer.ss_family == AF_INET) {
			char buffer[INET_ADDRSTRLEN];
			int error = getnameinfo((struct sockaddr const *) &peer, sizeof(sockaddr_in), buffer, sizeof(buffer), 0, 0,
									NI_NUMERICHOST);
			if (error == 0) {
				addr_name = buffer;
				port = ((struct sockaddr_in const *) &peer)->sin_port;
			}
		}

		struct addrinfo hints, *res0;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = PF_UNSPEC; // family ?
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP;
		hints.ai_flags = AI_PASSIVE & AI_NUMERICHOST; // AI_NUMERICHOST flag suppresses any potentially lengthy network host address lookups.
		int error = getaddrinfo(addr_name.c_str(), std::to_string(port).c_str(), &hints, &res0);
		if (error) {
			return peer;
		}
		sockaddr_storage* resolved_peer = 0;
		for (struct addrinfo *i = res0; i != nullptr; i = i->ai_next) {
			if ((i->ai_family == AF_INET) && (family==AF_INET)) {
				sockaddr_in *v4 = (sockaddr_in *) i->ai_addr;
				v4->sin_port = port;
				resolved_peer = (sockaddr_storage*)v4;
			}
			if ((i->ai_family == AF_INET6) && (family==AF_INET6)) {
				sockaddr_in6 *v6 = (sockaddr_in6 *) i->ai_addr;
				v6->sin6_port = port;
				resolved_peer = (sockaddr_storage*)v6;
			}
		}

//		debug_log("resolving ip family before sending %s -> %s", print_sockaddr(peer).c_str(), print_sockaddr(resolved_peer).c_str());
        if(resolved_peer)
            return *resolved_peer;
        else
            return peer;
	}
	else
        return peer;
		

}
#endif //__DHT_H__

