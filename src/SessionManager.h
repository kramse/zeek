// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h> // for u_char
#include <map>
#include <utility>

#include "zeek/Frag.h"
#include "zeek/NetVar.h"
#include "zeek/analyzer/protocol/tcp/Stats.h"
#include "zeek/telemetry/Manager.h"
#include "zeek/Hash.h"
#include "zeek/Session.h"

namespace zeek {

namespace detail { class PacketFilter; }

class EncapsulationStack;
class Packet;
class Connection;
struct ConnID;

struct SessionStats {
	size_t num_TCP_conns;
	size_t max_TCP_conns;
	uint64_t cumulative_TCP_conns;

	size_t num_UDP_conns;
	size_t max_UDP_conns;
	uint64_t cumulative_UDP_conns;

	size_t num_ICMP_conns;
	size_t max_ICMP_conns;
	uint64_t cumulative_ICMP_conns;

	size_t num_fragments;
	size_t max_fragments;
	uint64_t num_packets;
};

class SessionManager final {
public:
	SessionManager() = default;
	~SessionManager();

	void Done();	// call to drain events before destructing

	// Looks up the connection referred to by the given Val,
	// which should be a conn_id record.  Returns nil if there's
	// no such connection or the Val is ill-formed.
	Connection* FindConnection(Val* v);

	/**
	 * Looks up the connection referred to by a given key.
	 *
	 * @param conn_key The key for the connection to search for.
	 * @return The connection, or nullptr if one doesn't exist.
	 */
	Connection* FindConnection(const detail::ConnIDKey& conn_key);

	void Remove(Session* s);
	void Insert(Session* c, bool remove_existing=true);

	// Generating connection_pending events for all connections
	// that are still active.
	void Drain();

	// Clears the session maps.
	void Clear();

	void GetStats(SessionStats& s);

	void Weird(const char* name, const Packet* pkt,
	           const char* addl = "", const char* source = "");
	void Weird(const char* name, const IP_Hdr* ip,
	           const char* addl = "");

	[[deprecated("Remove in v5.1. Use packet_mgr->GetPacketFilter().")]]
	detail::PacketFilter* GetPacketFilter(bool init=true);

	unsigned int CurrentSessions()
		{
		return session_map.size();
		}

	[[deprecated("Remove in v5.1. Use CurrentSessions().")]]
	unsigned int CurrentConnections() { return CurrentSessions(); }

	unsigned int SessionMemoryUsage();
	unsigned int SessionMemoryUsageVals();

	[[deprecated("Remove in v5.1. Use SessionMemoryUsage().")]]
	unsigned int ConnectionMemoryUsage() { return SessionMemoryUsage(); }
	[[deprecated("Remove in v5.1. Use SessionMemoryUsageVals().")]]
	unsigned int ConnectionMemoryUsageConnVals() { return SessionMemoryUsageVals(); }

	unsigned int MemoryAllocation();

	// TODO: should this move somewhere else?
	analyzer::tcp::TCPStateStats tcp_stats;	// keeps statistics on TCP states

private:

	class StatBlocks {

	public:

		struct Block {
			telemetry::IntGauge num;
			telemetry::IntCounter total;
			size_t max = 0;

			Block(telemetry::IntGaugeFamily num_family,
			      telemetry::IntCounterFamily total_family,
			      std::string protocol) : num(num_family.GetOrAdd({{"protocol", protocol}})),
			                              total(total_family.GetOrAdd({{"protocol", protocol}}))
				{
				}
			};

		using BlockMap = std::map<std::string, Block>;

		BlockMap::iterator InitCounters(std::string protocol)
			{
			telemetry::IntGaugeFamily num_family = telemetry_mgr->GaugeFamily(
				"zeek", "open-sessions", {"protocol"}, "Active Zeek Sessions");
			telemetry::IntCounterFamily total_family = telemetry_mgr->CounterFamily(
				"zeek", "sessions", {"protocol"},
				"Total number of sessions", "1", true);

			auto [it, inserted] = entries.insert(
				{protocol, Block{num_family, total_family, protocol}});

			if ( inserted )
				return it;

			return entries.end();
			}

		Block* GetCounters(std::string protocol)
			{
			auto it = entries.find(protocol);
			if ( it == entries.end() )
				it = InitCounters(protocol);

			if ( it != entries.end() )
				return &(it->second);

			return nullptr;
			}

	private:

		BlockMap entries;
	};

	using SessionMap = std::map<detail::SessionKey, Session*>;

	// Inserts a new connection into the sessions map. If a connection with
	// the same key already exists in the map, it will be overwritten by
	// the new one.  Connection count stats get updated either way (so most
	// cases should likely check that the key is not already in the map to
	// avoid unnecessary incrementing of connecting counts).
	void InsertSession(detail::SessionKey key, Session* session);

	SessionMap session_map;
	StatBlocks stats;
};

// Manager for the currently active sessions.
extern SessionManager* session_mgr;
extern SessionManager*& sessions [[deprecated("Remove in v5.1. Use zeek::session_mgr.")]];

using NetSessions [[deprecated("Remove in v5.1. Use zeek::SessionManager.")]] = SessionManager;

} // namespace zeek
