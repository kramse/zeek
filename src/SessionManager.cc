// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeek-config.h"
#include "zeek/SessionManager.h"

#include <netinet/in.h>
#include <arpa/inet.h>

#include <stdlib.h>
#include <unistd.h>

#include <pcap.h>

#include "zeek/Desc.h"
#include "zeek/RunState.h"
#include "zeek/Event.h"
#include "zeek/Timer.h"
#include "zeek/NetVar.h"
#include "zeek/Reporter.h"
#include "zeek/RuleMatcher.h"
#include "zeek/Session.h"
#include "zeek/TunnelEncapsulation.h"
#include "zeek/telemetry/Manager.h"

#include "zeek/analyzer/protocol/icmp/ICMP.h"
#include "zeek/analyzer/protocol/udp/UDP.h"
#include "zeek/analyzer/Manager.h"

#include "zeek/iosource/IOSource.h"
#include "zeek/packet_analysis/Manager.h"

#include "zeek/analyzer/protocol/stepping-stone/events.bif.h"

zeek::SessionManager* zeek::session_mgr = nullptr;
zeek::SessionManager*& zeek::sessions = zeek::session_mgr;

namespace zeek {

SessionManager::~SessionManager()
	{
	Clear();
	}

void SessionManager::Done()
	{
	}

Connection* SessionManager::FindConnection(Val* v)
	{
	const auto& vt = v->GetType();
	if ( ! IsRecord(vt->Tag()) )
		return nullptr;

	RecordType* vr = vt->AsRecordType();
	auto vl = v->As<RecordVal*>();

	int orig_h, orig_p;	// indices into record's value list
	int resp_h, resp_p;

	if ( vr == id::conn_id )
		{
		orig_h = 0;
		orig_p = 1;
		resp_h = 2;
		resp_p = 3;
		}

	else
		{
		// While it's not a conn_id, it may have equivalent fields.
		orig_h = vr->FieldOffset("orig_h");
		resp_h = vr->FieldOffset("resp_h");
		orig_p = vr->FieldOffset("orig_p");
		resp_p = vr->FieldOffset("resp_p");

		if ( orig_h < 0 || resp_h < 0 || orig_p < 0 || resp_p < 0 )
			return nullptr;

		// ### we ought to check that the fields have the right
		// types, too.
		}

	const IPAddr& orig_addr = vl->GetFieldAs<AddrVal>(orig_h);
	const IPAddr& resp_addr = vl->GetFieldAs<AddrVal>(resp_h);

	auto orig_portv = vl->GetFieldAs<PortVal>(orig_p);
	auto resp_portv = vl->GetFieldAs<PortVal>(resp_p);

	ConnID id;

	id.src_addr = orig_addr;
	id.dst_addr = resp_addr;

	id.src_port = htons((unsigned short) orig_portv->Port());
	id.dst_port = htons((unsigned short) resp_portv->Port());

	id.is_one_way = false;	// ### incorrect for ICMP connections
	id.proto = orig_portv->PortType();

	detail::ConnIDKey conn_key = detail::BuildConnIDKey(id);
	detail::SessionKey key(&conn_key, sizeof(conn_key), false);

	Connection* conn = nullptr;
	auto it = session_map.find(key);
	if ( it != session_map.end() )
		conn = static_cast<Connection*>(it->second);

	return conn;
	}

Connection* SessionManager::FindConnection(const detail::ConnIDKey& conn_key)
	{
	detail::SessionKey key(&conn_key, sizeof(conn_key), false);

	auto it = session_map.find(key);
	if ( it != session_map.end() )
		return static_cast<Connection*>(it->second);

	return nullptr;
	}

void SessionManager::Remove(Session* s)
	{
	Connection* c = static_cast<Connection*>(s);

	if ( s->IsKeyValid() )
		{
		s->CancelTimers();
		s->Done();
		s->RemovalEvent();

		// Clears out the session's copy of the key so that if the
		// session has been Ref()'d somewhere, we know that on a future
		// call to Remove() that it's no longer in the map.
		detail::SessionKey key = s->SessionKey(false);

		if ( session_map.erase(key) == 0 )
			reporter->InternalWarning("connection missing");
		else
			{
			if ( auto* stat_block = stats.GetCounters(c->TransportIdentifier()) )
				stat_block->num.Dec();
			}

		s->ClearKey();
		Unref(s);
		}
	}

void SessionManager::Insert(Session* s, bool remove_existing)
	{
	assert(s->IsKeyValid());

	Session* old = nullptr;
	detail::SessionKey key = s->SessionKey(true);

	if ( remove_existing )
		{
		auto it = session_map.find(key);
		if ( it != session_map.end() )
			old = it->second;

		session_map.erase(key);
		}

	InsertSession(std::move(key), s);

	if ( old && old != s )
		{
		// Some clean-ups similar to those in Remove() (but invisible
		// to the script layer).
		old->CancelTimers();
		old->ClearKey();
		Unref(old);
		}
	}

void SessionManager::Drain()
	{
	for ( const auto& entry : session_map )
		{
		Session* tc = entry.second;
		tc->Done();
		tc->RemovalEvent();
		}
	}

void SessionManager::Clear()
	{
	for ( const auto& entry : session_map )
		Unref(entry.second);

	session_map.clear();

	detail::fragment_mgr->Clear();
	}

void SessionManager::GetStats(SessionStats& s)
	{
	auto* tcp_stats = stats.GetCounters("tcp");
	s.max_TCP_conns = tcp_stats->max;
	s.num_TCP_conns = tcp_stats->num.Value();
	s.cumulative_TCP_conns = tcp_stats->total.Value();

	auto* udp_stats = stats.GetCounters("udp");
	s.max_UDP_conns = udp_stats->max;
	s.num_UDP_conns = udp_stats->num.Value();
	s.cumulative_UDP_conns = udp_stats->total.Value();

	auto* icmp_stats = stats.GetCounters("icmp");
	s.max_ICMP_conns = icmp_stats->max;
	s.num_ICMP_conns = icmp_stats->num.Value();
	s.cumulative_ICMP_conns = icmp_stats->total.Value();

	s.num_fragments = detail::fragment_mgr->Size();
	s.max_fragments = detail::fragment_mgr->MaxFragments();
	s.num_packets = packet_mgr->PacketsProcessed();
	}

void SessionManager::Weird(const char* name, const Packet* pkt, const char* addl, const char* source)
	{
	const char* weird_name = name;

	if ( pkt )
		{
		pkt->dump_packet = true;

		if ( pkt->encap && pkt->encap->LastType() != BifEnum::Tunnel::NONE )
			weird_name = util::fmt("%s_in_tunnel", name);

		if ( pkt->ip_hdr )
			{
			reporter->Weird(pkt->ip_hdr->SrcAddr(), pkt->ip_hdr->DstAddr(), weird_name, addl, source);
			return;
			}
		}

	reporter->Weird(weird_name, addl, source);
	}

void SessionManager::Weird(const char* name, const IP_Hdr* ip, const char* addl)
	{
	reporter->Weird(ip->SrcAddr(), ip->DstAddr(), name, addl);
	}

unsigned int SessionManager::SessionMemoryUsage()
	{
	unsigned int mem = 0;

	if ( run_state::terminating )
		// Connections have been flushed already.
		return 0;

	for ( const auto& entry : session_map )
		mem += entry.second->MemoryAllocation();

	return mem;
	}

unsigned int SessionManager::SessionMemoryUsageVals()
	{
	unsigned int mem = 0;

	if ( run_state::terminating )
		// Connections have been flushed already.
		return 0;

	for ( const auto& entry : session_map )
		mem += entry.second->MemoryAllocationVal();

	return mem;
	}

unsigned int SessionManager::MemoryAllocation()
	{
	if ( run_state::terminating )
		// Connections have been flushed already.
		return 0;

	return SessionMemoryUsage()
		+ padded_sizeof(*this)
		+ (session_map.size() * (sizeof(SessionMap::key_type) + sizeof(SessionMap::value_type)))
		+ detail::fragment_mgr->MemoryAllocation();
		// FIXME: MemoryAllocation() not implemented for rest.
		;
	}

void SessionManager::InsertSession(detail::SessionKey key, Session* session)
	{
	key.CopyData();
	session_map.insert_or_assign(std::move(key), session);

	std::string protocol = session->TransportIdentifier();

	if ( auto* stat_block = stats.GetCounters(protocol) )
		{
		stat_block->num.Inc();
		stat_block->total.Inc();

		if ( stat_block->num.Value() > stat_block->max )
			stat_block->max++;
		}
	}

detail::PacketFilter* SessionManager::GetPacketFilter(bool init)
	{
	return packet_mgr->GetPacketFilter(init);
	}

} // namespace zeek
