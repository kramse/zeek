// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeek-config.h"
#include "zeek/Sessions.h"

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

zeek::NetSessions* zeek::sessions;

namespace zeek {

NetSessions::NetSessions()
	: stats(telemetry_mgr->GaugeFamily("zeek", "session_stats",
	                                   {"tcp", "udp", "icmp"},
	                                   "Zeek Session Stats", "1", false))
	{
	}

NetSessions::~NetSessions()
	{
	Clear();
	}

void NetSessions::Done()
	{
	}

void NetSessions::ProcessTransportLayer(double t, const Packet* pkt, size_t remaining)
	{
	const std::unique_ptr<IP_Hdr>& ip_hdr = pkt->ip_hdr;

	uint32_t len = ip_hdr->TotalLen();
	uint16_t ip_hdr_len = ip_hdr->HdrLen();

	if ( len < ip_hdr_len )
		{
		sessions->Weird("bogus_IP_header_lengths", pkt);
		return;
		}

	len -= ip_hdr_len;	// remove IP header

	int proto = ip_hdr->NextProto();

	if ( CheckHeaderTrunc(proto, len, remaining, pkt) )
		return;

	const u_char* data = ip_hdr->Payload();

	ConnID id;
	id.src_addr = ip_hdr->SrcAddr();
	id.dst_addr = ip_hdr->DstAddr();
	BifEnum::Tunnel::Type tunnel_type = BifEnum::Tunnel::IP;

	switch ( proto ) {
	case IPPROTO_TCP:
		{
		const struct tcphdr* tp = (const struct tcphdr *) data;
		id.src_port = tp->th_sport;
		id.dst_port = tp->th_dport;
		id.is_one_way = false;
		id.proto = TRANSPORT_TCP;
		break;
		}

	case IPPROTO_UDP:
		{
		const struct udphdr* up = (const struct udphdr *) data;
		id.src_port = up->uh_sport;
		id.dst_port = up->uh_dport;
		id.is_one_way = false;
		id.proto = TRANSPORT_UDP;
		break;
		}

	case IPPROTO_ICMP:
		{
		const struct icmp* icmpp = (const struct icmp *) data;

		id.src_port = icmpp->icmp_type;
		id.dst_port = analyzer::icmp::ICMP4_counterpart(icmpp->icmp_type,
		                                                icmpp->icmp_code,
		                                                id.is_one_way);
		id.src_port = htons(id.src_port);
		id.dst_port = htons(id.dst_port);
		id.proto = TRANSPORT_ICMP;
		break;
		}

	case IPPROTO_ICMPV6:
		{
		const struct icmp* icmpp = (const struct icmp *) data;

		id.src_port = icmpp->icmp_type;
		id.dst_port = analyzer::icmp::ICMP6_counterpart(icmpp->icmp_type,
		                                                icmpp->icmp_code,
		                                                id.is_one_way);
		id.src_port = htons(id.src_port);
		id.dst_port = htons(id.dst_port);
		id.proto = TRANSPORT_ICMP;
		break;
		}

	default:
		Weird("unknown_protocol", pkt, util::fmt("%d", proto));
		return;
	}

	detail::ConnIDKey conn_key = detail::BuildConnIDKey(id);
	detail::SessionKey key(&conn_key, sizeof(conn_key), false);
	Connection* conn = nullptr;

	// FIXME: The following is getting pretty complex. Need to split up
	// into separate functions.
	auto it = session_map.find(key);
	if (it != session_map.end() )
		conn = static_cast<Connection*>(it->second);

	if ( ! conn )
		{
		conn = NewConn(conn_key, t, &id, data, proto, ip_hdr->FlowLabel(), pkt);
		if ( conn )
			InsertSession(std::move(key), conn);
		}
	else
		{
		// We already know that connection.
		if ( conn->IsReuse(t, data) )
			{
			conn->Event(connection_reused, nullptr);

			Remove(conn);
			conn = NewConn(conn_key, t, &id, data, proto, ip_hdr->FlowLabel(), pkt);
			if ( conn )
				InsertSession(std::move(key), conn);
			}
		else
			{
			conn->CheckEncapsulation(pkt->encap);
			}
		}

	if ( ! conn )
		return;

	int record_packet = 1;	// whether to record the packet at all
	int record_content = 1;	// whether to record its data

	bool is_orig = (id.src_addr == conn->OrigAddr()) &&
			(id.src_port == conn->OrigPort());

	conn->CheckFlowLabel(is_orig, ip_hdr->FlowLabel());

	ValPtr pkt_hdr_val;

	if ( ipv6_ext_headers && ip_hdr->NumHeaders() > 1 )
		{
		pkt_hdr_val = ip_hdr->ToPktHdrVal();
		conn->EnqueueEvent(ipv6_ext_headers, nullptr, conn->ConnVal(),
		                   pkt_hdr_val);
		}

	if ( new_packet )
		conn->EnqueueEvent(new_packet, nullptr, conn->ConnVal(), pkt_hdr_val ?
		                   std::move(pkt_hdr_val) : ip_hdr->ToPktHdrVal());

	conn->NextPacket(t, is_orig, ip_hdr.get(), len, remaining, data,
	                 record_packet, record_content, pkt);

	// We skip this block for reassembled packets because the pointer
	// math wouldn't work.
	if ( ! ip_hdr->reassembled && record_packet )
		{
		if ( record_content )
			pkt->dump_packet = true;	// save the whole thing

		else
			{
			int hdr_len = data - pkt->data;
			packet_mgr->DumpPacket(pkt, hdr_len);	// just save the header
			}
		}
	}

int NetSessions::ParseIPPacket(int caplen, const u_char* const pkt, int proto,
                               IP_Hdr*& inner)
	{
	if ( proto == IPPROTO_IPV6 )
		{
		if ( caplen < (int)sizeof(struct ip6_hdr) )
			return -1;

		const struct ip6_hdr* ip6 = (const struct ip6_hdr*) pkt;
		inner = new IP_Hdr(ip6, false, caplen);
		if ( ( ip6->ip6_ctlun.ip6_un2_vfc & 0xF0 ) != 0x60 )
			return -2;
		}

	else if ( proto == IPPROTO_IPV4 )
		{
		if ( caplen < (int)sizeof(struct ip) )
			return -1;

		const struct ip* ip4 = (const struct ip*) pkt;
		inner = new IP_Hdr(ip4, false);
		if ( ip4->ip_v != 4 )
			return -2;
		}

	else
		{
		reporter->InternalWarning("Bad IP protocol version in ParseIPPacket");
		return -1;
		}

	if ( (uint32_t)caplen != inner->TotalLen() )
		return (uint32_t)caplen < inner->TotalLen() ? -1 : 1;

	return 0;
	}

bool NetSessions::CheckHeaderTrunc(int proto, uint32_t len, uint32_t caplen,
                                   const Packet* p)
	{
	uint32_t min_hdr_len = 0;
	switch ( proto ) {
	case IPPROTO_TCP:
		min_hdr_len = sizeof(struct tcphdr);
		break;
	case IPPROTO_UDP:
		min_hdr_len = sizeof(struct udphdr);
		break;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
	default:
		// Use for all other packets.
		min_hdr_len = ICMP_MINLEN;
		break;
	}

	if ( len < min_hdr_len )
		{
		Weird("truncated_header", p);
		return true;
		}

	if ( caplen < min_hdr_len )
		{
		Weird("internally_truncated_header", p);
		return true;
		}

	return false;
	}

Connection* NetSessions::FindConnection(Val* v)
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

void NetSessions::Remove(Session* s)
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
			switch ( c->ConnTransport() ) {
			case TRANSPORT_TCP:
				stats.GetOrAdd({{"tcp", "num_conns"}}).Dec();
				break;
			case TRANSPORT_UDP:
				stats.GetOrAdd({{"udp", "num_conns"}}).Dec();
				break;
			case TRANSPORT_ICMP:
				stats.GetOrAdd({{"icmp", "num_conns"}}).Dec();
				break;
			case TRANSPORT_UNKNOWN: break;
			}

		s->ClearKey();
		Unref(s);
		}
	}

void NetSessions::Insert(Session* s)
	{
	assert(s->IsKeyValid());

	Session* old = nullptr;
	detail::SessionKey key = s->SessionKey(true);

	auto it = session_map.find(key);
	if ( it != session_map.end() )
		old = it->second;

	session_map.erase(key);
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

void NetSessions::Drain()
	{
	for ( const auto& entry : session_map )
		{
		Session* tc = entry.second;
		tc->Done();
		tc->RemovalEvent();
		}
	}

void NetSessions::Clear()
	{
	for ( const auto& entry : session_map )
		Unref(entry.second);

	session_map.clear();

	detail::fragment_mgr->Clear();
	}

void NetSessions::GetStats(SessionStats& s)
	{
	s.max_TCP_conns = stats.GetOrAdd({{"tcp", "max_conns"}}).Value();
	s.num_TCP_conns = stats.GetOrAdd({{"tcp", "num_conns"}}).Value();
	s.cumulative_TCP_conns = stats.GetOrAdd({{"tcp", "cumulative_conns"}}).Value();

	s.max_UDP_conns = stats.GetOrAdd({{"udp", "max_conns"}}).Value();
	s.num_UDP_conns = stats.GetOrAdd({{"udp", "num_conns"}}).Value();
	s.cumulative_UDP_conns = stats.GetOrAdd({{"udp", "cumulative_conns"}}).Value();

	s.max_ICMP_conns = stats.GetOrAdd({{"icmp", "max_conns"}}).Value();
	s.num_ICMP_conns = stats.GetOrAdd({{"icmp", "num_conns"}}).Value();
	s.cumulative_ICMP_conns = stats.GetOrAdd({{"icmp", "cumulative_conns"}}).Value();

	s.num_fragments = detail::fragment_mgr->Size();
	s.max_fragments = detail::fragment_mgr->MaxFragments();
	s.num_packets = packet_mgr->PacketsProcessed();
	}

Connection* NetSessions::NewConn(const detail::ConnIDKey& k, double t, const ConnID* id,
                                 const u_char* data, int proto, uint32_t flow_label,
                                 const Packet* pkt)
	{
	// FIXME: This should be cleaned up a bit, it's too protocol-specific.
	// But I'm not yet sure what the right abstraction for these things is.
	int src_h = ntohs(id->src_port);
	int dst_h = ntohs(id->dst_port);
	int flags = 0;

	// Hmm... This is not great.
	TransportProto tproto = TRANSPORT_UNKNOWN;
	switch ( proto ) {
		case IPPROTO_ICMP:
			tproto = TRANSPORT_ICMP;
			break;
		case IPPROTO_TCP:
			tproto = TRANSPORT_TCP;
			break;
		case IPPROTO_UDP:
			tproto = TRANSPORT_UDP;
			break;
		case IPPROTO_ICMPV6:
			tproto = TRANSPORT_ICMP;
			break;
		default:
			reporter->InternalWarning("unknown transport protocol");
			return nullptr;
	};

	if ( tproto == TRANSPORT_TCP )
		{
		const struct tcphdr* tp = (const struct tcphdr*) data;
		flags = tp->th_flags;
		}

	bool flip = false;

	if ( ! WantConnection(src_h, dst_h, tproto, flags, flip) )
		return nullptr;

	Connection* conn = new Connection(this, k, t, id, flow_label, pkt);
	conn->SetTransport(tproto);

	if ( flip )
		conn->FlipRoles();

	if ( ! analyzer_mgr->BuildInitialAnalyzerTree(conn) )
		{
		conn->Done();
		Unref(conn);
		return nullptr;
		}

	if ( new_connection )
		conn->Event(new_connection, nullptr);

	return conn;
	}

bool NetSessions::IsLikelyServerPort(uint32_t port, TransportProto proto) const
	{
	// We keep a cached in-core version of the table to speed up the lookup.
	static std::set<bro_uint_t> port_cache;
	static bool have_cache = false;

	if ( ! have_cache )
		{
		auto likely_server_ports = id::find_val<TableVal>("likely_server_ports");
		auto lv = likely_server_ports->ToPureListVal();
		for ( int i = 0; i < lv->Length(); i++ )
			port_cache.insert(lv->Idx(i)->InternalUnsigned());
		have_cache = true;
		}

	// We exploit our knowledge of PortVal's internal storage mechanism
	// here.
	if ( proto == TRANSPORT_TCP )
		port |= TCP_PORT_MASK;
	else if ( proto == TRANSPORT_UDP )
		port |= UDP_PORT_MASK;
	else if ( proto == TRANSPORT_ICMP )
		port |= ICMP_PORT_MASK;

	return port_cache.find(port) != port_cache.end();
	}

bool NetSessions::WantConnection(uint16_t src_port, uint16_t dst_port,
                                 TransportProto transport_proto,
                                 uint8_t tcp_flags, bool& flip_roles)
	{
	flip_roles = false;

	if ( transport_proto == TRANSPORT_TCP )
		{
		if ( ! (tcp_flags & TH_SYN) || (tcp_flags & TH_ACK) )
			{
			// The new connection is starting either without a SYN,
			// or with a SYN ack. This means it's a partial connection.
			if ( ! zeek::detail::partial_connection_ok )
				return false;

			if ( tcp_flags & TH_SYN && ! zeek::detail::tcp_SYN_ack_ok )
				return false;

			// Try to guess true responder by the port numbers.
			// (We might also think that for SYN acks we could
			// safely flip the roles, but that doesn't work
			// for stealth scans.)
			if ( IsLikelyServerPort(src_port, TRANSPORT_TCP) )
				{ // connection is a candidate for flipping
				if ( IsLikelyServerPort(dst_port, TRANSPORT_TCP) )
					// Hmmm, both source and destination
					// are plausible.  Heuristic: flip only
					// if (1) this isn't a SYN ACK (to avoid
					// confusing stealth scans) and
					// (2) dest port > src port (to favor
					// more plausible servers).
					flip_roles = ! (tcp_flags & TH_SYN) && src_port < dst_port;
				else
					// Source is plausible, destination isn't.
					flip_roles = true;
				}
			}
		}

	else if ( transport_proto == TRANSPORT_UDP )
		flip_roles =
			IsLikelyServerPort(src_port, TRANSPORT_UDP) &&
			! IsLikelyServerPort(dst_port, TRANSPORT_UDP);

	return true;
	}

void NetSessions::Weird(const char* name, const Packet* pkt, const char* addl, const char* source)
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

void NetSessions::Weird(const char* name, const IP_Hdr* ip, const char* addl)
	{
	reporter->Weird(ip->SrcAddr(), ip->DstAddr(), name, addl);
	}

unsigned int NetSessions::ConnectionMemoryUsage()
	{
	unsigned int mem = 0;

	if ( run_state::terminating )
		// Connections have been flushed already.
		return 0;

	for ( const auto& entry : session_map )
		mem += entry.second->MemoryAllocation();

	return mem;
	}

unsigned int NetSessions::ConnectionMemoryUsageConnVals()
	{
	unsigned int mem = 0;

	if ( run_state::terminating )
		// Connections have been flushed already.
		return 0;

	for ( const auto& entry : session_map )
		mem += entry.second->MemoryAllocationConnVal();

	return mem;
	}

unsigned int NetSessions::MemoryAllocation()
	{
	if ( run_state::terminating )
		// Connections have been flushed already.
		return 0;

	return ConnectionMemoryUsage()
		+ padded_sizeof(*this)
		+ (session_map.size() * (sizeof(SessionMap::key_type) + sizeof(SessionMap::value_type)))
		+ detail::fragment_mgr->MemoryAllocation();
		// FIXME: MemoryAllocation() not implemented for rest.
		;
	}

void NetSessions::InsertSession(detail::SessionKey key, Session* session)
	{
	key.CopyData();
	session_map.insert_or_assign(std::move(key), session);

	std::string protocol;
	switch ( static_cast<Connection*>(session)->ConnTransport() )
		{
		case TRANSPORT_TCP:
			protocol = "tcp";
			break;
		case TRANSPORT_UDP:
			protocol = "udp";
			break;
		case TRANSPORT_ICMP:
			protocol = "icmp";
			break;
		default:
			break;
		}

	if ( ! protocol.empty() )
		{
		auto max = stats.GetOrAdd({{protocol, "max_conns"}});
		auto num = stats.GetOrAdd({{protocol, "num_conns"}});
		num.Inc();

		stats.GetOrAdd({{protocol, "cumulative_conns"}}).Inc();
		if ( num.Value() > max.Value() )
			max.Inc();
		}
	}

detail::PacketFilter* NetSessions::GetPacketFilter(bool init)
	{
	return packet_mgr->GetPacketFilter(init);
	}

} // namespace zeek
