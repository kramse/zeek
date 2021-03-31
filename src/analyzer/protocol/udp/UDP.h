// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

// This will include netinet/udp.h for us, plus set up some defines that make it work on all
// of the CI platforms.
#include "zeek/net_util.h"

#include "zeek/analyzer/Analyzer.h"

namespace zeek::analyzer::udp {

class UDP_Analyzer final : public analyzer::TransportLayerAnalyzer {
public:
	explicit UDP_Analyzer(Connection* conn);
	~UDP_Analyzer() override;

	void UpdateConnVal(RecordVal *conn_val) override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new UDP_Analyzer(conn); }

protected:

	void DeliverPacket(int len, const u_char* data, bool orig,
	                   uint64_t seq, const IP_Hdr* ip, int caplen) override;
	bool IsReuse(double t, const u_char* pkt) override;
	unsigned int MemoryAllocation() const override;

	void ChecksumEvent(bool is_orig, uint32_t threshold);

	// Returns true if the checksum is valid, false if not
	static bool ValidateChecksum(const IP_Hdr* ip, const struct udphdr* up,
	                             int len);

	bro_int_t request_len, reply_len;

private:
	void UpdateEndpointVal(RecordVal* endp, bool is_orig);

	// For tracking checksum history.
	uint32_t req_chk_cnt, req_chk_thresh;
	uint32_t rep_chk_cnt, rep_chk_thresh;
};

} // namespace zeek::analyzer::udp
