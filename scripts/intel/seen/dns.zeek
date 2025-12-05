##! Observe DNS request queries.

@load ../main
@load ./where-locations

module MatchyIntel;

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
	{
	MatchyIntel::seen(MatchyIntel::Seen($indicator=query,
	                                    $indicator_type=DOMAIN,
	                                    $conn=c,
	                                    $where=DNS::IN_REQUEST));
	}
