##! Observe connection endpoint IP addresses.

@load ../main
@load ./where-locations

module MatchyIntel;

event connection_established(c: connection)
	{
	if ( c$orig$state == TCP_ESTABLISHED &&
	     c$resp$state == TCP_ESTABLISHED )
		{
		MatchyIntel::seen(MatchyIntel::Seen($host=c$id$orig_h,
		                                    $conn=c,
		                                    $where=Conn::IN_ORIG));
		MatchyIntel::seen(MatchyIntel::Seen($host=c$id$resp_h,
		                                    $conn=c,
		                                    $where=Conn::IN_RESP));
		}
	}
