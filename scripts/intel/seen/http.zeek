##! Observe HTTP URLs and Host headers.

@load ../main
@load ./where-locations
@load base/protocols/http/utils

module MatchyIntel;

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
	{
	if ( is_orig && c?$http )
		{
		# Check full URL
		MatchyIntel::seen(MatchyIntel::Seen($indicator=HTTP::build_url(c$http),
		                                    $indicator_type=URL,
		                                    $conn=c,
		                                    $where=HTTP::IN_URL));

		# Also check just the Host header as a domain
		if ( c$http?$host )
			MatchyIntel::seen(MatchyIntel::Seen($indicator=c$http$host,
			                                    $indicator_type=DOMAIN,
			                                    $conn=c,
			                                    $where=HTTP::IN_HOST_HEADER));
		}
	}
