##! Observe SSL/TLS Server Name Indication and certificate common names.

@load ../main
@load ./where-locations
@load base/protocols/ssl

module MatchyIntel;

event ssl_extension_server_name(c: connection, is_orig: bool, names: string_vec)
	{
	if ( is_orig && c?$ssl && c$ssl?$server_name )
		MatchyIntel::seen(MatchyIntel::Seen($indicator=c$ssl$server_name,
		                                    $indicator_type=DOMAIN,
		                                    $conn=c,
		                                    $where=SSL::IN_SERVER_NAME));
	}

event ssl_established(c: connection)
	{
	if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 ||
	     ! c$ssl$cert_chain[0]?$x509 )
		return;

	if ( c$ssl$cert_chain[0]$x509?$certificate &&
	     c$ssl$cert_chain[0]$x509$certificate?$cn )
		MatchyIntel::seen(MatchyIntel::Seen($indicator=c$ssl$cert_chain[0]$x509$certificate$cn,
		                                    $indicator_type=DOMAIN,
		                                    $conn=c,
		                                    $where=X509::IN_CERT));
	}
