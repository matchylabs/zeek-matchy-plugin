# @TEST-DOC: Test MatchyIntel framework seen() function

# @TEST-EXEC: zeek %INPUT >out 2>&1
# @TEST-EXEC: btest-diff out

@load intel

redef MatchyIntel::db_path = getenv("TEST_FILES") + "/test.mxy";

global match_count = 0;

event MatchyIntel::match(s: MatchyIntel::Seen, metadata: string)
	{
	++match_count;
	print fmt("MATCH %d: %s (%s)", match_count, s$indicator, s$indicator_type);
	}

event zeek_init() &priority=-10
	{
	print "Testing MatchyIntel::seen()...";

	# IP lookup
	MatchyIntel::seen(MatchyIntel::Seen($host=1.2.3.4,
	                                    $where=MatchyIntel::IN_ANYWHERE));

	# Domain glob lookup
	MatchyIntel::seen(MatchyIntel::Seen($indicator="foo.evil.com",
	                                    $indicator_type=MatchyIntel::DOMAIN,
	                                    $where=MatchyIntel::IN_ANYWHERE));

	# Exact domain lookup
	MatchyIntel::seen(MatchyIntel::Seen($indicator="malware.example.com",
	                                    $indicator_type=MatchyIntel::DOMAIN,
	                                    $where=MatchyIntel::IN_ANYWHERE));

	# CIDR lookup
	MatchyIntel::seen(MatchyIntel::Seen($host=10.5.6.7,
	                                    $where=MatchyIntel::IN_ANYWHERE));

	# Non-matching lookup (should not trigger match event)
	MatchyIntel::seen(MatchyIntel::Seen($indicator="safe.example.org",
	                                    $indicator_type=MatchyIntel::DOMAIN,
	                                    $where=MatchyIntel::IN_ANYWHERE));
	}

event zeek_done()
	{
	print fmt("Total matches: %d (expected 4)", match_count);
	}
