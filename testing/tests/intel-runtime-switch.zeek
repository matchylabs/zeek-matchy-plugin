# @TEST-DOC: Test runtime database switching via Config::set_value

# @TEST-EXEC: zeek %INPUT 2>&1 | grep -v 'scripts/intel/main.zeek' >out
# @TEST-EXEC: btest-diff out

@load intel

redef MatchyIntel::db_path = getenv("TEST_FILES") + "/test.mxy";
redef exit_only_after_terminate = T;

global match_count = 0;
global expected_matches = 3;
global phase = 1;

event MatchyIntel::match(s: MatchyIntel::Seen, metadata: string)
	{
	++match_count;
	print fmt("MATCH %d: %s", match_count, s$indicator);

	if ( match_count == expected_matches )
		terminate();
	}

event zeek_init() &priority=-10
	{
	# Phase 1: Initial database should be loaded
	print "Phase 1: Query with initial database";
	MatchyIntel::seen(MatchyIntel::Seen($host=1.2.3.4,
	                                    $where=MatchyIntel::IN_ANYWHERE));

	# Phase 2: Unload database
	print "Phase 2: Unload database (empty path)";
	Config::set_value("MatchyIntel::db_path", "");
	# This should NOT produce a match
	MatchyIntel::seen(MatchyIntel::Seen($host=1.2.3.4,
	                                    $where=MatchyIntel::IN_ANYWHERE));

	# Phase 3: Reload database
	print "Phase 3: Reload database";
	Config::set_value("MatchyIntel::db_path", getenv("TEST_FILES") + "/test.mxy");
	MatchyIntel::seen(MatchyIntel::Seen($indicator="malware.example.com",
	                                    $indicator_type=MatchyIntel::DOMAIN,
	                                    $where=MatchyIntel::IN_ANYWHERE));

	# Phase 4: Invalid path should be rejected, keeping current DB
	print "Phase 4: Invalid path (should be rejected, DB stays loaded)";
	Config::set_value("MatchyIntel::db_path", "/nonexistent/path.mxy");
	MatchyIntel::seen(MatchyIntel::Seen($indicator="foo.evil.com",
	                                    $indicator_type=MatchyIntel::DOMAIN,
	                                    $where=MatchyIntel::IN_ANYWHERE));
	}

event zeek_done()
	{
	print fmt("Total matches: %d (expected %d)", match_count, expected_matches);
	}
