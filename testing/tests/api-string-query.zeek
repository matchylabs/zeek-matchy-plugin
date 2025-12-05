# @TEST-DOC: Test string and pattern queries

# @TEST-EXEC: zeek %INPUT >out 2>&1
# @TEST-EXEC: btest-diff out

event zeek_init()
	{
	local db = Matchy::load_database(getenv("TEST_FILES") + "/test.mxy");

	if ( ! Matchy::is_valid(db) )
		{
		print "FAIL: Could not load database";
		return;
		}

	# Test exact string match
	local r1 = Matchy::query_string(db, "malware.example.com");
	if ( r1 != "" )
		print "malware.example.com: MATCH";
	else
		print "malware.example.com: NO MATCH (unexpected)";

	# Test glob pattern match (foo.evil.com should match *.evil.com)
	local r2 = Matchy::query_string(db, "foo.evil.com");
	if ( r2 != "" )
		print "foo.evil.com: MATCH (glob)";
	else
		print "foo.evil.com: NO MATCH (unexpected)";

	# Test no match
	local r3 = Matchy::query_string(db, "safe.example.org");
	if ( r3 == "" )
		print "safe.example.org: NO MATCH (expected)";
	else
		print "safe.example.org: MATCH (unexpected)";
	}
