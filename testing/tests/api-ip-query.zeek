# @TEST-DOC: Test loading database and querying IPs

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

	print "Database loaded";

	# Test exact IP match
	local r1 = Matchy::query_ip(db, 1.2.3.4);
	if ( r1 != "" )
		print fmt("1.2.3.4: MATCH");
	else
		print "1.2.3.4: NO MATCH (unexpected)";

	# Test CIDR match (10.5.6.7 should match 10.0.0.0/8)
	local r2 = Matchy::query_ip(db, 10.5.6.7);
	if ( r2 != "" )
		print fmt("10.5.6.7: MATCH (CIDR)");
	else
		print "10.5.6.7: NO MATCH (unexpected)";

	# Test no match
	local r3 = Matchy::query_ip(db, 8.8.8.8);
	if ( r3 == "" )
		print "8.8.8.8: NO MATCH (expected)";
	else
		print "8.8.8.8: MATCH (unexpected)";
	}
