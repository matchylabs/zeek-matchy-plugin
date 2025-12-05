##! MatchyIntel - High-performance intelligence matching using Matchy databases
##!
##! This framework provides Intel-framework-like functionality using Matchy's
##! high-performance matching engine. It observes network data and checks it
##! against a Matchy database (.mxy file), generating match events and logs.
##!
##! Key differences from Zeek's Intel framework:
##!   - Data is managed externally (build .mxy files, Matchy autoreloads)
##!   - No insert/remove functions - all data management is external
##!   - Metadata is a JSON blob (flexible schema)
##!   - Single database model (for now)

@load base/frameworks/notice

module MatchyIntel;

export {
	redef enum Log::ID += { LOG };

	global log_policy: Log::PolicyHook;

	## Path to the Matchy intelligence database (.mxy file).
	## The database will be loaded at zeek_init and automatically
	## reloaded when the file is atomically replaced.
	option db_path = "" &redef;

	## Enum type to represent various types of intelligence data.
	## Used for logging and policy decisions.
	type Type: enum {
		## An IP address.
		ADDR,
		## A subnet in CIDR notation.
		SUBNET,
		## A complete URL.
		URL,
		## A DNS domain name.
		DOMAIN,
		## Email address.
		EMAIL,
		## A user name.
		USER_NAME,
		## File hash (MD5, SHA1, SHA256).
		FILE_HASH,
		## File name.
		FILE_NAME,
		## Certificate hash.
		CERT_HASH,
		## Software name/version.
		SOFTWARE,
		## Generic string indicator.
		STRING,
	};

	## Enum to represent where data came from when it was discovered.
	## Extended by seen/*.zeek scripts.
	type Where: enum {
		## A catchall value to represent data of unknown provenance.
		IN_ANYWHERE,
	};

	## Information about a piece of "seen" data.
	type Seen: record {
		## The string indicator (domain, URL, hash, etc.)
		indicator:       string        &log &optional;

		## The type of data that the indicator represents.
		indicator_type:  Type          &log &optional;

		## If the indicator type was ADDR, the IP address.
		host:            addr          &optional;

		## Where the data was discovered.
		where:           Where         &log;

		## The name of the node where the match was discovered.
		node:            string        &optional &log;

		## If the data was discovered within a connection, the
		## connection record should go here to give context.
		conn:            connection    &optional;

		## If the data was discovered within a connection, the
		## connection uid should go here. If conn is provided,
		## this will be automatically filled out.
		uid:             string        &optional;
	};

	## Record used for the logging framework representing a positive
	## hit within the intelligence framework.
	type Info: record {
		## Timestamp when the data was discovered.
		ts:           time           &log;

		## If a connection was associated with this intelligence hit,
		## this is the uid for the connection.
		uid:          string         &log &optional;

		## If a connection was associated with this intelligence hit,
		## this is the conn_id for the connection.
		id:           conn_id        &log &optional;

		## Where the data was seen.
		seen:         Seen           &log;

		## The indicator type that matched.
		matched_type: Type           &log &optional;

		## JSON metadata from the Matchy database.
		## This contains whatever fields were in the source data.
		metadata:     string         &log &optional;
	};

	## Function to declare discovery of a piece of data in order to check
	## it against the Matchy intelligence database.
	global seen: function(s: Seen);

	## Event to represent a match in the intelligence data.
	## This is the primary mechanism where a user may take actions based on
	## intelligence matches.
	##
	## s: Information about what was seen.
	## metadata: JSON string containing match metadata from the database.
	global match: event(s: Seen, metadata: string);

	## Hook to filter/suppress matches before the match event fires.
	## Break from this hook to suppress the match.
	##
	## s: The Seen instance.
	## found: T if a match was found, F otherwise.
	global seen_policy: hook(s: Seen, found: bool);

	## Hook to modify match info before logging.
	## Break from this hook to suppress logging (match event still fires).
	##
	## info: The Info record that will be logged.
	## s: Information about the data seen.
	## metadata: JSON metadata from the database.
	global extend_match: hook(info: Info, s: Seen, metadata: string);

	global log_matchy_intel: event(rec: Info);
}

# The database handle - initialized at zeek_init
# Note: We use a wrapper record since globals can't be &optional
type DBWrapper: record {
	handle: opaque of MatchyDB &optional;
};
global intel_db_wrapper: DBWrapper = DBWrapper();

# Track if database is loaded
global db_loaded = F;

# Track if we've warned about missing database
global warned_no_db = F;

# Internal function to load/reload the database
function load_intel_db(path: string): bool
	{
	if ( path == "" )
		{
		# Empty path means unload
		if ( intel_db_wrapper?$handle )
			{
			# Assigning a new empty record will drop the reference to the old handle,
			# triggering cleanup via Zeek's garbage collection
			intel_db_wrapper = DBWrapper();
			}
		db_loaded = F;
		return T;
		}

	# Load new database into a temporary wrapper to check validity
	local temp_wrapper: DBWrapper = DBWrapper();
	temp_wrapper$handle = Matchy::load_database(path);

	if ( ! temp_wrapper?$handle || ! Matchy::is_valid(temp_wrapper$handle) )
		{
		Reporter::warning(fmt("MatchyIntel: Failed to load database: %s", path));
		return F;
		}

	# Success - replace the old wrapper (old handle will be garbage collected)
	intel_db_wrapper = temp_wrapper;
	db_loaded = T;
	warned_no_db = F;  # Reset warning flag since we now have a database
	return T;
	}

# Handler called when db_path option is changed at runtime
function db_path_change_handler(ID: string, new_path: string): string
	{
	if ( load_intel_db(new_path) )
		return new_path;  # Accept the new value
	else
		return db_path;   # Reject - keep old value
	}

event zeek_init() &priority=5
	{
	Log::create_stream(LOG, [$columns=Info, $ev=log_matchy_intel, $path="matchy_intel", $policy=log_policy]);

	# Register the change handler for db_path option
	Option::set_change_handler("MatchyIntel::db_path", db_path_change_handler);

	# Load initial database if path is set
	if ( db_path != "" )
		load_intel_db(db_path);
	}

function seen(s: Seen)
	{
	# Check if database is loaded
	if ( ! db_loaded )
		{
		if ( ! warned_no_db && db_path == "" )
			{
			Reporter::warning("MatchyIntel: No database configured. Set MatchyIntel::db_path option.");
			warned_no_db = T;
			}
		return;
		}

	local result = "";

	# Query by IP or string
	if ( s?$host )
		{
		result = Matchy::query_ip(intel_db_wrapper$handle, s$host);
		if ( ! s?$indicator )
			s$indicator = fmt("%s", s$host);
		if ( ! s?$indicator_type )
			s$indicator_type = ADDR;
		}
	else if ( s?$indicator )
		{
		result = Matchy::query_string(intel_db_wrapper$handle, s$indicator);
		}
	else
		{
		Reporter::warning("MatchyIntel::seen called with no host or indicator");
		return;
		}

	local found = (|result| > 0);

	# Allow policy to filter
	if ( ! hook seen_policy(s, found) )
		return;

	if ( ! found )
		return;

	# Fill in node if not set
	if ( ! s?$node )
		s$node = peer_description;

	# Fire match event
	event MatchyIntel::match(s, result);
	}

event MatchyIntel::match(s: Seen, metadata: string) &priority=5
	{
	local info = Info($ts=network_time(), $seen=s);

	if ( s?$indicator_type )
		info$matched_type = s$indicator_type;

	info$metadata = metadata;

	if ( hook extend_match(info, s, metadata) )
		Log::write(MatchyIntel::LOG, info);
	}

hook extend_match(info: Info, s: Seen, metadata: string) &priority=5
	{
	# Add connection context if available
	if ( s?$conn )
		{
		s$uid = s$conn$uid;
		info$id = s$conn$id;
		}

	if ( s?$uid )
		info$uid = s$uid;
	}
