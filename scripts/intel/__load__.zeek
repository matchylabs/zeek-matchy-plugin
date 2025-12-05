##! MatchyIntel framework - high-performance intelligence matching.
##!
##! To use:
##!   1. Set MatchyIntel::db_path to your .mxy database file
##!   2. @load Matchy/DB/intel (this script)
##!
##! Example:
##!   redef MatchyIntel::db_path = "/etc/zeek/threat-intel.mxy";
##!   @load Matchy/DB/intel

@load ./main
@load ./seen
