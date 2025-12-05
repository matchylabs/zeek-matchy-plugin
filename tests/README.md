# Zeek Matchy Plugin Tests

## Running Tests (btest)

The primary test suite uses btest and is located in `../testing/`:

```bash
cd testing
btest        # Run all tests
btest -d     # Run with diagnostics on failure
btest -U     # Update baselines
```

## Manual Tests

This directory contains manual test scripts for quick verification:

```bash
cd tests
ZEEK_PLUGIN_PATH=../build zeek simple-test.zeek
```

## Building Test Database

The test database is pre-built, but you can rebuild it:

```bash
matchy build test-data.csv -o test.mxy --format csv
```

## Test Data

`test-data.csv` contains:

| Type | Entry | Data |
|------|-------|------|
| IP | 1.2.3.4 | threat_level=high, category=malware |
| CIDR | 10.0.0.0/8 | threat_level=low, category=internal |
| CIDR | 192.168.1.0/24 | threat_level=medium, category=suspicious |
| Pattern | *.evil.com | threat_level=critical, category=phishing |
| String | malware.example.com | threat_level=high, category=malware |
| String | test.local | threat_level=low, category=test |

## Expected Results

All queries should return JSON objects with the associated metadata:

```json
{"category":"malware","threat_level":"high","description":"Known C2 server"}
```

Non-matching queries return empty strings `""`.
