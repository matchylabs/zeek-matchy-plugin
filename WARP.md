# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

Zeek Matchy Plugin - A Zeek plugin for high-performance IP address and string pattern matching using Matchy databases (written in Rust). Provides BiF (Built-in Function) implementations for loading `.mxy` databases and querying them from Zeek scripts.

**Core components:**
- `src/Plugin.{h,cc}` - Zeek plugin registration, opaque type (MatchyDB) definition
- `src/matchy.bif` - Built-in Function definitions that bridge Zeek and Matchy C API
- `scripts/main.zeek` - Low-level BiF documentation
- `scripts/intel/` - MatchyIntel framework (Intel Framework replacement)
  - `main.zeek` - Core types, seen() function, match event, logging
  - `seen/*.zeek` - Observation scripts for DNS, HTTP, SSL, connections

## Build System

### Prerequisites
- Zeek 5.0+ installed with `zeek-config` in PATH
- Matchy library built with `--features capi` (produces `libmatchy.{a,dylib,so}` and `include/matchy/matchy.h`)
- CMake 3.15+
- C++17 compiler
- Rust 1.70+ (for building Matchy dependency)

### Build Commands

**Configure:**
```bash
# With MATCHY_ROOT (most common during development):
MATCHY_ROOT=/path/to/matchy cmake -DCMAKE_MODULE_PATH=$(zeek-config --cmake_dir) ..

# If Matchy is installed system-wide:
cmake -DCMAKE_MODULE_PATH=$(zeek-config --cmake_dir) ..
```

**Build:**
```bash
make
```

**Install (optional):**
```bash
sudo make install
```

### Build Output
- Plugin shared library: `build/lib/Matchy-DB.*.so` (or `.dylib` on macOS)
- Generated BiF C++ code: `build/matchy.bif.{cc,h,init.cc,register.cc}`
- Distribution tarball: `build/Matchy_DB.tgz`

## Testing

**Run basic tests:**
```bash
cd tests
ZEEK_PLUGIN_PATH=../build zeek simple-test.zeek
```

**Run comprehensive tests:**
```bash
cd tests
ZEEK_PLUGIN_PATH=../build zeek basic-test.zeek
```

**Expected output:** All tests should print "PASS"

**Test database location:** `tests/test.mxy` (pre-built)

**Rebuild test database:**
```bash
cd tests
matchy build test-data.csv -o test.mxy --format csv
```

### Running Zeek with plugin (without install)
```bash
export ZEEK_PLUGIN_PATH=/path/to/zeek-matchy-plugin/build
zeek -N Matchy::DB  # Verify plugin loads
zeek your-script.zeek
```

## Architecture

### Plugin Registration Flow
1. `Plugin::Configure()` (Plugin.cc) - Registers plugin with Zeek as "Matchy::DB"
2. CMake's `zeek_plugin_bif()` processes `matchy.bif` to generate C++ glue code
3. Generated code registers BiFs in the `Matchy::` namespace

### BiF Implementation Pattern
Each BiF in `matchy.bif` follows this structure:
```cpp
function bif_name%(args%): return_type
%{
    // C++ implementation accessing Matchy C API
    // Error handling via zeek::reporter->Warning()
    // Returns via zeek::val_mgr or zeek::make_intrusive<>
%}
```

### Database Lifecycle
1. **Load:** `Matchy::load_database()` calls `matchy_open()` → returns opaque MatchyDB handle
2. **Query:** `Matchy::query_ip()` / `query_string()` → JSON result string
3. **Cleanup:** Automatic via Zeek's garbage collection when handle goes out of scope

### Memory Management
- Opaque MatchyDB type wraps `matchy_t*` pointer
- Destructor (`~MatchyDB()`) calls `matchy_close()` automatically
- Matchy results: BiF code calls `matchy_free_result()` and `matchy_free_string()` before returning
- Zeek values: Use `zeek::make_intrusive<>` for ref-counted types

## Common Development Tasks

### Adding a new BiF
1. Add function declaration in `src/matchy.bif` with `%%{ implementation }%%`
2. Follow existing patterns for error handling and memory management
3. Rebuild: `cd build && make`
4. Test: `cd tests && ZEEK_PLUGIN_PATH=../build zeek your-test.zeek`

### Troubleshooting Build Issues
- **"Matchy library not found":** Ensure `MATCHY_ROOT` is set and Matchy was built with `--features capi`
- **"ZeekPlugin.cmake not found":** Use `cmake -DCMAKE_MODULE_PATH=$(zeek-config --cmake_dir) ..`
- **Runtime library loading (macOS):** `export DYLD_LIBRARY_PATH=$MATCHY_ROOT/target/release:$DYLD_LIBRARY_PATH`

### Plugin Not Found at Runtime
```bash
export ZEEK_PLUGIN_PATH=/path/to/zeek-matchy-plugin/build
zeek -N Matchy::DB  # Should show: "Matchy::DB - Fast IP and pattern matching..."
```

## API Functions (BiFs)

All functions are in the `Matchy::` namespace:

- `load_database(filename: string): opaque of MatchyDB` - Load `.mxy` database, returns handle
- `is_valid(db: opaque of MatchyDB): bool` - Check if handle is valid
- `query_ip(db: opaque of MatchyDB, ip: addr): string` - Query by IP, returns JSON or ""
- `query_string(db: opaque of MatchyDB, query: string): string` - Query by string/pattern, returns JSON or ""

**Return value conventions:**
- `load_database`: Returns opaque handle or nullptr on failure
- `is_valid`: `zeek::val_mgr->True()` / `zeek::val_mgr->False()`
- Query functions: JSON string on match, empty string on no-match/error

## MatchyIntel Framework

High-level Intel Framework replacement in `scripts/intel/`:

- `MatchyIntel::db_path` option - Path to database (supports runtime changes)
- `MatchyIntel::seen(s: Seen)` - Check indicator against database
- `MatchyIntel::match` event - Fires on hits with JSON metadata
- `MatchyIntel::seen_policy` hook - Filter/suppress matches
- `MatchyIntel::extend_match` hook - Customize logging

**Observation scripts** automatically check:
- Connection IPs (`conn.zeek`)
- DNS queries (`dns.zeek`)
- HTTP URLs and Host headers (`http.zeek`)
- SSL/TLS SNI and certificate CNs (`ssl.zeek`)

## Dependencies

**External:**
- Matchy library (Rust crate with C API) - https://github.com/sethhall/matchy
- Zeek 5.0+ development headers

**Matchy C API usage:**
- `matchy_open()` / `matchy_close()`
- `matchy_query()` - Returns `matchy_result_t`
- `matchy_result_to_json()` - Converts result to JSON string
- `matchy_free_result()` / `matchy_free_string()` - Memory cleanup

## Zeek Integration Notes

**Plugin discovery:** Zeek finds plugins via `ZEEK_PLUGIN_PATH` or installed plugin directories

**Script loading:** The plugin automatically makes BiFs available; user scripts just call `Matchy::function_name()`

**No explicit @load required** for BiFs (unlike pure Zeek modules), but users can `@load Matchy/DB` for clarity

**Performance characteristics:**
- Database loading: <1ms (memory-mapped)
- IP queries: 7M+/sec
- Pattern queries: 3M+/sec
- No need to reload databases across runs (persistent mmap)
