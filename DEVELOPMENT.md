# Development Guide

This document provides information for developers and AI agents continuing development of got-audit.

## Project Overview

**got-audit** is a machine-generated C++ port of the `got-audit` command from GEF (GDB Enhanced Features). It audits the Global Offset Table (GOT) of running Linux processes to detect security issues.

**Key fact:** This is a port, not an original implementation. The core algorithm and expected behavior come from GEF's GotAuditCommand.

## Architecture

### Module Breakdown

```
got-audit/
├── src/
│   ├── main.cpp              # Entry point, CLI parsing, orchestration
│   ├── elf_parser.cpp        # ELF file parsing using libelf
│   ├── process_memory.cpp    # Process attachment and memory reading
│   ├── got_auditor.cpp       # Core audit logic and duplicate detection
│   └── report.cpp            # Output formatting and display
├── include/
│   ├── elf_parser.h
│   ├── process_memory.h
│   ├── got_auditor.h
│   └── report.h
└── tests/
    ├── run_tests.sh          # Test suite
    └── test_program.c        # Simple test target
```

### Data Flow

1. **Attach** (process_memory.cpp)
   - `ptrace(PTRACE_ATTACH)` to target PID
   - Parse `/proc/<PID>/maps` for memory layout
   
2. **Index Symbols** (got_auditor.cpp)
   - For each loaded library, parse with ELF parser
   - Extract exported symbols (defined, not undefined)
   - Build `symbols_to_paths_` and `paths_to_symbols_` maps

3. **Audit GOT** (got_auditor.cpp, elf_parser.cpp)
   - Parse JUMP_SLOT relocations from ELF file
   - For each GOT entry:
     - Read actual value from process memory
     - Determine which library it points to
     - Check for duplicate symbols
     - Check if symbol is actually exported by target library

4. **Report** (report.cpp)
   - Format output with colors
   - Display warnings for issues

### Key Classes

**ElfParser** (`elf_parser.cpp`)
- Wraps libelf for ELF file parsing
- Extracts JUMP_SLOT relocations (GOT entries)
- Extracts dynamic symbols that are DEFINED (not undefined)
- Determines PIE/RelRO status

**ProcessMemory** (`process_memory.cpp`)
- Manages ptrace attachment lifecycle
- Parses `/proc/<PID>/maps`
- Reads process memory via `process_vm_readv()`

**GotAuditor** (`got_auditor.cpp`)
- Coordinates the audit process
- Builds symbol index from all loaded libraries
- Implements duplicate detection logic
- Generates warnings

**Report** (`report.cpp`)
- ANSI color codes for output
- Formats the audit results

### Critical Implementation Details

#### Duplicate Symbol Detection

The logic for "acceptable duplicates" is nuanced:

```cpp
bool only_in_main = (paths.size() == 2 &&
    (std::find(paths.begin(), paths.end(), main_executable_path_) != paths.end()));
```

This means: "If a symbol is defined in exactly two places, and one of them is the main executable, don't warn."

Rationale: Main executables may redefine symbols from libraries for their own use.

#### Known Duplicate Symbols

`GotAuditor::expected_duplicates_` contains symbols that are legitimately exported by multiple libraries (e.g., math functions in both libc and libm). These never generate warnings.

#### Symbol Filtering

**Critical:** When building the symbol index, we MUST filter out undefined symbols:

```cpp
if (sym.st_shndx == SHN_UNDEF) {
    continue;  // Skip undefined/imported symbols
}
```

Otherwise, we get false positives where a library importing `dlopen` looks like it exports `dlopen`.

## Development Environment

### Prerequisites

See [README.md](README.md#requirements) for dependency installation.

### Building

See [README.md](README.md#building) for standard build instructions.

For development builds with debug symbols:
```bash
cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
```

### Testing

```bash
# Run full test suite
cd tests
./run_tests.sh

# Manual testing
sudo ./build/got-audit <PID>
sudo ./build/got-audit --all <PID>

# Compare with original GEF
gdb -p <PID>
(gdb) source /path/to/gef.py
(gdb) got-audit
```

### Debugging

```bash
# Build with debug symbols
cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
make

# Run under GDB
sudo gdb --args ./got-audit <PID>

# Memory leak detection
sudo valgrind --leak-check=full ./got-audit <PID>
```

## Code Style

See [CONTRIBUTING.md](CONTRIBUTING.md#code-style-guidelines) for detailed style guidelines with examples.

## Common Development Tasks

### Adding a New Command-Line Option

1. Add to `long_options[]` in `main.cpp`
2. Add case to `getopt_long()` switch statement
3. Update `print_usage()` function
4. Update man page `got-audit.1`
5. Add test in `tests/run_tests.sh`

### Adding a New Warning Type

1. Generate warning string in `GotAuditor::check_for_warnings()`
2. Add to `entry.warnings` vector
3. Update documentation in README.md
4. Add test case

### Supporting a New Architecture

1. Update `parse_relocations()` in `elf_parser.cpp`:
   ```cpp
   if (ehdr.e_machine == EM_NEWARCH && type == NEWARCH_JUMP_SLOT) {
       is_jump_slot = true;
   }
   ```
2. Test on target architecture
3. Update README.md limitations section
4. Add to CI matrix in `.github/workflows/ci.yml`

## Reference Materials

### Original GEF Implementation

Location: https://github.com/hugsy/gef and https://github.com/hugsy/gef-extras/

Key classes:
- `GotCommand`: Base implementation
- `GotAuditCommand`: Audit-specific logic

### libelf Documentation

- API reference: `man elf`
- Tutorial: https://sourceware.org/elfutils/Libelf-Tutorial.html
- Key functions:
  - `elf_begin()` - Open ELF file
  - `gelf_getehdr()` - Get ELF header
  - `elf_nextscn()` - Iterate sections
  - `gelf_getsym()` - Get symbol entry

### ptrace Documentation

- API reference: `man 2 ptrace`
- Key operations:
  - `PTRACE_ATTACH` - Attach to process
  - `PTRACE_DETACH` - Detach from process
- Modern alternative: `process_vm_readv()` for memory reads

## Known Issues and Limitations

1. **Requires root** - ptrace requires CAP_SYS_PTRACE capability
2. **Process pause** - Target process stops while we're attached
3. **SELinux/AppArmor** - May block ptrace even with root
4. **Container processes** - May need to enter namespace first
5. **No core dump support** - Only live processes

## Testing Strategy

### Unit Testing
Currently minimal - most testing is integration testing via `run_tests.sh`.

Future: Consider adding unit tests for:
- ElfParser symbol extraction
- Duplicate detection logic
- Memory map parsing

### Integration Testing
`tests/run_tests.sh` covers:
- Binary execution
- Command-line arguments
- Output validation
- No false positives

### Manual Testing
Always test against:
- Simple programs (test_program.c)
- Complex programs (bash, haproxy)
- Both with and without --all flag

## Continuous Integration

See `.github/workflows/ci.yml` for:
- Multi-platform builds (Ubuntu, Fedora)
- Multi-compiler testing (GCC, Clang)
- Static analysis (cppcheck, clang-tidy)
- Documentation validation

## Release Process

1. Update version in:
   - `src/main.cpp` (`print_version()`)
   - `got-audit.spec` (Version and changelog)

2. Tag release:
   ```bash
   git tag -a v1.x.x -m "Release v1.x.x"
   ```

3. Build artifacts:
   ```bash
   make -C build
   rpmbuild -ba got-audit.spec
   ```

## Contributing Guidelines

See CONTRIBUTING.md for:
- Code review process
- Commit message format
- Branch naming conventions
- Testing requirements

## Questions or Issues?

For understanding the original behavior, consult:
1. GEF source code (`gef/gef.py`)
2. GEF documentation (https://github.com/hugsy/gef)
3. Git history (`git log` for rationale behind changes)
