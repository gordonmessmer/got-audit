# GOT Audit Tool

A C++ port of the GEF `got-audit` command that audits the Global Offset Table (GOT) of running Linux processes to detect potential security issues.

## Overview

This tool attaches to a running process and examines its Global Offset Table to identify:
- Symbols resolving to unexpected memory regions
- Duplicate symbol definitions across libraries
- Symbols not exported by the target library
- GOT protection status (Full RelRO, Partial RelRO, or No RelRO)

This can help detect namespace tampering, symbol hijacking, and other security vulnerabilities.

## Features

- **Process Attachment**: Uses `ptrace` to attach to running processes
- **ELF Parsing**: Parses ELF files using `libelf` to extract GOT entries and symbol tables
- **Memory Analysis**: Reads process memory to determine actual GOT values
- **Duplicate Detection**: Identifies symbols defined in multiple libraries (with known exceptions)
- **Export Verification**: Checks that resolved symbols are actually exported by their target libraries
- **Flexible Auditing**: Audit just the main executable or all loaded ELF objects

## Requirements

- Linux kernel with `ptrace` support
- CMake 3.15 or higher
- C++17 compatible compiler (GCC 7+ or Clang 5+)
- libelf development headers

### Installing Dependencies

**Fedora/RHEL:**
```bash
sudo dnf install cmake gcc-c++ elfutils-libelf-devel
```

**Debian/Ubuntu:**
```bash
sudo apt-get install cmake g++ libelf-dev
```

## Building

```bash
mkdir build
cd build
cmake ..
make
```

Optional install:
```bash
sudo make install
```

This will install:
- Binary to `/usr/local/bin/got-audit`
- Man page to `/usr/local/share/man/man1/got-audit.1`

## Testing

Run the test suite:
```bash
cd tests
./run_tests.sh
```

Or use CMake's test runner:
```bash
cd build
make test
```

The test suite verifies:
- Binary compilation and basic functionality
- Correct handling of command-line arguments
- Ability to attach and audit processes
- Output format and content
- No false positive duplicate symbol warnings
- Man page validity

## Man Page

View the manual page:
```bash
man ./got-audit.1
```

After installation:
```bash
man got-audit
```

## Usage

```bash
got-audit [OPTIONS] <PID>
```

### Options

- `--all`, `-a`: Audit GOT for all mapped ELF objects (not just the main executable)
- `--help`, `-h`: Show help message

### Arguments

- `<PID>`: Process ID to audit

### Examples

Audit the main executable of process 1234:
```bash
sudo ./got-audit 1234
```

Audit all ELF objects loaded by process 1234:
```bash
sudo ./got-audit --all 1234
```

### Example Output

```
Successfully attached to process 1234

════════════════════════════════════════════════════════════════
/usr/bin/bash
════════════════════════════════════════════════════════════════

GOT protection: Full RelRO | GOT functions: 231

endgrent : /usr/lib64/libc.so.6
__ctype_toupper_loc : /usr/lib64/libc.so.6
free : /usr/lib64/libc.so.6
strcpy : /usr/lib64/libc.so.6
printf : /usr/lib64/libc.so.6
tputs : /usr/lib64/libtinfo.so.6.5
...

Detached from process 1234
```

**Color coding:**
- 🟢 Green: Resolved symbols (pointing to external libraries)
- 🟡 Yellow: Unresolved symbols (still pointing to PLT stubs)
- 🔴 Red: Warnings (duplicate symbols or export mismatches)

## How It Works

1. Attaches to the process and reads its memory layout
2. Parses GOT entries and builds a symbol index from loaded libraries  
3. Checks each GOT entry for unexpected resolutions or duplicates

For technical details, see [DEVELOPMENT.md](DEVELOPMENT.md#data-flow).

## Output Format

The tool produces a report for each audited ELF object:

```
════════════════════════════════════════════════════════════════
/path/to/executable
════════════════════════════════════════════════════════════════

GOT protection: Full RelRO | GOT functions: 42

read : /usr/lib64/libc.so.6
write : /usr/lib64/libc.so.6
printf : /usr/lib64/libc.so.6
malloc : /usr/lib64/libc.so.6
...
```

### Color Coding

- **Green**: Resolved symbols (pointing outside the executable's own memory)
- **Yellow**: Unresolved symbols (still pointing to PLT stubs)
- **Red**: Warnings (duplicate symbols or export mismatches)

### Warnings

**Duplicate Symbol Warning:**
```
symbol_name : /lib/library.so :: ERROR symbol_name found in multiple paths (/lib/library1.so, /lib/library2.so)
```

**Export Mismatch Warning:**
```
symbol_name : /lib/library.so :: ERROR symbol_name not exported by /lib/library.so
```

## Limitations

- Requires root privileges (or appropriate `CAP_SYS_PTRACE` capability)
- Target process is temporarily paused while attached
- Only supports ELF binaries
- Only tested on x86_64, i386, and aarch64 architectures

## Architecture

For technical details about the architecture, module breakdown, data flow, and key classes, see [DEVELOPMENT.md](DEVELOPMENT.md#architecture).

## Security Considerations

This tool attaches to running processes using `ptrace`, which requires elevated privileges. Use with caution and only on processes you own or have permission to inspect.

## Origin

This tool is a machine-generated C++ port of the `got-audit` command from [GEF (GDB Enhanced Features)](https://github.com/hugsy/gef), a GDB plugin. The original implementation was written in Python and integrated with GDB.

**Original GEF Project:**
- Repository: https://github.com/hugsy/gef
- Copyright (c) 2013-2025 crazy rabbidz
- License: MIT

**This Port:**
- Created by Claude (Anthropic AI) in 2026
- Based on GEF's GotAuditCommand implementation in gef/gef.py
- Implemented using standard libelf API and ptrace system calls

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

This is a machine-generated port of work from GEF (GDB Enhanced Features), which is also MIT licensed. The port was created by Claude (Anthropic AI) based on the original GotAuditCommand implementation.

**Reference materials:**
- GEF (GDB Enhanced Features) - got-audit command implementation (gef/gef.py)
- Standard libelf API documentation
- Linux ptrace system call documentation
- ELF format specification
