# Project Context for AI Agents

This file provides context for AI agents (like Claude) working on this codebase.

## What This Project Is

**got-audit** is a machine-generated C++ port of the `got-audit` command from GEF (GDB Enhanced Features). It was created by Claude (Anthropic AI) in May 2026.

## Architecture at a Glance

```
Process → ptrace attach → Read /proc/PID/maps
                       ↓
    Read GOT values from process memory (process_vm_readv)
                       ↓
    Parse ELF files (libelf) → Extract symbols & GOT entries
                       ↓
    Check: Does symbol resolve to expected library?
           Is symbol exported by that library?
           Is symbol duplicated unexpectedly?
                       ↓
    Report warnings in color-coded output
```

## Key Files and Their Purpose

| File | Purpose | Key Functions |
|------|---------|---------------|
| `src/main.cpp` | Entry point, CLI parsing | `main()`, `print_usage()` |
| `src/elf_parser.cpp` | Parse ELF files with libelf | `parse_relocations()`, `parse_dynamic_symbols()` |
| `src/process_memory.cpp` | Attach to process, read memory | `attach()`, `read_uint64()` |
| `src/got_auditor.cpp` | Core audit logic | `audit_got()`, `check_for_warnings()` |
| `src/report.cpp` | Format output | `print_got_report()` |

## Design Decisions

### Why C++?

The original request specified C++. Python would have been easier for a port, but C++ was the requirement.

### Why libelf?

Standard, widely available, well-documented. Alternatives like libbfd are more complex.

### Why ptrace?

Standard Linux mechanism for process inspection. Requires root, but that's acceptable for a security tool.

### Why Not Use nm/readelf External Tools?

The original request said "try to avoid calling external tools like nm". So we use libelf directly.

## Common Patterns

### Error Handling

```cpp
bool function() {
    if (error_condition) {
        std::cerr << "Error message\n";
        return false;
    }
    // ... do work ...
    return true;
}
```

Never throw exceptions. Always return bool and log to stderr.

### Resource Management

```cpp
class ElfParser {
    ~ElfParser() {
        if (elf_handle_) {
            elf_end(static_cast<Elf*>(elf_handle_));
        }
        if (fd_ >= 0) {
            close(fd_);
        }
    }
};
```

RAII: destructors clean up resources automatically.

### Symbol Name Handling

Symbol names can have version suffixes like `malloc@GLIBC_2.17`. We strip these:

```cpp
std::string sym_name(name);
size_t at_pos = sym_name.find('@');
if (at_pos != std::string::npos) {
    sym_name = sym_name.substr(0, at_pos);
}
```

## Testing Strategy

1. **Automated tests** - `tests/run_tests.sh` (13 tests)
2. **Manual testing** - Against real processes
3. **Regression testing** - Ensure bugs stay fixed

## What NOT to Change

- **Symbol filtering logic** - Already debugged and fixed
- **Basic algorithm** - Should match GEF unless there's a good reason to diverge

## What CAN Be Changed

- Performance optimizations
- Additional output formats (JSON, etc.)
- New command-line options
- Better error messages
- Architecture support
- Platform support

## Dependencies

### Build-time
- CMake ≥ 3.15
- C++ compiler with C++17 support (GCC or Clang)
- libelf headers (`elfutils-libelf-devel` or `libelf-dev`)

### Runtime
- Linux kernel with ptrace support
- libelf shared library
- Root privileges or CAP_SYS_PTRACE capability

## Limitations

1. **Linux only** - Uses Linux-specific ptrace and /proc
2. **ELF only** - No support for PE, Mach-O, etc.
3. **Requires root** - ptrace needs privileges
4. **Process pauses** - Target stops while attached (brief)
5. **Live processes only** - No core dump support yet

## Git History

Use `git log` and `git show <commit>` to understand why changes were made.

## Development Workflow

1. Read DEVELOPMENT.md for setup
2. Make changes
3. Test with `./build.sh && cd tests && ./run_tests.sh`
4. Update documentation
5. Commit with clear message
6. Push for CI to run

## Communication

When writing commit messages or documentation:
- Be clear about what changed and WHY
- Credit AI assistance if used

## Questions to Ask When Modifying Code

1. Does this maintain backward compatibility?
2. Does this introduce security issues?
3. Does this need tests?
4. Does this need documentation updates?
5. Will this work on other Linux distributions?
6. Is the error handling correct?

## Files That Must Stay in Sync

When changing:
- Command-line options → Update `main.cpp`, `got-audit.1`, `README.md`
- Warning types → Update `got_auditor.cpp`, `README.md`, tests
- Version number → Update `main.cpp`, `got-audit.spec`

## Code Smells to Avoid

- **Magic numbers** - Use named constants
- **Long functions** - Break up >50 lines
- **Deep nesting** - Early return instead
- **Unclear names** - `x`, `tmp`, `foo` are bad
- **Memory leaks** - Always use RAII
- **Undefined behavior** - Validate all inputs

## Performance Considerations

- Symbol indexing can be slow for many libraries
- Process memory reads are relatively fast (process_vm_readv)
- ELF parsing is I/O bound
- Most time spent in libelf, not our code

Future optimization: parallel symbol indexing, ELF file caching.

## Security Considerations

This tool is used for security analysis, so it must be secure:
- Validate all ELF inputs (could be malicious)
- Don't leak sensitive info in error messages
- Maintain least privilege
- No privilege escalation paths
- Clean detach from process even on errors

## Future AI Agents: Notes for You

If you're an AI agent working on this code:

1. **Read this file first** - Understand the context
2. **Check DEVELOPMENT.md** - Technical details
3. **Look at git history** - Learn from past mistakes
4. **Test thoroughly** - Don't break existing functionality
5. **Document changes** - Future you (or another agent) will thank you
6. **Ask questions** - It's OK not to know everything

## License and Attribution

MIT License - Same as GEF

Always credit:
- Original GEF authors (crazy rabbidz, 2013-2025)
- This port was machine-generated by Claude (Anthropic AI)
- Contributors who made changes

## Quick Reference

```bash
# Build
./build.sh

# Test
cd tests && ./run_tests.sh

# Run
sudo ./build/got-audit <PID>
sudo ./build/got-audit --all <PID>

# Format check
groff -man -Tascii got-audit.1 > /dev/null
```

---

Last updated: 2026-05-27 by Claude Sonnet 4.5
