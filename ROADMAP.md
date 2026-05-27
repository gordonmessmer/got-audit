# Roadmap

Future enhancements and features for got-audit.

## Version 1.1 (Next Minor Release)

### High Priority

- [ ] **Core dump support** - Audit GOT from core dumps, not just live processes
  - Read from ELF core file instead of live memory
  - No ptrace required
  - Useful for post-mortem analysis
  - Reference: GDB's core file handling

- [ ] **JSON output format** - Machine-readable output for tool integration
  ```bash
  got-audit --json <PID>
  ```
  - Structured data for parsing
  - Integration with security scanners
  - Easier automated testing

- [ ] **Symbol filtering** - Only show specific symbols
  ```bash
  got-audit --filter="dlopen,malloc" <PID>
  got-audit --exclude="libc" <PID>
  ```

### Medium Priority

- [ ] **Quiet mode** - Suppress informational messages
  ```bash
  got-audit --quiet <PID>  # Only show warnings/errors
  ```

- [ ] **Configuration file** - Custom expected duplicates
  ```bash
  ~/.config/got-audit/config.yml
  ```
  - Override expected_duplicates list
  - Custom warning rules
  - Output preferences

- [ ] **Performance improvements**
  - Parallel symbol indexing
  - Cache parsed ELF files
  - Benchmark on large processes

### Low Priority

- [ ] **Colorization control**
  ```bash
  got-audit --no-color <PID>
  export GOT_AUDIT_COLORS=never
  ```

- [ ] **Verbosity levels**
  ```bash
  got-audit -v <PID>     # Verbose
  got-audit -vv <PID>    # Very verbose (debug)
  ```

## Version 1.2

### Architecture Support

- [ ] **Test on ARM64** - Verify aarch64 support
- [ ] **Test on i386** - Verify 32-bit x86 support
- [ ] **RISC-V support** - Add EM_RISCV relocation detection
- [ ] **MIPS support** - Add EM_MIPS relocation detection

### Platform Support

- [ ] **Alpine Linux** - Test with musl libc instead of glibc
- [ ] **FreeBSD** - Port to FreeBSD (different /proc, ptrace)
- [ ] **Android** - Test on Android processes
- [ ] **macOS** - Investigate Mach-O format support

### Security Features

- [ ] **Symbol versioning checks** - Verify symbol versions match
  - Currently strips `@GLIBC_2.17` suffixes
  - Could verify version compatibility

- [ ] **ASLR detection** - Detect if ASLR is working
  - Compare base addresses across runs
  - Warn if predictable

- [ ] **Hardening recommendations** - Suggest security improvements
  - "Enable Full RelRO"
  - "This symbol could be protected"

## Version 2.0 (Major Changes)

### Breaking Changes Allowed

- [ ] **Plugin system** - Extensible warning rules
  ```cpp
  class CustomWarningRule : public WarningRule {
      bool check(const GotEntry& entry) override;
  };
  ```

- [ ] **Database of known issues** - CVE mapping
  - "This GOT hijack matches CVE-2024-XXXX"
  - Update database from online source

- [ ] **Remote auditing** - Audit over SSH/network
  ```bash
  got-audit --remote=user@host <PID>
  ```

- [ ] **Differential auditing** - Compare before/after
  ```bash
  got-audit --snapshot <PID>
  # ... do something ...
  got-audit --diff <PID>
  ```

### Advanced Features

- [ ] **Continuous monitoring** - Watch for GOT changes
  ```bash
  got-audit --monitor <PID>  # Stay attached, report changes
  ```

- [ ] **Syscall tracing integration** - Combine with strace
  - Detect GOT modifications at runtime
  - LD_PRELOAD attack detection

- [ ] **Integration with GDB/LLDB** - Native debugger support
  - GDB Python script that calls got-audit
  - LLDB plugin

## Community Wishlist

Items requested by users (to be prioritized):

- **Better error messages** - More helpful diagnostics
- **Example attack demonstrations** - Show real exploits
- **Tutorial mode** - Educational output
- **Comparison mode** - Compare two processes side-by-side
- **Export to various formats** - CSV, XML, HTML report

## Research Projects

Experimental features that need investigation:

- [ ] **ML-based anomaly detection**
  - Learn "normal" GOT patterns
  - Detect anomalous entries
  
- [ ] **Fuzzing integration**
  - Fuzz ELF parser
  - Detect parser bugs
  
- [ ] **Binary diffing**
  - Compare GOT across binary versions
  - Detect supply chain attacks

- [ ] **DWARF debug info**
  - Use debug symbols for better reporting
  - Show source locations

## Documentation Improvements

- [ ] **Video tutorials** - Screencast demonstrations
- [ ] **Blog posts** - Write-ups of interesting findings
- [ ] **Presentations** - Conference talks about GOT auditing
- [ ] **Case studies** - Real-world security analysis examples
- [ ] **FAQ** - Common questions and answers
- [ ] **Troubleshooting guide** - Common issues and solutions

## Testing Improvements

- [ ] **Fuzzing** - Fuzz ELF parser with malformed files
  ```bash
  afl-fuzz -i testcases/ -o findings/ ./got-audit @@
  ```

- [ ] **Code coverage** - Measure test coverage
  - Target: >80% line coverage
  - gcov/lcov integration

- [ ] **Benchmarking** - Performance regression tests
  - Time to audit large processes
  - Memory usage profiling

- [ ] **Cross-platform CI** - Test on more platforms
  - Debian, Arch, Gentoo
  - Different kernel versions
  - Container environments

## Build System

- [ ] **Debian packaging** - .deb packages
- [ ] **Arch AUR** - AUR package
- [ ] **Homebrew** - macOS package manager
- [ ] **Snap/Flatpak** - Universal Linux packages
- [ ] **Static binary** - No dependencies

## Integration

- [ ] **Lynis integration** - Security auditing tool
- [ ] **OSSEC integration** - HIDS integration
- [ ] **Wazuh integration** - Security platform
- [ ] **Nmap NSE script** - Network scanning
- [ ] **Metasploit module** - Exploitation framework

## Contributing

Want to work on a roadmap item? See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Before starting major work:
1. Open a GitHub Discussion/Issue to discuss approach
2. Check if someone else is working on it
3. Consider breaking into smaller tasks
4. Write tests first (TDD approach)

## Prioritization

Features are prioritized based on:
1. **Security impact** - Does it detect more attacks?
2. **User demand** - How many people requested it?
3. **Compatibility** - Does it match GEF behavior?
4. **Maintainability** - How complex is the code?
5. **Performance** - Does it slow things down?

## Versioning

We follow [Semantic Versioning](https://semver.org/):
- **MAJOR** - Breaking changes
- **MINOR** - New features, backward compatible
- **PATCH** - Bug fixes, backward compatible

---

Last updated: 2026-05-27
