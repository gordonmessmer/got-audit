# Contributing to got-audit

Thank you for your interest in contributing to got-audit!

## Important Context

This project is a **machine-generated C++ port** of the `got-audit` command from GEF (GDB Enhanced Features). The original implementation is in Python and can be found at https://github.com/hugsy/gef.

When contributing, please keep in mind:
1. **Behavior compatibility**: Changes should maintain compatibility with the original GEF implementation when possible
2. **Reference the original**: Check `gef/gef.py` for expected behavior
3. **Document AI assistance**: If using AI tools (like Claude) for development, note this in commit messages

## Getting Started

### Development Environment

See [DEVELOPMENT.md](DEVELOPMENT.md) for detailed setup instructions.

Quick start:
```bash
# Install dependencies (Fedora)
sudo dnf install cmake gcc-c++ elfutils-libelf-devel

# Build
./build.sh

# Test
cd tests && ./run_tests.sh
```

### Finding Issues to Work On

- Check GitHub Issues for bugs and feature requests
- Look for "TODO" comments in source code
- Compare behavior with original GEF implementation

## Contribution Process

### 1. Fork and Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-number-description
```

Branch naming:
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation only
- `refactor/` - Code refactoring
- `test/` - Test improvements

### 2. Make Changes

- Write clean, readable C++17 code
- Follow existing code style
- Add tests for new functionality
- Update documentation (README.md, man page, DEVELOPMENT.md)
- Ensure no compiler warnings (`make` should be clean)

### 3. Test Thoroughly

```bash
# Build and run tests
./build.sh
cd tests && ./run_tests.sh

# Test manually with real processes
sudo ./build/got-audit <PID>
sudo ./build/got-audit --all <PID>

# Compare with GEF if possible
gdb -p <PID>
(gdb) source /path/to/gef.py
(gdb) got-audit

# Check for memory leaks
sudo valgrind --leak-check=full ./build/got-audit <PID>
```

### 4. Commit

Follow this commit message format:

```
Short summary (50 chars or less)

Longer description of what changed and why. Reference any
issues or discussions. Explain the rationale for the change.

If this maintains compatibility with GEF, note:
"Matches GEF behavior in gef.py:NNNN"

If this diverges from GEF, explain why:
"Diverges from GEF because [reason]"

Co-Authored-By: Your Name <your.email@example.com>
```

### 5. Submit Pull Request

- Ensure all tests pass
- Reference any related issues
- Provide clear description of what changed and why
- Include example output if UI changes

## Code Review Process

- All changes require review
- Address feedback promptly
- Be open to suggestions
- Reviewers will check:
  - Code quality and clarity
  - Test coverage
  - Documentation updates
  - Compatibility with GEF (when applicable)
  - Security implications (this is a security tool)

## Code Style Guidelines

### C++ Style

- **C++17** standard features
- **RAII** for resource management
- **const correctness** - use const where applicable
- **Clear names** over clever code
- **Error handling** - return bool, log to stderr
- **No exceptions** - this is systems code

Example:
```cpp
// Good
bool ElfParser::parse_symbols() {
    if (!validate_header()) {
        std::cerr << "Invalid ELF header\n";
        return false;
    }
    // ... do work ...
    return true;
}

// Avoid
void ElfParser::parse_symbols() {
    if (!validate_header()) {
        throw std::runtime_error("Invalid ELF header");
    }
    // ...
}
```

### Naming Conventions

- **Classes**: PascalCase (`GotAuditor`, `ElfParser`)
- **Functions**: snake_case (`parse_symbols`, `build_index`)
- **Member variables**: trailing underscore (`proc_mem_`, `symbols_`)
- **Constants**: UPPER_SNAKE_CASE or const variable

### Comments

- Comment the "why", not the "what"
- Document non-obvious behavior

```cpp
// Good
// GEF allows duplicates if one is in the main executable
// See gef.py:9659
bool only_in_main = (paths.size() == 2 && ...);

// Avoid
// Check if only in main
bool only_in_main = ...;
```

### Header Guards

Use `#ifndef` guards, not `#pragma once`:
```cpp
#ifndef MODULE_NAME_H
#define MODULE_NAME_H
// ...
#endif // MODULE_NAME_H
```

## Testing Requirements

### New Features

- Add test case to `tests/run_tests.sh`
- Test both success and failure paths
- Test with `--all` flag if applicable
- Compare with GEF behavior

### Bug Fixes

- Add regression test that would have caught the bug
- Verify fix doesn't break existing tests
- Document the bug and fix in commit message

### Test Coverage

Aim for:
- All command-line options tested
- All error paths tested
- No false positives in duplicate detection
- Output format consistency

## Documentation Requirements

Update these files as appropriate:

- **README.md** - User-facing features, usage examples
- **got-audit.1** - Man page for new options/features
- **DEVELOPMENT.md** - Internal architecture changes
- **CONTRIBUTING.md** - Process changes
- **Source code** - API documentation in headers

## Security Considerations

This tool:
- Attaches to processes (requires root)
- Reads process memory
- Is used for security analysis

When contributing:
- **No unsafe operations** - validate all inputs
- **No privilege escalation** - maintain least privilege
- **Clear error messages** - but don't leak sensitive info
- **Audit-grade code** - this tool audits security, so it must be secure

## License

By contributing, you agree that your contributions will be licensed under the MIT License, the same as the original GEF project.

All contributions must include:
```cpp
/*
 * got-audit - [Module description]
 *
 * SPDX-License-Identifier: MIT
 *
 * [Rest of header...]
 */
```

## AI-Assisted Development

If you use AI tools (like Claude, GitHub Copilot, etc.) for development:

1. **Review all generated code** - Don't blindly accept suggestions
2. **Test thoroughly** - AI-generated code needs verification
3. **Attribute properly** - Add to Co-Authored-By:
   ```
   Co-Authored-By: Your Name <your@email.com>
   Co-Authored-By: Claude Sonnet 4.5 <noreply@anthropic.com>
   ```
4. **Document decisions** - Explain why AI suggestions were accepted/rejected

## Questions?

- Check [DEVELOPMENT.md](DEVELOPMENT.md) for technical details
- Review existing code for examples
- Open a GitHub Discussion for questions
- Check original GEF documentation

## Code of Conduct

- Be respectful and professional
- Welcome newcomers
- Focus on the code, not the person
- Remember: everyone is learning
- This is a machine-generated port - there's no "original author" to defer to

## Thank You!

Your contributions help make got-audit better for everyone. Whether it's a bug fix, new feature, documentation improvement, or test addition - all contributions are valued!
