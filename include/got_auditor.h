/*
 * got-audit - GOT auditing interface
 *
 * SPDX-License-Identifier: MIT
 *
 * This is a machine-generated C++ port of the "got-audit" command from GEF
 * (GDB Enhanced Features), created by Claude (Anthropic AI) in 2026.
 *
 * Original GEF project: https://github.com/hugsy/gef
 *   Copyright (c) 2013-2025 crazy rabbidz
 */

#ifndef GOT_AUDITOR_H
#define GOT_AUDITOR_H

#include "elf_parser.h"
#include "process_memory.h"
#include <string>
#include <vector>
#include <map>
#include <set>

struct GotEntry {
    std::string symbol_name;
    std::string source_path;
    uint64_t got_offset;
    uint64_t got_address;
    uint64_t resolved_address;
    std::string resolved_path;
    bool is_resolved;
    // Version requirement of this reference, carried from the relocation so the
    // auditor can apply the loader's resolution rules (see docs/alerting.md).
    bool ref_versioned = false;
    std::string ref_version;
    std::vector<std::string> warnings;
};

// One definition of a symbol found in a particular library, with the versioning
// attributes that decide whether it can legitimately satisfy a given reference.
struct SymbolDefLoc {
    std::string path;
    std::string version;   // empty = unversioned definition
    bool is_default;       // @@ default node or unversioned
    unsigned char bind;    // STB_GLOBAL (strong) or STB_WEAK
};

class GotAuditor {
public:
    GotAuditor(ProcessMemory& proc_mem, const std::string& main_executable, bool audit_all);

    bool build_symbol_index();
    std::vector<GotEntry> audit_got(const std::string& path);

private:
    ProcessMemory& proc_mem_;
    std::string main_executable_path_;
    bool audit_all_;

    // Every strong/weak definition seen, keyed by base symbol name, so the
    // reference-driven candidate set can be computed per GOT entry.
    std::map<std::string, std::vector<SymbolDefLoc>> defs_by_symbol_;
    // Libraries whose symbols have been indexed; used to avoid re-parsing and to
    // scope the resolution-consistency check to objects we actually know about.
    std::set<std::string> indexed_paths_;

    // Allowlist for Alert 1 (ambiguous duplicates) only; see docs/alerting.md.
    static const std::set<std::string> expected_duplicates_;

    void index_symbols_from_path(const std::string& path);
    void check_for_warnings(GotEntry& entry);
};

#endif // GOT_AUDITOR_H
