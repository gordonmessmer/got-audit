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
    std::vector<std::string> warnings;
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

    std::map<std::string, std::vector<std::string>> symbols_to_paths_;
    std::map<std::string, std::vector<std::string>> paths_to_symbols_;

    static const std::set<std::string> expected_duplicates_;

    void index_symbols_from_path(const std::string& path);
    void check_for_warnings(GotEntry& entry);
};

#endif // GOT_AUDITOR_H
