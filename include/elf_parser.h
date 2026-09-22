/*
 * got-audit - ELF file parser interface
 *
 * SPDX-License-Identifier: MIT
 *
 * This is a machine-generated C++ port of the "got-audit" command from GEF
 * (GDB Enhanced Features), created by Claude (Anthropic AI) in 2026.
 *
 * Original GEF project: https://github.com/hugsy/gef
 *   Copyright (c) 2013-2025 crazy rabbidz
 */

#ifndef ELF_PARSER_H
#define ELF_PARSER_H

#include <string>
#include <vector>
#include <map>
#include <cstdint>

struct RelocationEntry {
    uint64_t offset;
    std::string symbol_name;
    // Version requirement of the reference, read from .gnu.version /
    // .gnu.version_r. When versioned is true, version names the required node;
    // otherwise the reference is unversioned and version is empty.
    std::string version;
    bool versioned = false;
};

struct SymbolInfo {
    std::string name;
    uint64_t value;
    uint64_t size;
    unsigned char bind;
    unsigned char type;
    // Version node this definition provides, read from .gnu.version /
    // .gnu.version_d. Empty means an unversioned definition. is_default is true
    // for a @@ default node or an unversioned symbol, false for a hidden @ node.
    std::string version;
    bool is_default = true;
};

class ElfParser {
public:
    explicit ElfParser(const std::string& filepath);
    ~ElfParser();

    bool parse();

    std::vector<RelocationEntry> get_jump_slots() const { return jump_slots_; }
    std::vector<std::string> get_exported_symbols() const;
    const std::map<std::string, std::vector<SymbolInfo>>& get_symbol_definitions() const {
        return dynamic_symbols_;
    }
    bool is_pie() const { return is_pie_; }
    bool has_full_relro() const { return has_full_relro_; }
    bool has_partial_relro() const { return has_partial_relro_; }

private:
    std::string filepath_;
    int fd_;
    void* elf_handle_;

    std::vector<RelocationEntry> jump_slots_;
    // A base symbol name can have several definitions (e.g. a default and a
    // hidden version node), so each name maps to a list of definitions.
    std::map<std::string, std::vector<SymbolInfo>> dynamic_symbols_;
    bool is_pie_;
    bool has_full_relro_;
    bool has_partial_relro_;

    // Symbol-versioning tables, populated by parse_versions() before symbols and
    // relocations are read. versym_ is indexed by dynamic-symbol-table index.
    std::vector<uint16_t> versym_;
    std::map<uint16_t, std::string> verdef_names_;
    std::map<uint16_t, std::string> verneed_names_;

    bool parse_versions();
    bool parse_relocations();
    bool parse_dynamic_symbols();
    bool check_relro();
};

#endif // ELF_PARSER_H
