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
    std::string version;
};

struct SymbolInfo {
    std::string name;
    uint64_t value;
    uint64_t size;
    unsigned char bind;
    unsigned char type;
};

class ElfParser {
public:
    explicit ElfParser(const std::string& filepath);
    ~ElfParser();

    bool parse();

    std::vector<RelocationEntry> get_jump_slots() const { return jump_slots_; }
    std::vector<std::string> get_exported_symbols() const;
    bool is_pie() const { return is_pie_; }
    bool has_full_relro() const { return has_full_relro_; }
    bool has_partial_relro() const { return has_partial_relro_; }

private:
    std::string filepath_;
    int fd_;
    void* elf_handle_;

    std::vector<RelocationEntry> jump_slots_;
    std::map<std::string, SymbolInfo> dynamic_symbols_;
    bool is_pie_;
    bool has_full_relro_;
    bool has_partial_relro_;

    bool parse_relocations();
    bool parse_dynamic_symbols();
    bool check_relro();
};

#endif // ELF_PARSER_H
