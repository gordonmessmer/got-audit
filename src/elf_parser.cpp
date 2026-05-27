/*
 * got-audit - ELF file parser
 *
 * SPDX-License-Identifier: MIT
 *
 * This is a machine-generated C++ port of the "got-audit" command from GEF
 * (GDB Enhanced Features), created by Claude (Anthropic AI) in 2026.
 *
 * Original GEF project: https://github.com/hugsy/gef
 *   Copyright (c) 2013-2025 crazy rabbidz
 *
 * ELF parsing implemented using libelf API.
 */

#include "elf_parser.h"
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>
#include <libelf.h>
#include <gelf.h>
#include <cstring>
#include <iostream>

ElfParser::ElfParser(const std::string& filepath)
    : filepath_(filepath)
    , fd_(-1)
    , elf_handle_(nullptr)
    , is_pie_(false)
    , has_full_relro_(false)
    , has_partial_relro_(false) {
}

ElfParser::~ElfParser() {
    if (elf_handle_) {
        elf_end(static_cast<Elf*>(elf_handle_));
    }
    if (fd_ >= 0) {
        close(fd_);
    }
}

bool ElfParser::parse() {
    if (elf_version(EV_CURRENT) == EV_NONE) {
        std::cerr << "ELF library initialization failed: " << elf_errmsg(-1) << std::endl;
        return false;
    }

    fd_ = open(filepath_.c_str(), O_RDONLY);
    if (fd_ < 0) {
        std::cerr << "Failed to open file: " << filepath_ << std::endl;
        return false;
    }

    elf_handle_ = elf_begin(fd_, ELF_C_READ, nullptr);
    if (!elf_handle_) {
        std::cerr << "elf_begin() failed: " << elf_errmsg(-1) << std::endl;
        return false;
    }

    Elf* elf = static_cast<Elf*>(elf_handle_);
    if (elf_kind(elf) != ELF_K_ELF) {
        std::cerr << "Not an ELF file: " << filepath_ << std::endl;
        return false;
    }

    GElf_Ehdr ehdr;
    if (!gelf_getehdr(elf, &ehdr)) {
        std::cerr << "Failed to get ELF header: " << elf_errmsg(-1) << std::endl;
        return false;
    }

    is_pie_ = (ehdr.e_type == ET_DYN);

    if (!parse_dynamic_symbols()) {
        return false;
    }

    if (!parse_relocations()) {
        return false;
    }

    if (!check_relro()) {
        return false;
    }

    return true;
}

bool ElfParser::parse_dynamic_symbols() {
    Elf* elf = static_cast<Elf*>(elf_handle_);
    Elf_Scn* scn = nullptr;

    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) {
            continue;
        }

        if (shdr.sh_type != SHT_DYNSYM) {
            continue;
        }

        Elf_Data* data = elf_getdata(scn, nullptr);
        if (!data) {
            continue;
        }

        size_t num_symbols = shdr.sh_size / shdr.sh_entsize;
        for (size_t i = 0; i < num_symbols; i++) {
            GElf_Sym sym;
            if (!gelf_getsym(data, i, &sym)) {
                continue;
            }

            const char* name = elf_strptr(elf, shdr.sh_link, sym.st_name);
            if (!name || name[0] == '\0') {
                continue;
            }

            unsigned char bind = GELF_ST_BIND(sym.st_info);
            unsigned char type = GELF_ST_TYPE(sym.st_info);

            // Only include defined symbols (not undefined/imported symbols)
            if (sym.st_shndx == SHN_UNDEF) {
                continue;
            }

            if (type == STT_FUNC || type == STT_GNU_IFUNC || type == STT_NOTYPE) {
                if (bind == STB_GLOBAL || bind == STB_WEAK) {
                    std::string sym_name(name);
                    size_t at_pos = sym_name.find('@');
                    if (at_pos != std::string::npos) {
                        sym_name = sym_name.substr(0, at_pos);
                    }

                    SymbolInfo info;
                    info.name = sym_name;
                    info.value = sym.st_value;
                    info.size = sym.st_size;
                    info.bind = bind;
                    info.type = type;

                    dynamic_symbols_[sym_name] = info;
                }
            }
        }
    }

    return true;
}

bool ElfParser::parse_relocations() {
    Elf* elf = static_cast<Elf*>(elf_handle_);
    Elf_Scn* scn = nullptr;

    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) {
            continue;
        }

        if (shdr.sh_type != SHT_RELA && shdr.sh_type != SHT_REL) {
            continue;
        }

        Elf_Data* data = elf_getdata(scn, nullptr);
        if (!data) {
            continue;
        }

        GElf_Shdr link_shdr;
        Elf_Scn* link_scn = elf_getscn(elf, shdr.sh_link);
        if (!link_scn || !gelf_getshdr(link_scn, &link_shdr)) {
            continue;
        }

        size_t num_relocs = shdr.sh_size / shdr.sh_entsize;
        for (size_t i = 0; i < num_relocs; i++) {
            GElf_Rela rela;
            GElf_Rel rel;
            uint64_t offset;
            uint64_t sym_idx;
            uint64_t type;

            if (shdr.sh_type == SHT_RELA) {
                if (!gelf_getrela(data, i, &rela)) {
                    continue;
                }
                offset = rela.r_offset;
                sym_idx = GELF_R_SYM(rela.r_info);
                type = GELF_R_TYPE(rela.r_info);
            } else {
                if (!gelf_getrel(data, i, &rel)) {
                    continue;
                }
                offset = rel.r_offset;
                sym_idx = GELF_R_SYM(rel.r_info);
                type = GELF_R_TYPE(rel.r_info);
            }

            GElf_Ehdr ehdr;
            gelf_getehdr(elf, &ehdr);

            bool is_jump_slot = false;
            if (ehdr.e_machine == EM_X86_64 && type == 7) {
                is_jump_slot = true;
            } else if (ehdr.e_machine == EM_386 && type == 7) {
                is_jump_slot = true;
            } else if (ehdr.e_machine == EM_AARCH64 && type == 1026) {
                is_jump_slot = true;
            }

            if (!is_jump_slot) {
                continue;
            }

            Elf_Data* sym_data = elf_getdata(link_scn, nullptr);
            if (!sym_data) {
                continue;
            }

            GElf_Sym sym;
            if (!gelf_getsym(sym_data, sym_idx, &sym)) {
                continue;
            }

            const char* name = elf_strptr(elf, link_shdr.sh_link, sym.st_name);
            if (!name) {
                continue;
            }

            RelocationEntry entry;
            entry.offset = offset;
            entry.symbol_name = name;

            size_t at_pos = entry.symbol_name.find('@');
            if (at_pos != std::string::npos) {
                entry.version = entry.symbol_name.substr(at_pos + 1);
                entry.symbol_name = entry.symbol_name.substr(0, at_pos);
            }

            jump_slots_.push_back(entry);
        }
    }

    return true;
}

bool ElfParser::check_relro() {
    Elf* elf = static_cast<Elf*>(elf_handle_);
    Elf_Scn* scn = nullptr;

    bool found_gnu_relro = false;
    bool found_bind_now = false;

    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) {
            continue;
        }

        if (shdr.sh_type == SHT_DYNAMIC) {
            Elf_Data* data = elf_getdata(scn, nullptr);
            if (!data) {
                continue;
            }

            size_t num_entries = shdr.sh_size / shdr.sh_entsize;
            for (size_t i = 0; i < num_entries; i++) {
                GElf_Dyn dyn;
                if (!gelf_getdyn(data, i, &dyn)) {
                    continue;
                }

                if (dyn.d_tag == DT_BIND_NOW) {
                    found_bind_now = true;
                } else if (dyn.d_tag == DT_FLAGS && (dyn.d_un.d_val & DF_BIND_NOW)) {
                    found_bind_now = true;
                } else if (dyn.d_tag == DT_FLAGS_1 && (dyn.d_un.d_val & DF_1_NOW)) {
                    found_bind_now = true;
                }
            }
        }
    }

    scn = nullptr;
    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        GElf_Phdr phdr;
        size_t phnum;
        if (elf_getphdrnum(elf, &phnum) != 0) {
            continue;
        }

        for (size_t i = 0; i < phnum; i++) {
            if (!gelf_getphdr(elf, i, &phdr)) {
                continue;
            }

            if (phdr.p_type == PT_GNU_RELRO) {
                found_gnu_relro = true;
                break;
            }
        }
        if (found_gnu_relro) {
            break;
        }
    }

    has_partial_relro_ = found_gnu_relro;
    has_full_relro_ = found_gnu_relro && found_bind_now;

    return true;
}

std::vector<std::string> ElfParser::get_exported_symbols() const {
    std::vector<std::string> symbols;
    for (const auto& pair : dynamic_symbols_) {
        symbols.push_back(pair.first);
    }
    return symbols;
}
