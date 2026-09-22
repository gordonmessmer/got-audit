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

    if (!parse_versions()) {
        return false;
    }

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

// VERSYM_HIDDEN marks a .gnu.version entry as referring to a non-default node.
static const uint16_t kVersymHidden = 0x8000;

// Read the symbol-versioning sections (.gnu.version, .gnu.version_d,
// .gnu.version_r) so that each definition and each reference can be tagged with
// its version node. Without this, the version requirement of a GOT reference and
// the default/non-default status of a definition are unknown, and the auditor
// falls back to treating every symbol as unversioned.
bool ElfParser::parse_versions() {
    Elf* elf = static_cast<Elf*>(elf_handle_);
    Elf_Scn* scn = nullptr;

    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr)) {
            continue;
        }

        if (shdr.sh_type == SHT_GNU_versym) {
            Elf_Data* data = elf_getdata(scn, nullptr);
            if (!data) {
                continue;
            }
            size_t count = (shdr.sh_entsize != 0) ? shdr.sh_size / shdr.sh_entsize
                                                   : shdr.sh_size / sizeof(GElf_Versym);
            versym_.resize(count, 1);
            for (size_t i = 0; i < count; i++) {
                GElf_Versym vs;
                if (gelf_getversym(data, i, &vs)) {
                    versym_[i] = vs;
                }
            }
        } else if (shdr.sh_type == SHT_GNU_verdef) {
            Elf_Data* data = elf_getdata(scn, nullptr);
            if (!data) {
                continue;
            }
            size_t offset = 0;
            for (unsigned int i = 0; i < shdr.sh_info; i++) {
                GElf_Verdef vd;
                if (!gelf_getverdef(data, offset, &vd)) {
                    break;
                }
                // The first auxiliary entry holds the version node's own name;
                // the base entry (VER_FLG_BASE) names the object itself, not a
                // real version node, so it is skipped.
                if (!(vd.vd_flags & VER_FLG_BASE)) {
                    GElf_Verdaux vda;
                    if (gelf_getverdaux(data, offset + vd.vd_aux, &vda)) {
                        const char* nm = elf_strptr(elf, shdr.sh_link, vda.vda_name);
                        if (nm) {
                            verdef_names_[vd.vd_ndx & 0x7fff] = nm;
                        }
                    }
                }
                if (vd.vd_next == 0) {
                    break;
                }
                offset += vd.vd_next;
            }
        } else if (shdr.sh_type == SHT_GNU_verneed) {
            Elf_Data* data = elf_getdata(scn, nullptr);
            if (!data) {
                continue;
            }
            size_t offset = 0;
            for (unsigned int i = 0; i < shdr.sh_info; i++) {
                GElf_Verneed vn;
                if (!gelf_getverneed(data, offset, &vn)) {
                    break;
                }
                size_t aux_off = offset + vn.vn_aux;
                for (unsigned int j = 0; j < vn.vn_cnt; j++) {
                    GElf_Vernaux vna;
                    if (!gelf_getvernaux(data, aux_off, &vna)) {
                        break;
                    }
                    const char* nm = elf_strptr(elf, shdr.sh_link, vna.vna_name);
                    if (nm) {
                        verneed_names_[vna.vna_other & 0x7fff] = nm;
                    }
                    if (vna.vna_next == 0) {
                        break;
                    }
                    aux_off += vna.vna_next;
                }
                if (vn.vn_next == 0) {
                    break;
                }
                offset += vn.vn_next;
            }
        }
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
                    // The st_name string never carries an @version suffix; the
                    // version comes from the .gnu.version tables indexed by the
                    // symbol's own dynsym index.
                    std::string sym_name(name);

                    SymbolInfo info;
                    info.name = sym_name;
                    info.value = sym.st_value;
                    info.size = sym.st_size;
                    info.bind = bind;
                    info.type = type;
                    info.version.clear();
                    info.is_default = true;

                    uint16_t raw = (i < versym_.size()) ? versym_[i] : 1;
                    uint16_t vndx = raw & 0x7fff;
                    if (vndx > 1) {
                        auto it = verdef_names_.find(vndx);
                        if (it != verdef_names_.end()) {
                            info.version = it->second;
                        }
                        info.is_default = !(raw & kVersymHidden);
                    }

                    dynamic_symbols_[sym_name].push_back(info);
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
            entry.versioned = false;

            // The reference's version requirement comes from .gnu.version indexed
            // by the referenced symbol's dynsym index; an undefined symbol's need
            // is described in .gnu.version_r (verneed).
            uint16_t raw = (sym_idx < versym_.size()) ? versym_[sym_idx] : 1;
            uint16_t vndx = raw & 0x7fff;
            if (vndx > 1) {
                auto it = verneed_names_.find(vndx);
                if (it != verneed_names_.end()) {
                    entry.version = it->second;
                    entry.versioned = true;
                } else {
                    // Fall back to a locally defined version node (rare for an
                    // undefined reference, but keeps the tag consistent).
                    auto it2 = verdef_names_.find(vndx);
                    if (it2 != verdef_names_.end()) {
                        entry.version = it2->second;
                        entry.versioned = true;
                    }
                }
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
