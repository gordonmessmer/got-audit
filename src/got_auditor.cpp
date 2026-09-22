/*
 * got-audit - GOT auditing logic
 *
 * SPDX-License-Identifier: MIT
 *
 * This is a machine-generated C++ port of the "got-audit" command from GEF
 * (GDB Enhanced Features), created by Claude (Anthropic AI) in 2026.
 *
 * Original GEF project: https://github.com/hugsy/gef
 *   Copyright (c) 2013-2025 crazy rabbidz
 *
 * This file implements the core auditing logic from GEF's GotAuditCommand,
 * including duplicate symbol detection and expected duplicates list.
 */

#include "got_auditor.h"
#include <iostream>
#include <algorithm>
#include <elf.h>

// Allowlist for Alert 1 (ambiguous resolution) only. See docs/alerting.md: the
// reference-driven duplicate rule already resolves the vast majority of the old
// hard-coded entries, because references are versioned and bind deterministically
// (Samba private libs, libc-vs-libtirpc xdr_*, weak math aliases, ...). What
// remains here are genuinely-duplicated *strong* definitions that stay ambiguous
// under the rule but are known-good. This list never suppresses Alert 2.
//
// Each group is labelled with the libraries the duplication comes from, so a
// future addition can be attributed the same way.
const std::set<std::string> GotAuditor::expected_duplicates_ = {
    // Symbols that appear in both GNU's libc.so and libm.so under the same
    // strong, default version node, so a reference can bind to either.
    "__finite", "__finitef", "__finitel",
    "__signbit", "__signbitf", "__signbitl",

    // Symbols exported unversioned by libsasl2 and by the auth mechanism plugins
    // it loads (libsasldb and the per-mechanism plugins). The plugins are loaded
    // by libsasl2 itself, so the shared _plug_* helpers are duplicated by design.
    "_plug_buf_alloc", "_plug_challenge_prompt", "_plug_decode",
    "_plug_decode_free", "_plug_decode_init", "_plug_find_prompt",
    "_plug_free_secret", "_plug_free_string",
    "_plug_get_error_message", "_plug_get_password",
    "_plug_get_realm", "_plug_get_simple", "_plug_iovec_to_buf",
    "_plug_ipfromstring", "_plug_make_fulluser",
    "_plug_make_prompts", "_plug_parseuser",
    "_plug_snprintf_os_info", "_plug_strdup",

    // Base64 helpers exported by GNU's libresolv and vendored, unversioned, into
    // libvncserver; either can satisfy an unversioned reference.
    "__b64_ntop", "__b64_pton"
};

// Whether a definition can legitimately satisfy a reference, following the GNU
// loader's check_match rules (see docs/alerting.md):
//   - a versioned reference binds to a matching version node OR any unversioned
//     definition (the interposition wildcard);
//   - an unversioned reference binds only to a default definition.
static bool def_satisfies_ref(const SymbolDefLoc& def,
                              bool ref_versioned,
                              const std::string& ref_version) {
    if (ref_versioned) {
        return def.version == ref_version || def.version.empty();
    }
    return def.is_default;
}

GotAuditor::GotAuditor(ProcessMemory& proc_mem, const std::string& main_executable, bool audit_all)
    : proc_mem_(proc_mem)
    , main_executable_path_(main_executable)
    , audit_all_(audit_all) {
}

bool GotAuditor::build_symbol_index() {
    for (const auto& mapping : proc_mem_.get_memory_maps()) {
        if (!mapping.is_executable() || mapping.path.empty()) {
            continue;
        }

        if (mapping.path[0] != '/' && mapping.path != "[vdso]") {
            continue;
        }

        if (mapping.path == "[vdso]") {
            continue;
        }

        index_symbols_from_path(mapping.path);
    }

    return true;
}

void GotAuditor::index_symbols_from_path(const std::string& path) {
    if (indexed_paths_.find(path) != indexed_paths_.end()) {
        return;
    }
    indexed_paths_.insert(path);

    ElfParser parser(path);
    if (!parser.parse()) {
        return;
    }

    for (const auto& sym : parser.get_symbol_definitions()) {
        const std::string& name = sym.first;
        for (const auto& def : sym.second) {
            SymbolDefLoc loc;
            loc.path = path;
            loc.version = def.version;
            loc.is_default = def.is_default;
            loc.bind = def.bind;
            defs_by_symbol_[name].push_back(loc);
        }
    }
}

std::vector<GotEntry> GotAuditor::audit_got(const std::string& path) {
    std::vector<GotEntry> results;

    ElfParser parser(path);
    if (!parser.parse()) {
        std::cerr << "Failed to parse ELF file: " << path << std::endl;
        return results;
    }

    const MemoryMapping* base_mapping = proc_mem_.find_mapping_by_path(path);
    if (!base_mapping) {
        std::cerr << "Could not find memory mapping for: " << path << std::endl;
        return results;
    }

    uint64_t base_address = base_mapping->start;
    uint64_t end_address = 0;

    for (const auto& mapping : proc_mem_.get_memory_maps()) {
        if (mapping.path == path && mapping.end > end_address) {
            end_address = mapping.end;
        }
    }

    auto relocs = parser.get_jump_slots();

    for (const auto& reloc : relocs) {
        GotEntry entry;
        entry.symbol_name = reloc.symbol_name;
        entry.source_path = path;
        entry.got_offset = reloc.offset;
        entry.ref_versioned = reloc.versioned;
        entry.ref_version = reloc.version;

        if (parser.is_pie()) {
            entry.got_address = base_address + reloc.offset;
        } else {
            entry.got_address = reloc.offset;
        }

        entry.resolved_address = proc_mem_.read_uint64(entry.got_address);

        if (entry.resolved_address >= base_address && entry.resolved_address < end_address) {
            entry.is_resolved = false;
            entry.resolved_path = path;
        } else {
            entry.is_resolved = true;
            const MemoryMapping* resolved_mapping = proc_mem_.find_mapping(entry.resolved_address);
            if (resolved_mapping) {
                entry.resolved_path = resolved_mapping->path;
            } else {
                entry.resolved_path = "no mapping found";
            }
        }

        check_for_warnings(entry);

        results.push_back(entry);
    }

    return results;
}

void GotAuditor::check_for_warnings(GotEntry& entry) {
    if (entry.resolved_path == "no mapping found") {
        return;
    }

    auto it = defs_by_symbol_.find(entry.symbol_name);
    const std::vector<SymbolDefLoc>* defs =
        (it != defs_by_symbol_.end()) ? &it->second : nullptr;

    // ---- Alert 1: ambiguous resolution (the duplicate rule) -----------------
    // Count the distinct libraries holding a *strong* definition that could
    // legitimately satisfy this reference. Two or more means the binding is
    // load-order-dependent, i.e. a latent hijack. See docs/alerting.md.
    if (defs && expected_duplicates_.find(entry.symbol_name) == expected_duplicates_.end()) {
        std::set<std::string> strong_candidate_libs;
        for (const auto& def : *defs) {
            if (def.bind == STB_GLOBAL &&
                def_satisfies_ref(def, entry.ref_versioned, entry.ref_version)) {
                strong_candidate_libs.insert(def.path);
            }
        }

        // An executable providing its own copy of a single library symbol is a
        // legitimate pattern, not an ambiguous resolution.
        bool only_in_main = (strong_candidate_libs.size() == 2 &&
            strong_candidate_libs.count(main_executable_path_) != 0);

        if (strong_candidate_libs.size() > 1 && !only_in_main) {
            std::string warning = "ERROR " + entry.symbol_name + " found in multiple paths (";
            bool first = true;
            for (const auto& lib : strong_candidate_libs) {
                if (!first) warning += ", ";
                warning += lib;
                first = false;
            }
            warning += ")";
            entry.warnings.push_back(warning);
        }
    }

    // ---- Alert 2: illegitimate resolution (the hijack detector) -------------
    // Check the definition the GOT slot actually resolves to against what the
    // loader's rules would allow. Not subject to the allowlist.
    if (entry.resolved_path == "[vdso]" ||
        entry.resolved_path == entry.source_path ||
        indexed_paths_.find(entry.resolved_path) == indexed_paths_.end()) {
        return;
    }

    std::vector<const SymbolDefLoc*> resolved_defs;
    if (defs) {
        for (const auto& def : *defs) {
            if (def.path == entry.resolved_path) {
                resolved_defs.push_back(&def);
            }
        }
    }

    // (a) The resolved library does not define this symbol at all.
    if (resolved_defs.empty()) {
        entry.warnings.push_back("ERROR " + entry.symbol_name +
                                 " not exported by " + entry.resolved_path);
        return;
    }

    // (b)/(c) No definition in the resolved library can legally satisfy the
    // reference: version mismatch (versioned ref), or a non-default node captured
    // an unversioned ref.
    bool resolved_can_satisfy = false;
    bool resolved_has_strong = false;
    for (const auto* def : resolved_defs) {
        if (def_satisfies_ref(*def, entry.ref_versioned, entry.ref_version)) {
            resolved_can_satisfy = true;
            if (def->bind == STB_GLOBAL) {
                resolved_has_strong = true;
            }
        }
    }

    if (!resolved_can_satisfy) {
        if (entry.ref_versioned) {
            entry.warnings.push_back("ERROR " + entry.symbol_name +
                " resolved to " + entry.resolved_path +
                " which does not provide version " + entry.ref_version +
                " (nor an unversioned definition)");
        } else {
            entry.warnings.push_back("ERROR " + entry.symbol_name +
                " resolved to a non-default version in " + entry.resolved_path +
                " for an unversioned reference");
        }
        return;
    }

    // (d) The resolved definition is only weak, yet a strong definition that can
    // satisfy the reference exists elsewhere. The loader prefers strong
    // regardless of load order, so this binding is anomalous.
    if (!resolved_has_strong && defs) {
        for (const auto& def : *defs) {
            if (def.path != entry.resolved_path &&
                def.bind == STB_GLOBAL &&
                def_satisfies_ref(def, entry.ref_versioned, entry.ref_version)) {
                entry.warnings.push_back("ERROR " + entry.symbol_name +
                    " resolved to a weak definition in " + entry.resolved_path +
                    " while a strong definition exists in " + def.path);
                break;
            }
        }
    }
}
