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

const std::set<std::string> GotAuditor::expected_duplicates_ = {
    "__cxa_finalize",
    "copysign", "copysignf", "copysignl", "__finite", "finite",
    "__finitef", "finitef", "__finitel", "finitel", "frexp",
    "frexpf", "frexpl", "ldexp", "ldexpf", "ldexpl", "modf",
    "modff", "modfl", "scalbn", "scalbnf", "scalbnl", "__signbit",
    "__signbitf", "__signbitl",
    "fgetxattr", "flistxattr", "fremovexattr", "fsetxattr",
    "getxattr", "lgetxattr", "listxattr", "llistxattr",
    "lremovexattr", "lsetxattr", "removexattr", "setxattr",
    "authdes_create", "authdes_pk_create", "_authenticate",
    "authnone_create", "authunix_create",
    "authunix_create_default", "bindresvport", "callrpc",
    "clnt_broadcast", "clnt_create", "clnt_pcreateerror",
    "clnt_perrno", "clnt_perror", "clntraw_create",
    "clnt_spcreateerror", "clnt_sperrno", "clnt_sperror",
    "clnttcp_create", "clntudp_bufcreate", "clntudp_create",
    "clntunix_create", "get_myaddress", "getnetname",
    "getpublickey", "getrpcport", "host2netname",
    "key_decryptsession", "key_decryptsession_pk",
    "key_encryptsession", "key_encryptsession_pk", "key_gendes",
    "key_get_conv", "key_secretkey_is_set", "key_setnet",
    "key_setsecret", "__libc_clntudp_bufcreate", "netname2host",
    "netname2user", "pmap_getmaps", "pmap_getport",
    "pmap_rmtcall", "pmap_set", "pmap_unset", "registerrpc",
    "_rpc_dtablesize", "rtime", "_seterr_reply", "svcerr_auth",
    "svcerr_decode", "svcerr_noproc", "svcerr_noprog",
    "svcerr_progvers", "svcerr_systemerr", "svcerr_weakauth",
    "svc_exit", "svcfd_create", "svc_getreq", "svc_getreq_common",
    "svc_getreq_poll", "svc_getreqset", "svcraw_create",
    "svc_register", "svc_run", "svc_sendreply", "svctcp_create",
    "svcudp_bufcreate", "svcudp_create", "svcunix_create",
    "svcunixfd_create", "svc_unregister", "user2netname",
    "xdr_accepted_reply", "xdr_array", "xdr_authunix_parms",
    "xdr_bool", "xdr_bytes", "xdr_callhdr", "xdr_callmsg",
    "xdr_char", "xdr_cryptkeyarg", "xdr_cryptkeyarg2",
    "xdr_cryptkeyres", "xdr_des_block", "xdr_double", "xdr_enum",
    "xdr_float", "xdr_free", "xdr_getcredres", "xdr_hyper",
    "xdr_int", "xdr_int16_t", "xdr_int32_t", "xdr_int64_t",
    "xdr_int8_t", "xdr_keybuf", "xdr_key_netstarg",
    "xdr_key_netstres", "xdr_keystatus", "xdr_long",
    "xdr_longlong_t", "xdrmem_create", "xdr_netnamestr",
    "xdr_netobj", "xdr_opaque", "xdr_opaque_auth", "xdr_pmap",
    "xdr_pmaplist", "xdr_pointer", "xdr_quad_t", "xdrrec_create",
    "xdrrec_endofrecord", "xdrrec_eof", "xdrrec_skiprecord",
    "xdr_reference", "xdr_rejected_reply", "xdr_replymsg",
    "xdr_rmtcall_args", "xdr_rmtcallres", "xdr_short",
    "xdr_sizeof", "xdrstdio_create", "xdr_string", "xdr_u_char",
    "xdr_u_hyper", "xdr_u_int", "xdr_uint16_t", "xdr_uint32_t",
    "xdr_uint64_t", "xdr_uint8_t", "xdr_u_long",
    "xdr_u_longlong_t", "xdr_union", "xdr_unixcred",
    "xdr_u_quad_t", "xdr_u_short", "xdr_vector", "xdr_void",
    "xdr_wrapstring", "xprt_register", "xprt_unregister",
    "_plug_buf_alloc", "_plug_challenge_prompt", "_plug_decode",
    "_plug_decode_free", "_plug_decode_init", "_plug_find_prompt",
    "_plug_free_secret", "_plug_free_string",
    "_plug_get_error_message", "_plug_get_password",
    "_plug_get_realm", "_plug_get_simple", "_plug_iovec_to_buf",
    "_plug_ipfromstring", "_plug_make_fulluser",
    "_plug_make_prompts", "_plug_parseuser",
    "_plug_snprintf_os_info", "_plug_strdup",
    "__b64_ntop", "__b64_pton"
};

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
    if (paths_to_symbols_.find(path) != paths_to_symbols_.end()) {
        return;
    }

    ElfParser parser(path);
    if (!parser.parse()) {
        return;
    }

    std::vector<std::string> symbols = parser.get_exported_symbols();
    paths_to_symbols_[path] = symbols;

    for (const auto& symbol : symbols) {
        symbols_to_paths_[symbol].push_back(path);
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

    auto& paths = symbols_to_paths_[entry.symbol_name];
    if (paths.size() > 1 && expected_duplicates_.find(entry.symbol_name) == expected_duplicates_.end()) {
        bool only_in_main = (paths.size() == 2 &&
            (std::find(paths.begin(), paths.end(), main_executable_path_) != paths.end()));

        if (!only_in_main) {
            std::string warning = "ERROR " + entry.symbol_name + " found in multiple paths (";
            for (size_t i = 0; i < paths.size(); i++) {
                if (i > 0) warning += ", ";
                warning += paths[i];
            }
            warning += ")";
            entry.warnings.push_back(warning);
        }
    }

    if (entry.resolved_path != "[vdso]" &&
        entry.resolved_path != entry.source_path) {

        auto it = paths_to_symbols_.find(entry.resolved_path);
        if (it != paths_to_symbols_.end()) {
            const auto& exported = it->second;
            if (std::find(exported.begin(), exported.end(), entry.symbol_name) == exported.end()) {
                std::string warning = "ERROR " + entry.symbol_name +
                                    " not exported by " + entry.resolved_path;
                entry.warnings.push_back(warning);
            }
        }
    }
}
