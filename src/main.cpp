/*
 * got-audit - Audit the Global Offset Table of running processes
 *
 * SPDX-License-Identifier: MIT
 *
 * This is a machine-generated C++ port of the "got-audit" command from GEF
 * (GDB Enhanced Features), created by Claude (Anthropic AI) in 2026.
 *
 * Original GEF project: https://github.com/hugsy/gef
 *   Copyright (c) 2013-2025 crazy rabbidz
 *
 * This port is based on the GotAuditCommand implementation in gef/gef.py.
 */

#include "elf_parser.h"
#include "process_memory.h"
#include "got_auditor.h"
#include "report.h"
#include <iostream>
#include <getopt.h>
#include <unistd.h>
#include <cstdlib>

void print_version() {
    std::cout << "got-audit version 1.0.0\n"
              << "Machine-generated C++ port of GEF's got-audit command\n"
              << "Original GEF: https://github.com/hugsy/gef (MIT License)\n"
              << "This port: Copyright (c) 2026 Contributors (MIT License)\n";
}

void print_usage(const char* program_name) {
    std::cerr << "Usage: " << program_name << " [OPTIONS] <PID>\n"
              << "\n"
              << "Audit the Global Offset Table of a running process.\n"
              << "\n"
              << "OPTIONS:\n"
              << "  --all, -a       Audit GOT for all mapped ELF objects (not just main executable)\n"
              << "  --help, -h      Show this help message\n"
              << "  --version, -v   Show version information\n"
              << "\n"
              << "ARGUMENTS:\n"
              << "  <PID>        Process ID to audit\n"
              << "\n"
              << "DESCRIPTION:\n"
              << "  This tool examines the Global Offset Table (GOT) of a running process\n"
              << "  to identify potential security issues such as:\n"
              << "    - Symbols resolving to unexpected libraries\n"
              << "    - Duplicate symbol definitions across libraries\n"
              << "    - Symbols not exported by the target library\n"
              << "\n"
              << "EXAMPLES:\n"
              << "  " << program_name << " 1234          # Audit main executable of PID 1234\n"
              << "  " << program_name << " --all 1234   # Audit all ELF objects in PID 1234\n"
              << std::endl;
}

int main(int argc, char* argv[]) {
    bool audit_all = false;
    pid_t pid = 0;

    static struct option long_options[] = {
        {"all",     no_argument, nullptr, 'a'},
        {"help",    no_argument, nullptr, 'h'},
        {"version", no_argument, nullptr, 'v'},
        {nullptr, 0, nullptr, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "ahv", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'a':
                audit_all = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'v':
                print_version();
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (optind >= argc) {
        std::cerr << "Error: Missing PID argument\n\n";
        print_usage(argv[0]);
        return 1;
    }

    pid = std::atoi(argv[optind]);
    if (pid <= 0) {
        std::cerr << "Error: Invalid PID: " << argv[optind] << "\n";
        return 1;
    }

    if (geteuid() != 0) {
        std::cerr << "Warning: This tool requires root privileges to attach to processes.\n";
        std::cerr << "         If attachment fails, try running with sudo.\n\n";
    }

    ProcessMemory proc_mem(pid);
    if (!proc_mem.attach()) {
        std::cerr << "Failed to attach to process " << pid << "\n";
        return 1;
    }

    std::cout << "Successfully attached to process " << pid << "\n";

    GotAuditor auditor(proc_mem, audit_all);
    if (!auditor.build_symbol_index()) {
        std::cerr << "Failed to build symbol index\n";
        proc_mem.detach();
        return 1;
    }

    std::string main_executable_path;
    for (const auto& mapping : proc_mem.get_memory_maps()) {
        if (!mapping.path.empty() && mapping.path[0] == '/' && mapping.is_executable()) {
            main_executable_path = mapping.path;
            break;
        }
    }

    if (main_executable_path.empty()) {
        std::cerr << "Could not determine main executable path\n";
        proc_mem.detach();
        return 1;
    }

    std::vector<std::string> paths_to_audit;

    if (audit_all) {
        std::set<std::string> unique_paths;
        for (const auto& mapping : proc_mem.get_memory_maps()) {
            if (!mapping.path.empty() && mapping.path[0] == '/' && mapping.is_executable()) {
                unique_paths.insert(mapping.path);
            }
        }
        paths_to_audit.assign(unique_paths.begin(), unique_paths.end());
    } else {
        paths_to_audit.push_back(main_executable_path);
    }

    for (const auto& path : paths_to_audit) {
        ElfParser parser(path);
        if (!parser.parse()) {
            std::cerr << "Failed to parse: " << path << "\n";
            continue;
        }

        std::vector<GotEntry> entries = auditor.audit_got(path);

        Report::print_got_report(
            path,
            entries,
            parser.has_full_relro(),
            parser.has_partial_relro()
        );
    }

    proc_mem.detach();
    std::cout << "Detached from process " << pid << "\n";

    return 0;
}
