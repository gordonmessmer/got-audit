/*
 * got-audit - Report generation
 *
 * SPDX-License-Identifier: MIT
 *
 * This is a machine-generated C++ port of the "got-audit" command from GEF
 * (GDB Enhanced Features), created by Claude (Anthropic AI) in 2026.
 *
 * Original GEF project: https://github.com/hugsy/gef
 *   Copyright (c) 2013-2025 crazy rabbidz
 *
 * Report formatting based on GEF's GotAuditCommand output style.
 */

#include "report.h"
#include <iostream>
#include <iomanip>
#include <sstream>

const char* Report::RESET = "\033[0m";
const char* Report::GREEN = "\033[32m";
const char* Report::YELLOW = "\033[33m";
const char* Report::RED = "\033[31m";
const char* Report::CYAN = "\033[36m";
const char* Report::BOLD = "\033[1m";

std::string Report::colorize(const std::string& text, const std::string& color) {
    return color + text + RESET;
}

void Report::print_got_report(
    const std::string& path,
    const std::vector<GotEntry>& entries,
    bool has_full_relro,
    bool has_partial_relro) {

    std::string relro_status;
    if (has_full_relro) {
        relro_status = colorize("Full RelRO", GREEN);
    } else if (has_partial_relro) {
        relro_status = colorize("Partial RelRO", YELLOW);
    } else {
        relro_status = colorize("No RelRO", RED);
    }

    std::cout << "\n" << colorize("════════════════════════════════════════════════════════════════", CYAN) << "\n";
    std::cout << colorize(path, BOLD) << "\n";
    std::cout << colorize("════════════════════════════════════════════════════════════════", CYAN) << "\n\n";
    std::cout << "GOT protection: " << relro_status
              << " | GOT functions: " << entries.size() << "\n\n";

    for (const auto& entry : entries) {
        std::string color;
        if (entry.is_resolved) {
            color = GREEN;
        } else {
            color = YELLOW;
        }

        std::cout << colorize(entry.symbol_name, color);
        std::cout << " : " << entry.resolved_path;

        if (!entry.warnings.empty()) {
            for (const auto& warning : entry.warnings) {
                std::cout << " :: " << colorize(warning, RED);
            }
        }

        std::cout << "\n";
    }

    std::cout << "\n";
}
