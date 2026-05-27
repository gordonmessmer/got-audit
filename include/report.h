/*
 * got-audit - Report generation interface
 *
 * SPDX-License-Identifier: MIT
 *
 * This is a machine-generated C++ port of the "got-audit" command from GEF
 * (GDB Enhanced Features), created by Claude (Anthropic AI) in 2026.
 *
 * Original GEF project: https://github.com/hugsy/gef
 *   Copyright (c) 2013-2025 crazy rabbidz
 */

#ifndef REPORT_H
#define REPORT_H

#include "got_auditor.h"
#include <vector>
#include <string>

class Report {
public:
    static void print_got_report(
        const std::string& path,
        const std::vector<GotEntry>& entries,
        bool has_full_relro,
        bool has_partial_relro
    );

private:
    static std::string colorize(const std::string& text, const std::string& color);
    static const char* RESET;
    static const char* GREEN;
    static const char* YELLOW;
    static const char* RED;
    static const char* CYAN;
    static const char* BOLD;
};

#endif // REPORT_H
