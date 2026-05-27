/*
 * got-audit - Process memory reader
 *
 * SPDX-License-Identifier: MIT
 *
 * This is a machine-generated C++ port of the "got-audit" command from GEF
 * (GDB Enhanced Features), created by Claude (Anthropic AI) in 2026.
 *
 * Original GEF project: https://github.com/hugsy/gef
 *   Copyright (c) 2013-2025 crazy rabbidz
 *
 * Process attachment and memory reading using ptrace and /proc filesystem.
 */

#include "process_memory.h"
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <fstream>
#include <sstream>
#include <iostream>
#include <cstring>
#include <errno.h>

ProcessMemory::ProcessMemory(pid_t pid)
    : pid_(pid)
    , attached_(false) {
}

ProcessMemory::~ProcessMemory() {
    if (attached_) {
        detach();
    }
}

bool ProcessMemory::attach() {
    if (attached_) {
        return true;
    }

    if (ptrace(PTRACE_ATTACH, pid_, nullptr, nullptr) == -1) {
        std::cerr << "Failed to attach to process " << pid_
                  << ": " << strerror(errno) << std::endl;
        return false;
    }

    int status;
    if (waitpid(pid_, &status, 0) == -1) {
        std::cerr << "waitpid failed: " << strerror(errno) << std::endl;
        ptrace(PTRACE_DETACH, pid_, nullptr, nullptr);
        return false;
    }

    attached_ = true;

    if (!parse_maps()) {
        detach();
        return false;
    }

    return true;
}

void ProcessMemory::detach() {
    if (attached_) {
        ptrace(PTRACE_DETACH, pid_, nullptr, nullptr);
        attached_ = false;
    }
}

bool ProcessMemory::parse_maps() {
    std::string maps_path = "/proc/" + std::to_string(pid_) + "/maps";
    std::ifstream maps_file(maps_path);

    if (!maps_file.is_open()) {
        std::cerr << "Failed to open " << maps_path << std::endl;
        return false;
    }

    std::string line;
    while (std::getline(maps_file, line)) {
        MemoryMapping mapping;

        std::istringstream iss(line);
        std::string address_range;
        iss >> address_range;

        size_t dash_pos = address_range.find('-');
        if (dash_pos == std::string::npos) {
            continue;
        }

        mapping.start = std::stoull(address_range.substr(0, dash_pos), nullptr, 16);
        mapping.end = std::stoull(address_range.substr(dash_pos + 1), nullptr, 16);

        iss >> mapping.permissions;

        std::string offset_str;
        iss >> offset_str;
        mapping.offset = std::stoull(offset_str, nullptr, 16);

        iss >> mapping.device;
        iss >> mapping.inode;

        std::string path_part;
        if (iss >> std::ws && std::getline(iss, path_part)) {
            mapping.path = path_part;
        } else {
            mapping.path = "";
        }

        memory_maps_.push_back(mapping);
    }

    return true;
}

bool ProcessMemory::read_memory(uint64_t address, void* buffer, size_t size) {
    if (!attached_) {
        std::cerr << "Not attached to process" << std::endl;
        return false;
    }

    struct iovec local_iov;
    struct iovec remote_iov;

    local_iov.iov_base = buffer;
    local_iov.iov_len = size;
    remote_iov.iov_base = reinterpret_cast<void*>(address);
    remote_iov.iov_len = size;

    ssize_t nread = process_vm_readv(pid_, &local_iov, 1, &remote_iov, 1, 0);
    if (nread == -1) {
        return false;
    }

    return nread == static_cast<ssize_t>(size);
}

uint64_t ProcessMemory::read_uint64(uint64_t address) {
    uint64_t value = 0;
    if (!read_memory(address, &value, sizeof(value))) {
        return 0;
    }
    return value;
}

const MemoryMapping* ProcessMemory::find_mapping(uint64_t address) const {
    for (const auto& mapping : memory_maps_) {
        if (mapping.contains(address)) {
            return &mapping;
        }
    }
    return nullptr;
}

const MemoryMapping* ProcessMemory::find_mapping_by_path(const std::string& path) const {
    for (const auto& mapping : memory_maps_) {
        if (mapping.path == path) {
            return &mapping;
        }
    }
    return nullptr;
}
