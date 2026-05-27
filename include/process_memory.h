/*
 * got-audit - Process memory reader interface
 *
 * SPDX-License-Identifier: MIT
 *
 * This is a machine-generated C++ port of the "got-audit" command from GEF
 * (GDB Enhanced Features), created by Claude (Anthropic AI) in 2026.
 *
 * Original GEF project: https://github.com/hugsy/gef
 *   Copyright (c) 2013-2025 crazy rabbidz
 */

#ifndef PROCESS_MEMORY_H
#define PROCESS_MEMORY_H

#include <string>
#include <vector>
#include <cstdint>

struct MemoryMapping {
    uint64_t start;
    uint64_t end;
    std::string permissions;
    uint64_t offset;
    std::string device;
    uint64_t inode;
    std::string path;

    bool is_executable() const {
        return permissions.length() >= 3 && permissions[2] == 'x';
    }

    bool contains(uint64_t addr) const {
        return addr >= start && addr < end;
    }
};

class ProcessMemory {
public:
    explicit ProcessMemory(pid_t pid);
    ~ProcessMemory();

    bool attach();
    void detach();

    std::vector<MemoryMapping> get_memory_maps() const { return memory_maps_; }
    bool read_memory(uint64_t address, void* buffer, size_t size);
    uint64_t read_uint64(uint64_t address);

    const MemoryMapping* find_mapping(uint64_t address) const;
    const MemoryMapping* find_mapping_by_path(const std::string& path) const;

private:
    pid_t pid_;
    bool attached_;
    std::vector<MemoryMapping> memory_maps_;

    bool parse_maps();
};

#endif // PROCESS_MEMORY_H
