#!/bin/bash
set -e

echo "Building got-audit..."

if [ ! -d "build" ]; then
    mkdir build
fi

cd build
cmake ..
make -j$(nproc)

echo ""
echo "Build complete! Binary is at: build/got-audit"
echo ""
echo "Usage: sudo ./build/got-audit [--all] <PID>"
