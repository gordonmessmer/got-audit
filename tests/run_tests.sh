#!/bin/bash
#
# Test suite for got-audit
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
AUDIT_BIN="$PROJECT_DIR/build/got-audit"
TEST_PROGRAM="$SCRIPT_DIR/test_program"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

# Helper functions
pass() {
    echo -e "${GREEN}✓${NC} $1"
    ((TESTS_PASSED++))
}

fail() {
    echo -e "${RED}✗${NC} $1"
    ((TESTS_FAILED++))
}

info() {
    echo -e "${YELLOW}ℹ${NC} $1"
}

# Build test program
build_test_program() {
    info "Building test program..."
    gcc -o "$TEST_PROGRAM" "$SCRIPT_DIR/test_program.c" -Wall -Wextra
    if [ $? -eq 0 ]; then
        pass "Test program compiled"
    else
        fail "Test program compilation failed"
        exit 1
    fi
}

# Test 1: Verify got-audit binary exists
test_binary_exists() {
    if [ -f "$AUDIT_BIN" ]; then
        pass "got-audit binary exists"
    else
        fail "got-audit binary not found at $AUDIT_BIN"
        echo "Run ./build.sh first"
        exit 1
    fi
}

# Test 2: Test --help flag
test_help_flag() {
    if "$AUDIT_BIN" --help > /dev/null 2>&1; then
        pass "--help flag works"
    else
        fail "--help flag failed"
    fi
}

# Test 3: Test invalid PID
test_invalid_pid() {
    if ! "$AUDIT_BIN" 999999 > /dev/null 2>&1; then
        pass "Rejects invalid PID"
    else
        fail "Should fail on invalid PID"
    fi
}

# Test 4: Test auditing test program
test_audit_program() {
    info "Starting test program..."
    "$TEST_PROGRAM" > /dev/null 2>&1 &
    local pid=$!
    sleep 1

    if ! kill -0 $pid 2>/dev/null; then
        fail "Test program failed to start"
        return
    fi

    info "Auditing test program (PID: $pid)..."
    local output
    if [ "$(id -u)" -eq 0 ]; then
        output=$("$AUDIT_BIN" $pid 2>&1)
    else
        output=$(sudo "$AUDIT_BIN" $pid 2>&1)
    fi
    local ret=$?

    kill -TERM $pid 2>/dev/null
    wait $pid 2>/dev/null

    if [ $ret -eq 0 ]; then
        pass "Successfully audited test program"

        # Verify output contains expected elements
        if echo "$output" | grep -q "GOT protection:"; then
            pass "Output contains GOT protection status"
        else
            fail "Output missing GOT protection status"
        fi

        if echo "$output" | grep -q "GOT functions:"; then
            pass "Output contains GOT functions count"
        else
            fail "Output missing GOT functions count"
        fi

        # Should see standard C library functions
        if echo "$output" | grep -qE "(printf|strcpy|sleep|signal)"; then
            pass "Output contains expected library functions"
        else
            fail "Output missing expected library functions"
        fi

        # Should resolve to libc
        if echo "$output" | grep -q "libc.so"; then
            pass "Output shows libc.so resolution"
        else
            fail "Output missing libc.so resolution"
        fi
    else
        fail "Failed to audit test program"
        echo "$output"
    fi
}

# Test 5: Test --all flag
test_all_flag() {
    info "Starting test program for --all test..."
    "$TEST_PROGRAM" > /dev/null 2>&1 &
    local pid=$!
    sleep 1

    if ! kill -0 $pid 2>/dev/null; then
        fail "Test program failed to start for --all test"
        return
    fi

    info "Testing --all flag (PID: $pid)..."
    local output
    if [ "$(id -u)" -eq 0 ]; then
        output=$("$AUDIT_BIN" --all $pid 2>&1)
    else
        output=$(sudo "$AUDIT_BIN" --all $pid 2>&1)
    fi
    local ret=$?

    kill -TERM $pid 2>/dev/null
    wait $pid 2>/dev/null

    if [ $ret -eq 0 ]; then
        # With --all flag, should see multiple libraries audited
        local lib_count=$(echo "$output" | grep -c "════════════════════════════════════════════════════════════════" || true)
        if [ $lib_count -gt 1 ]; then
            pass "--all flag audits multiple libraries (found $lib_count)"
        else
            fail "--all flag should audit multiple libraries (found only $lib_count)"
        fi
    else
        fail "Failed to run with --all flag"
    fi
}

# Test 6: Check for false positive duplicate warnings
test_no_false_duplicates() {
    info "Testing for false positive duplicate warnings..."
    "$TEST_PROGRAM" > /dev/null 2>&1 &
    local pid=$!
    sleep 1

    if ! kill -0 $pid 2>/dev/null; then
        fail "Test program failed to start for duplicate test"
        return
    fi

    local output
    if [ "$(id -u)" -eq 0 ]; then
        output=$("$AUDIT_BIN" $pid 2>&1)
    else
        output=$(sudo "$AUDIT_BIN" $pid 2>&1)
    fi

    kill -TERM $pid 2>/dev/null
    wait $pid 2>/dev/null

    # Count ERROR messages (should be 0 or very few for a simple program)
    local error_count=$(echo "$output" | grep -c "ERROR" || true)
    if [ $error_count -eq 0 ]; then
        pass "No false positive duplicate errors"
    else
        fail "Found $error_count ERROR messages (may be false positives)"
        echo "$output" | grep "ERROR"
    fi
}

# Test 7: Verify man page exists
test_man_page() {
    if [ -f "$PROJECT_DIR/got-audit.1" ]; then
        pass "Man page exists"

        # Try to render it to check syntax (only if man is available)
        if command -v man > /dev/null 2>&1; then
            if man -l "$PROJECT_DIR/got-audit.1" > /dev/null 2>&1; then
                pass "Man page syntax is valid"
            else
                fail "Man page has syntax errors"
            fi
        else
            info "man command not available, skipping syntax check"
        fi
    else
        fail "Man page not found"
    fi
}

# Main test execution
main() {
    echo "======================================"
    echo "  got-audit Test Suite"
    echo "======================================"
    echo ""

    test_binary_exists
    build_test_program
    test_help_flag
    test_invalid_pid
    test_audit_program
    test_all_flag
    test_no_false_duplicates
    test_man_page

    # Cleanup
    rm -f "$TEST_PROGRAM"

    # Summary
    echo ""
    echo "======================================"
    echo "  Test Results"
    echo "======================================"
    echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
    echo -e "${RED}Failed: $TESTS_FAILED${NC}"
    echo ""

    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}Some tests failed!${NC}"
        exit 1
    fi
}

main "$@"
