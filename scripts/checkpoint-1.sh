#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

LOG="checkpoints/checkpoint-1.log"
mkdir -p checkpoints

log_result() {
    local step="$1"
    local status="$2"
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    {
        echo "=== ${ts} ${step}: ${status} ==="
    } >> "$LOG"
}

fail() {
    local step="$1"
    local output="$2"
    echo "FAIL: ${step}"
    if [ -n "${output}" ]; then
        echo "${output}"
    fi
    log_result "${step}" "FAIL"
    exit 1
}

pass() {
    local step="$1"
    echo "PASS: ${step}"
    log_result "${step}" "PASS"
}

echo "Step 1/5: gofmt (gofmt -l .)"
if GOFMT_OUT="$(gofmt -l . 2>&1)"; then
    if [ -n "${GOFMT_OUT}" ]; then
        fail "gofmt" "${GOFMT_OUT}"
    else
        pass "gofmt"
    fi
else
    fail "gofmt" "${GOFMT_OUT}"
fi

echo "Step 2/5: go vet (go vet ./...)"
if VET_OUT="$(go vet ./... 2>&1)"; then
    pass "go vet"
else
    fail "go vet" "${VET_OUT}"
fi

echo "Step 3/5: golangci-lint (golangci-lint run ./...)"
if LINT_OUT="$(golangci-lint run ./... 2>&1)"; then
    pass "golangci-lint"
else
    fail "golangci-lint" "${LINT_OUT}"
fi

echo "Step 4/5: clang-format (clang-format --dry-run --Werror bpf/probe.c bpf/lsm.c bpf/headers/common.h)"
if CLANG_OUT="$(clang-format --dry-run --Werror bpf/probe.c bpf/lsm.c bpf/headers/common.h 2>&1)"; then
    pass "clang-format"
else
    fail "clang-format" "${CLANG_OUT}"
fi

echo "Step 5/5: go test -race (go test -race -count=1 ./internal/...)"
if TEST_OUT="$(go test -race -count=1 ./internal/... 2>&1)"; then
    echo "${TEST_OUT}"
    pass "go test -race"
else
    fail "go test -race" "${TEST_OUT}"
fi
