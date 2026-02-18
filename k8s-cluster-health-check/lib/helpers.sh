#!/usr/bin/env bash
# Helper functions for health check output
# Provides consistent output formatting and counters

# Mark as loaded to prevent double-sourcing
export HEALTH_CHECK_HELPERS_LOADED=1

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Counters (exported for sub-scripts)
export TOTAL_CHECKS=${TOTAL_CHECKS:-0}
export PASSED_CHECKS=${PASSED_CHECKS:-0}
export WARNINGS=${WARNINGS:-0}
export FAILURES=${FAILURES:-0}

# Output functions
pass() {
    echo -e "  ${GREEN}✅${NC} $1"
    ((PASSED_CHECKS++)) || true
    ((TOTAL_CHECKS++)) || true
    export PASSED_CHECKS TOTAL_CHECKS
}

warn() {
    echo -e "  ${YELLOW}⚠️${NC}  $1"
    ((WARNINGS++)) || true
    ((TOTAL_CHECKS++)) || true
    export WARNINGS TOTAL_CHECKS
}

fail() {
    echo -e "  ${RED}❌${NC} $1"
    ((FAILURES++)) || true
    ((TOTAL_CHECKS++)) || true
    export FAILURES TOTAL_CHECKS
}

info() {
    echo -e "  ${BLUE}ℹ️${NC}  $1"
}

header() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
}

subheader() {
    echo -e "\n${YELLOW}── $1 ──${NC}"
}
