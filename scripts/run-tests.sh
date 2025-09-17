#!/bin/bash

# GhostWire Test Runner Script
# This script provides convenient commands for running different types of tests

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
VERBOSE=false
REPORT=false
FORMAT="text"
PARALLELISM=4
TIMEOUT=300

# Functions
print_usage() {
    echo "GhostWire Test Runner"
    echo ""
    echo "Usage: $0 [OPTIONS] [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  unit                 Run unit tests"
    echo "  integration          Run integration tests"
    echo "  performance          Run performance benchmarks"
    echo "  scenarios            Run scenario tests"
    echo "  all                  Run all tests"
    echo "  quick                Run quick smoke tests"
    echo "  ci                   Run CI test suite"
    echo ""
    echo "Options:"
    echo "  -v, --verbose        Enable verbose output"
    echo "  -r, --report         Generate test reports"
    echo "  -f, --format FORMAT  Output format (text, json, html)"
    echo "  -j, --parallelism N  Number of parallel test instances"
    echo "  -t, --timeout N      Test timeout in seconds"
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 unit                           # Run unit tests"
    echo "  $0 integration --verbose          # Run integration tests with verbose output"
    echo "  $0 performance --report --format html  # Run benchmarks and generate HTML report"
    echo "  $0 all --report                   # Run all tests and generate reports"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check if we're in the right directory
    if [[ ! -f "Cargo.toml" ]] || [[ ! -d "crates/ghostwire-tests" ]]; then
        log_error "This script must be run from the GhostWire project root directory"
        exit 1
    fi

    # Check Rust installation
    if ! command -v cargo &> /dev/null; then
        log_error "Cargo not found. Please install Rust: https://rustup.rs/"
        exit 1
    fi

    # Check if ghostwire-tests crate exists
    if [[ ! -f "crates/ghostwire-tests/Cargo.toml" ]]; then
        log_error "ghostwire-tests crate not found"
        exit 1
    fi

    log_success "Prerequisites check passed"
}

build_project() {
    log_info "Building GhostWire project..."
    if $VERBOSE; then
        cargo build --workspace
    else
        cargo build --workspace --quiet
    fi
    log_success "Build completed"
}

run_unit_tests() {
    log_info "Running unit tests..."
    local cmd="cargo test --workspace"

    if $VERBOSE; then
        cmd="$cmd --verbose"
    fi

    if eval "$cmd"; then
        log_success "Unit tests passed"
    else
        log_error "Unit tests failed"
        exit 1
    fi
}

run_integration_tests() {
    log_info "Running integration tests..."
    local cmd="cargo run --bin test_runner -- --integration"

    if $VERBOSE; then
        cmd="$cmd --verbose"
    fi

    if $REPORT; then
        cmd="$cmd --report --format $FORMAT"
    fi

    cmd="$cmd --parallelism $PARALLELISM --timeout $TIMEOUT"

    if eval "$cmd"; then
        log_success "Integration tests passed"
    else
        log_error "Integration tests failed"
        exit 1
    fi
}

run_performance_tests() {
    log_info "Running performance benchmarks..."
    local cmd="cargo run --bin test_runner -- --performance"

    if $VERBOSE; then
        cmd="$cmd --verbose"
    fi

    if $REPORT; then
        cmd="$cmd --report --format $FORMAT"
    fi

    cmd="$cmd --parallelism $PARALLELISM --timeout $TIMEOUT"

    if eval "$cmd"; then
        log_success "Performance benchmarks completed"
    else
        log_error "Performance benchmarks failed"
        exit 1
    fi
}

run_scenario_tests() {
    log_info "Running scenario tests..."
    local cmd="cargo run --bin test_runner -- --scenarios"

    if $VERBOSE; then
        cmd="$cmd --verbose"
    fi

    if $REPORT; then
        cmd="$cmd --report --format $FORMAT"
    fi

    cmd="$cmd --parallelism $PARALLELISM --timeout $TIMEOUT"

    if eval "$cmd"; then
        log_success "Scenario tests passed"
    else
        log_error "Scenario tests failed"
        exit 1
    fi
}

run_all_tests() {
    log_info "Running all tests..."
    local cmd="cargo run --bin test_runner -- --all"

    if $VERBOSE; then
        cmd="$cmd --verbose"
    fi

    if $REPORT; then
        cmd="$cmd --report --format $FORMAT"
    fi

    cmd="$cmd --parallelism $PARALLELISM --timeout $TIMEOUT"

    if eval "$cmd"; then
        log_success "All tests passed"
    else
        log_error "Some tests failed"
        exit 1
    fi
}

run_quick_tests() {
    log_info "Running quick smoke tests..."

    # Run a subset of unit tests
    log_info "Running core unit tests..."
    cargo test --package ghostwire-common --quiet
    cargo test --package ghostwire-server --lib --quiet

    # Run basic integration test
    log_info "Running basic integration test..."
    cargo run --bin test_runner -- --integration --timeout 60 --parallelism 1

    log_success "Quick tests completed"
}

run_ci_tests() {
    log_info "Running CI test suite..."

    # Set CI-friendly defaults
    export GHOSTWIRE_TEST_PARALLELISM=2
    export GHOSTWIRE_TEST_TIMEOUT=300

    # Run tests with JSON output for CI processing
    local cmd="cargo run --bin test_runner -- --all --report --format json"
    cmd="$cmd --parallelism 2 --timeout 300"

    if eval "$cmd"; then
        log_success "CI tests passed"
    else
        log_error "CI tests failed"
        exit 1
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -r|--report)
            REPORT=true
            shift
            ;;
        -f|--format)
            FORMAT="$2"
            shift 2
            ;;
        -j|--parallelism)
            PARALLELISM="$2"
            shift 2
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        unit|integration|performance|scenarios|all|quick|ci)
            COMMAND="$1"
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

# Validate format
if [[ "$FORMAT" != "text" && "$FORMAT" != "json" && "$FORMAT" != "html" ]]; then
    log_error "Invalid format: $FORMAT. Must be text, json, or html"
    exit 1
fi

# Default command if none specified
if [[ -z "$COMMAND" ]]; then
    COMMAND="quick"
fi

# Main execution
main() {
    log_info "Starting GhostWire test runner..."
    log_info "Command: $COMMAND"
    log_info "Verbose: $VERBOSE"
    log_info "Report: $REPORT"
    log_info "Format: $FORMAT"
    log_info "Parallelism: $PARALLELISM"
    log_info "Timeout: ${TIMEOUT}s"
    echo ""

    check_prerequisites
    build_project

    case $COMMAND in
        unit)
            run_unit_tests
            ;;
        integration)
            run_integration_tests
            ;;
        performance)
            run_performance_tests
            ;;
        scenarios)
            run_scenario_tests
            ;;
        all)
            run_all_tests
            ;;
        quick)
            run_quick_tests
            ;;
        ci)
            run_ci_tests
            ;;
        *)
            log_error "Unknown command: $COMMAND"
            print_usage
            exit 1
            ;;
    esac

    echo ""
    log_success "Test runner completed successfully!"

    if $REPORT; then
        log_info "Test reports generated:"
        ls -la ghostwire-test-report-*.* 2>/dev/null || log_info "No report files found"
    fi
}

# Run main function
main "$@"