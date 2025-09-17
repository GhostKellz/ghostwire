# GhostWire Tests

Comprehensive integration tests and performance benchmarks for the GhostWire mesh VPN system.

## Overview

This crate provides a complete testing framework for GhostWire, including:

- **Integration Tests**: End-to-end testing across all components
- **Performance Benchmarks**: Detailed performance analysis and regression testing
- **Scenario Tests**: Real-world usage patterns and edge cases
- **Load Testing**: Stress testing under various conditions
- **Chaos Engineering**: Fault injection and resilience testing

## Quick Start

### Running All Tests

```bash
# Run all test suites
cargo run --bin test_runner -- --all

# Run specific test suites
cargo run --bin test_runner -- --integration
cargo run --bin test_runner -- --performance
cargo run --bin test_runner -- --scenarios
```

### Running Individual Test Categories

```bash
# Integration tests
cargo test --lib integration

# Performance benchmarks
cargo bench

# Specific benchmarks
cargo bench network_throughput
cargo bench encryption_performance
cargo bench connection_establishment
cargo bench mesh_scaling
cargo bench derp_relay_performance
```

### Generating Reports

```bash
# Generate HTML report
cargo run --bin test_runner -- --all --report --format html

# Generate JSON report
cargo run --bin test_runner -- --all --report --format json

# Verbose output with detailed metrics
cargo run --bin test_runner -- --all --verbose
```

## Test Structure

### Integration Tests (`src/integration/`)

- **Server Tests**: Server startup, API endpoints, concurrent connections
- **Authentication Tests**: JWT validation, OIDC integration, session management
- **Database Tests**: CRUD operations, migrations, connection pooling
- **DERP Tests**: Relay functionality, NAT traversal, connection establishment
- **DNS Tests**: MagicDNS resolution, split-DNS configuration
- **Mesh Tests**: Node registration, network topology, scaling behavior

### Performance Benchmarks (`benches/`)

- **Network Throughput**: API request rates, concurrent connection handling
- **Encryption Performance**: Key generation, encryption/decryption speeds
- **Connection Establishment**: Server startup, client connection times
- **Mesh Scaling**: Registration performance with increasing node counts
- **DERP Relay Performance**: Relay server throughput and latency

### Scenarios (`src/scenarios.rs`)

- **Small Team Setup**: Typical 5-person team mesh network
- **Remote Worker**: Adding external workers to existing mesh
- **Network Partition Recovery**: Handling network splits and healing
- **High Churn**: Rapid node joins/leaves testing

### Utilities (`src/utils.rs`)

- **Test Environment**: Setup and teardown helpers
- **Load Testing**: Concurrent request generation
- **Chaos Testing**: Fault injection utilities
- **Resource Monitoring**: Memory and CPU tracking
- **Performance Tracking**: Metrics collection and analysis

## Configuration

### Environment Variables

```bash
# Test configuration
export GHOSTWIRE_TEST_VERBOSE=1          # Enable verbose logging
export GHOSTWIRE_TEST_PARALLELISM=8      # Number of parallel test instances
export GHOSTWIRE_TEST_TIMEOUT=300        # Test timeout in seconds
export GHOSTWIRE_TEST_PROFILE=1          # Enable performance profiling
export GHOSTWIRE_TEST_DATA_DIR=/tmp/test  # Test data directory

# Chaos testing
export GHOSTWIRE_CHAOS_FAILURE_RATE=0.01    # 1% failure rate
export GHOSTWIRE_CHAOS_DELAY_RATE=0.05      # 5% delay rate
export GHOSTWIRE_CHAOS_MAX_DELAY_MS=100     # Max delay in milliseconds
```

### Test Runner Options

```
OPTIONS:
    --integration         Run integration tests
    --performance         Run performance tests
    --scenarios          Run scenario tests
    --all                Run all test suites
    --verbose            Enable verbose logging
    --parallelism <N>    Number of parallel test instances
    --timeout <SECS>     Test timeout in seconds
    --profile            Enable performance profiling
    --data-dir <PATH>    Test data directory
    --report             Generate detailed reports
    --format <FORMAT>    Output format (text, json, html)
```

## Benchmark Results

### Example Performance Metrics

```
Crypto Performance:
  Key Generation: 15,234 ops/sec, avg 0.07ms
  Encryption (4KB): 45,678 ops/sec, 890 MB/s
  Decryption (4KB): 46,123 ops/sec, 901 MB/s

Network Performance:
  API Throughput: 12,345 requests/sec
  Connection Establishment: 234 connections/sec, avg 4.3ms
  Concurrent Connections (50): 8,901 requests/sec

Mesh Scaling:
  10 nodes: 45ms registration, 12ms netmap generation
  50 nodes: 187ms registration, 34ms netmap generation
  100 nodes: 398ms registration, 67ms netmap generation
```

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: GhostWire Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rs/toolchain@v1
        with:
          toolchain: stable

      # Run integration tests
      - name: Integration Tests
        run: cargo run --bin test_runner -- --integration --report --format json

      # Run performance benchmarks
      - name: Performance Tests
        run: cargo run --bin test_runner -- --performance --report --format json

      # Upload test results
      - uses: actions/upload-artifact@v3
        with:
          name: test-results
          path: ghostwire-test-report-*.json
```

## Advanced Usage

### Custom Test Scenarios

```rust
use ghostwire_tests::{TestSuite, TestConfig, TestResult};

struct MyCustomTestSuite;

#[async_trait::async_trait]
impl TestSuite for MyCustomTestSuite {
    fn name(&self) -> &str {
        "Custom Test Suite"
    }

    async fn run_tests(&self, config: &TestConfig) -> Result<Vec<TestResult>> {
        // Your custom test logic here
        Ok(vec![])
    }
}
```

### Load Testing

```rust
use ghostwire_tests::utils::load::{run_load_test, LoadTestConfig};

let config = LoadTestConfig {
    duration: Duration::from_secs(60),
    concurrent_users: 100,
    target_rate: Some(1000.0), // 1000 requests/sec
    ..Default::default()
};

let results = run_load_test("api_load_test", config, || async {
    // Your load test logic
    Ok(Duration::from_millis(10))
}).await?;
```

### Chaos Testing

```rust
use ghostwire_tests::utils::chaos::{chaos_test, ChaosConfig};

let config = ChaosConfig {
    failure_rate: 0.05,    // 5% failure rate
    delay_rate: 0.1,       // 10% delay rate
    max_delay_ms: 200,
    ..Default::default()
};

chaos_test("network_resilience", config, 1000, || {
    Box::new(async {
        // Your chaos test logic
        Ok(())
    })
}).await?;
```

## Troubleshooting

### Common Issues

1. **Port Conflicts**: Tests use dynamic port allocation, but conflicts can occur
   - Solution: Set `GHOSTWIRE_TEST_PARALLELISM=1` to run tests sequentially

2. **Resource Limits**: Large-scale tests may hit system limits
   - Solution: Increase ulimits or reduce test scale

3. **Flaky Tests**: Network timing issues in CI environments
   - Solution: Increase timeouts with `GHOSTWIRE_TEST_TIMEOUT=600`

4. **Memory Usage**: Performance tests may use significant memory
   - Solution: Monitor with `--profile` flag and adjust test parameters

### Debug Mode

```bash
# Enable debug logging for all components
RUST_LOG=debug cargo run --bin test_runner -- --all --verbose

# Enable debug logging for specific components
RUST_LOG=ghostwire_tests=debug,ghostwire_server=debug cargo test
```

## Contributing

When adding new tests:

1. **Integration Tests**: Add to appropriate module in `src/integration/`
2. **Benchmarks**: Create new files in `benches/` directory
3. **Scenarios**: Add realistic end-to-end scenarios to `src/scenarios.rs`
4. **Utilities**: Extend `src/utils.rs` with reusable testing components

### Performance Regression Testing

All benchmarks include performance regression detection:

- **Warning Threshold**: 10% performance degradation
- **Failure Threshold**: 25% performance degradation
- **Baseline**: Previous test run results

### Test Coverage

Target coverage levels:
- **Integration Tests**: 90%+ of API endpoints and major code paths
- **Performance Tests**: All critical performance-sensitive components
- **Scenario Tests**: Common real-world usage patterns
- **Edge Cases**: Error conditions and boundary conditions