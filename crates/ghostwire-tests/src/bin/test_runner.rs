//! Test runner for executing all GhostWire test suites

use anyhow::Result;
use clap::Parser;
use ghostwire_tests::{
    integration::IntegrationTestSuite,
    performance::PerformanceTestSuite,
    scenarios::ScenariosTestSuite,
    TestConfig, TestSuite,
};
use std::time::Instant;
use tracing::{info, error, Level};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Parser)]
#[command(name = "ghostwire-test-runner")]
#[command(about = "GhostWire comprehensive test runner")]
struct Args {
    /// Run integration tests
    #[arg(long)]
    integration: bool,

    /// Run performance tests
    #[arg(long)]
    performance: bool,

    /// Run scenario tests
    #[arg(long)]
    scenarios: bool,

    /// Run all test suites
    #[arg(long)]
    all: bool,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Number of parallel test instances
    #[arg(long, default_value = "4")]
    parallelism: usize,

    /// Test timeout in seconds
    #[arg(long, default_value = "300")]
    timeout: u64,

    /// Enable performance profiling
    #[arg(long)]
    profile: bool,

    /// Test data directory
    #[arg(long)]
    data_dir: Option<std::path::PathBuf>,

    /// Generate detailed reports
    #[arg(long)]
    report: bool,

    /// Output format (text, json, html)
    #[arg(long, default_value = "text")]
    format: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = if args.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::from_default_env()
                .add_directive(format!("ghostwire={}", log_level).parse()?)
                .add_directive(format!("ghostwire_tests={}", log_level).parse()?)
        )
        .init();

    info!("Starting GhostWire test runner");

    let config = TestConfig {
        verbose: args.verbose,
        parallelism: args.parallelism,
        timeout_secs: args.timeout,
        profile: args.profile,
        data_dir: args.data_dir,
    };

    let mut total_results = Vec::new();
    let overall_start = Instant::now();

    // Determine which test suites to run
    let run_integration = args.integration || args.all;
    let run_performance = args.performance || args.all;
    let run_scenarios = args.scenarios || args.all;

    if !run_integration && !run_performance && !run_scenarios {
        error!("No test suites selected. Use --integration, --performance, --scenarios, or --all");
        std::process::exit(1);
    }

    // Run integration tests
    if run_integration {
        info!("Running integration test suite");
        let suite = IntegrationTestSuite;

        let start = Instant::now();
        match suite.run_tests(&config).await {
            Ok(mut results) => {
                let duration = start.elapsed();
                info!("Integration tests completed in {:?}", duration);
                total_results.append(&mut results);
            }
            Err(e) => {
                error!("Integration tests failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Run performance tests
    if run_performance {
        info!("Running performance test suite");
        let suite = PerformanceTestSuite;

        let start = Instant::now();
        match suite.run_tests(&config).await {
            Ok(mut results) => {
                let duration = start.elapsed();
                info!("Performance tests completed in {:?}", duration);
                total_results.append(&mut results);
            }
            Err(e) => {
                error!("Performance tests failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Run scenario tests
    if run_scenarios {
        info!("Running scenario test suite");
        let suite = ScenariosTestSuite;

        let start = Instant::now();
        match suite.run_tests(&config).await {
            Ok(mut results) => {
                let duration = start.elapsed();
                info!("Scenario tests completed in {:?}", duration);
                total_results.append(&mut results);
            }
            Err(e) => {
                error!("Scenario tests failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    let overall_duration = overall_start.elapsed();

    // Generate report
    generate_report(&total_results, overall_duration, &args).await?;

    // Summary
    let passed = total_results.iter().filter(|r| r.success).count();
    let failed = total_results.iter().filter(|r| !r.success).count();
    let total = total_results.len();

    info!("Test run completed in {:?}", overall_duration);
    info!("Results: {}/{} passed, {} failed", passed, total, failed);

    if failed > 0 {
        error!("Some tests failed");
        std::process::exit(1);
    } else {
        info!("All tests passed!");
    }

    Ok(())
}

async fn generate_report(
    results: &[ghostwire_tests::TestResult],
    duration: std::time::Duration,
    args: &Args,
) -> Result<()> {
    match args.format.as_str() {
        "text" => generate_text_report(results, duration).await,
        "json" => generate_json_report(results, duration, args).await,
        "html" => generate_html_report(results, duration, args).await,
        _ => {
            error!("Unsupported format: {}", args.format);
            std::process::exit(1);
        }
    }
}

async fn generate_text_report(
    results: &[ghostwire_tests::TestResult],
    duration: std::time::Duration,
) -> Result<()> {
    println!("\n=== GhostWire Test Report ===\n");

    println!("Overall Duration: {:?}", duration);
    println!("Total Tests: {}", results.len());

    let passed = results.iter().filter(|r| r.success).count();
    let failed = results.iter().filter(|r| !r.success).count();

    println!("Passed: {}", passed);
    println!("Failed: {}", failed);
    println!("Success Rate: {:.1}%", (passed as f64 / results.len() as f64) * 100.0);

    if !results.is_empty() {
        println!("\n--- Test Results ---\n");

        for result in results {
            let status = if result.success { "PASS" } else { "FAIL" };
            println!("{:8} {} ({} ms)", status, result.name, result.duration_ms);

            if !result.success {
                if let Some(error) = &result.error {
                    println!("         Error: {}", error);
                }
            }

            if !result.metrics.is_empty() {
                println!("         Metrics:");
                for (key, value) in &result.metrics {
                    println!("           {}: {:.2}", key, value);
                }
            }
        }

        // Performance summary
        println!("\n--- Performance Summary ---\n");

        let avg_duration = results.iter().map(|r| r.duration_ms).sum::<u64>() as f64 / results.len() as f64;
        let max_duration = results.iter().map(|r| r.duration_ms).max().unwrap_or(0);
        let min_duration = results.iter().map(|r| r.duration_ms).min().unwrap_or(0);

        println!("Average Test Duration: {:.2} ms", avg_duration);
        println!("Max Test Duration: {} ms", max_duration);
        println!("Min Test Duration: {} ms", min_duration);

        // Collect all metrics
        let mut all_metrics = std::collections::HashMap::<String, Vec<f64>>::new();
        for result in results {
            for (key, value) in &result.metrics {
                all_metrics.entry(key.clone()).or_insert_with(Vec::new).push(*value);
            }
        }

        if !all_metrics.is_empty() {
            println!("\n--- Performance Metrics ---\n");
            for (metric, values) in all_metrics {
                let avg = values.iter().sum::<f64>() / values.len() as f64;
                let max = values.iter().fold(0.0f64, |a, &b| a.max(b));
                let min = values.iter().fold(f64::INFINITY, |a, &b| a.min(b));

                println!("{}: avg={:.2}, min={:.2}, max={:.2}", metric, avg, min, max);
            }
        }
    }

    Ok(())
}

async fn generate_json_report(
    results: &[ghostwire_tests::TestResult],
    duration: std::time::Duration,
    args: &Args,
) -> Result<()> {
    let report = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "duration_ms": duration.as_millis(),
        "total_tests": results.len(),
        "passed": results.iter().filter(|r| r.success).count(),
        "failed": results.iter().filter(|r| !r.success).count(),
        "results": results,
        "config": {
            "verbose": args.verbose,
            "parallelism": args.parallelism,
            "timeout_secs": args.timeout,
            "profile": args.profile
        }
    });

    if args.report {
        let filename = format!("ghostwire-test-report-{}.json", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
        tokio::fs::write(&filename, serde_json::to_string_pretty(&report)?).await?;
        info!("JSON report written to {}", filename);
    } else {
        println!("{}", serde_json::to_string_pretty(&report)?);
    }

    Ok(())
}

async fn generate_html_report(
    results: &[ghostwire_tests::TestResult],
    duration: std::time::Duration,
    args: &Args,
) -> Result<()> {
    let passed = results.iter().filter(|r| r.success).count();
    let failed = results.iter().filter(|r| !r.success).count();

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>GhostWire Test Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .summary {{ background-color: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .test-result {{ margin: 10px 0; padding: 10px; border-radius: 3px; }}
        .pass {{ background-color: #d4edda; border-left: 4px solid #28a745; }}
        .fail {{ background-color: #f8d7da; border-left: 4px solid #dc3545; }}
        .metrics {{ margin-left: 20px; font-size: 0.9em; color: #666; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <h1>GhostWire Test Report</h1>

    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Generated:</strong> {}</p>
        <p><strong>Duration:</strong> {:.2}s</p>
        <p><strong>Total Tests:</strong> {}</p>
        <p><strong>Passed:</strong> {} ({:.1}%)</p>
        <p><strong>Failed:</strong> {} ({:.1}%)</p>
    </div>

    <h2>Test Results</h2>
    <table>
        <tr>
            <th>Test Name</th>
            <th>Status</th>
            <th>Duration (ms)</th>
            <th>Metrics</th>
            <th>Error</th>
        </tr>
"#,
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
        duration.as_secs_f64(),
        results.len(),
        passed,
        (passed as f64 / results.len() as f64) * 100.0,
        failed,
        (failed as f64 / results.len() as f64) * 100.0,
    );

    let mut html = html;

    for result in results {
        let status_class = if result.success { "pass" } else { "fail" };
        let status_text = if result.success { "PASS" } else { "FAIL" };

        let metrics_text = if result.metrics.is_empty() {
            String::new()
        } else {
            result.metrics.iter()
                .map(|(k, v)| format!("{}: {:.2}", k, v))
                .collect::<Vec<_>>()
                .join(", ")
        };

        let error_text = result.error.as_deref().unwrap_or("");

        html.push_str(&format!(
            r#"        <tr class="{}">
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
            <td>{}</td>
        </tr>
"#,
            status_class, result.name, status_text, result.duration_ms, metrics_text, error_text
        ));
    }

    html.push_str(
        r#"    </table>
</body>
</html>"#,
    );

    if args.report {
        let filename = format!("ghostwire-test-report-{}.html", chrono::Utc::now().format("%Y%m%d-%H%M%S"));
        tokio::fs::write(&filename, html).await?;
        info!("HTML report written to {}", filename);
    } else {
        println!("{}", html);
    }

    Ok(())
}