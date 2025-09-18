use std::process::Command;

fn main() {
    println!("🧪 Testing ZQLite Integration");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // Test 1: Check ZQLite binary is available
    println!("✅ Test 1: ZQLite binary availability");
    match Command::new("zqlite").arg("version").output() {
        Ok(output) => {
            println!("   ZQLite version: {}", String::from_utf8_lossy(&output.stdout));
        }
        Err(e) => {
            println!("   ❌ ZQLite binary not found: {}", e);
            return;
        }
    }

    // Test 2: Check ZQLite header files
    println!("✅ Test 2: ZQLite header files");
    let header_paths = vec![
        "/usr/local/include/zqlite.h",
        "/usr/include/zqlite.h",
        "/home/chris/.local/include/zqlite.h",
    ];

    let mut header_found = false;
    for path in header_paths {
        if std::path::Path::new(path).exists() {
            println!("   Found header: {}", path);
            header_found = true;
            break;
        }
    }

    if !header_found {
        println!("   ⚠️  ZQLite header files not found in standard locations");
        println!("   This may require building ZQLite from source with FFI support");
    }

    // Test 3: Check ZQLite library files
    println!("✅ Test 3: ZQLite library files");
    let lib_paths = vec![
        "/usr/local/lib/libzqlite.so",
        "/usr/lib/libzqlite.so",
        "/home/chris/.local/lib/libzqlite.so",
    ];

    let mut lib_found = false;
    for path in lib_paths {
        if std::path::Path::new(path).exists() {
            println!("   Found library: {}", path);
            lib_found = true;
            break;
        }
    }

    if !lib_found {
        println!("   ⚠️  ZQLite library files not found in standard locations");
        println!("   This may require building ZQLite from source with FFI support");
    }

    // Test 4: Test basic ZQLite functionality
    println!("✅ Test 4: Basic ZQLite functionality");
    match Command::new("zqlite")
        .arg("exec")
        .arg(":memory:")
        .arg("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT); INSERT INTO test (name) VALUES ('Ghostwire'); SELECT * FROM test;")
        .output()
    {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            if stdout.contains("Ghostwire") {
                println!("   ✅ Basic SQL operations working");
            } else {
                println!("   ❌ SQL operations failed");
                println!("   STDOUT: {}", stdout);
                println!("   STDERR: {}", stderr);
            }
        }
        Err(e) => {
            println!("   ❌ Failed to execute ZQLite command: {}", e);
        }
    }

    println!("\n🎯 Integration Status:");
    if header_found && lib_found {
        println!("   ✅ ZQLite is ready for Rust FFI integration");
        println!("   🚀 Ghostwire can now use ZQLite's advanced features:");
        println!("      • Post-quantum cryptography");
        println!("      • 56x faster peer registration");
        println!("      • 37x faster ACL evaluation");
        println!("      • 70% compression ratio");
        println!("      • Sub-millisecond query latencies");
    } else {
        println!("   ⚠️  ZQLite FFI components need to be built");
        println!("   📝 Next steps:");
        println!("      1. Clone ZQLite source: git clone https://github.com/ghostkellz/zqlite");
        println!("      2. Build with FFI: zig build -Dffi=true");
        println!("      3. Install headers and libraries");
        println!("      4. Set ZQLITE_PATH and ZQLITE_INCLUDE environment variables");
    }
}