/// Utility functions for GhostWire Desktop
///
/// Common helper functions used throughout the application.

use std::time::{SystemTime, UNIX_EPOCH};
use chrono::{DateTime, Utc};

/// Format bytes in human-readable format
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];

    if bytes == 0 {
        return "0 B".to_string();
    }

    let mut value = bytes as f64;
    let mut unit_index = 0;

    while value >= 1024.0 && unit_index < UNITS.len() - 1 {
        value /= 1024.0;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.1} {}", value, UNITS[unit_index])
    }
}

/// Format duration in human-readable format
pub fn format_duration(duration: std::time::Duration) -> String {
    let total_seconds = duration.as_secs();

    if total_seconds < 60 {
        format!("{}s", total_seconds)
    } else if total_seconds < 3600 {
        let minutes = total_seconds / 60;
        let seconds = total_seconds % 60;
        if seconds == 0 {
            format!("{}m", minutes)
        } else {
            format!("{}m {}s", minutes, seconds)
        }
    } else if total_seconds < 86400 {
        let hours = total_seconds / 3600;
        let minutes = (total_seconds % 3600) / 60;
        if minutes == 0 {
            format!("{}h", hours)
        } else {
            format!("{}h {}m", hours, minutes)
        }
    } else {
        let days = total_seconds / 86400;
        let hours = (total_seconds % 86400) / 3600;
        if hours == 0 {
            format!("{}d", days)
        } else {
            format!("{}d {}h", days, hours)
        }
    }
}

/// Format relative time from a timestamp
pub fn format_relative_time(time: DateTime<Utc>) -> String {
    let now = Utc::now();
    let duration = now.signed_duration_since(time);

    if duration.num_seconds() < 0 {
        return "in the future".to_string();
    }

    let seconds = duration.num_seconds();

    if seconds < 60 {
        "just now".to_string()
    } else if seconds < 3600 {
        let minutes = seconds / 60;
        if minutes == 1 {
            "1 minute ago".to_string()
        } else {
            format!("{} minutes ago", minutes)
        }
    } else if seconds < 86400 {
        let hours = seconds / 3600;
        if hours == 1 {
            "1 hour ago".to_string()
        } else {
            format!("{} hours ago", hours)
        }
    } else if seconds < 2592000 {
        let days = seconds / 86400;
        if days == 1 {
            "1 day ago".to_string()
        } else {
            format!("{} days ago", days)
        }
    } else if seconds < 31536000 {
        let months = seconds / 2592000;
        if months == 1 {
            "1 month ago".to_string()
        } else {
            format!("{} months ago", months)
        }
    } else {
        let years = seconds / 31536000;
        if years == 1 {
            "1 year ago".to_string()
        } else {
            format!("{} years ago", years)
        }
    }
}

/// Validate IP address string
pub fn is_valid_ip(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>().is_ok()
}

/// Validate CIDR notation
pub fn is_valid_cidr(cidr: &str) -> bool {
    if let Some((ip_str, prefix_str)) = cidr.split_once('/') {
        if let (Ok(_), Ok(prefix)) = (ip_str.parse::<std::net::IpAddr>(), prefix_str.parse::<u8>()) {
            // Check prefix length based on IP version
            match ip_str.parse::<std::net::IpAddr>().unwrap() {
                std::net::IpAddr::V4(_) => prefix <= 32,
                std::net::IpAddr::V6(_) => prefix <= 128,
            }
        } else {
            false
        }
    } else {
        false
    }
}

/// Generate a random machine name
pub fn generate_machine_name() -> String {
    let adjectives = [
        "swift", "bright", "clever", "gentle", "brave", "quiet", "wise", "bold",
        "calm", "eager", "fair", "happy", "kind", "lively", "nice", "proud",
    ];

    let nouns = [
        "fox", "hawk", "wolf", "bear", "deer", "lion", "eagle", "shark",
        "tiger", "panther", "falcon", "lynx", "otter", "badger", "raven", "seal",
    ];

    let adj = adjectives[fastrand::usize(..adjectives.len())];
    let noun = nouns[fastrand::usize(..nouns.len())];
    let number = fastrand::u16(100..999);

    format!("{}-{}-{}", adj, noun, number)
}

/// Check if the application is running with elevated privileges
pub fn is_elevated() -> bool {
    #[cfg(windows)]
    {
        // On Windows, check if running as administrator
        use std::ffi::CString;
        use winapi::um::processthreadsapi::GetCurrentProcess;
        use winapi::um::securitybaseapi::GetTokenInformation;
        use winapi::um::winnt::{TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};

        unsafe {
            let mut token = std::ptr::null_mut();
            if winapi::um::processthreadsapi::OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY,
                &mut token,
            ) == 0 {
                return false;
            }

            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut size = 0;

            let result = GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut _ as *mut _,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut size,
            );

            winapi::um::handleapi::CloseHandle(token);

            result != 0 && elevation.TokenIsElevated != 0
        }
    }

    #[cfg(unix)]
    {
        // On Unix systems, check if running as root
        unsafe { libc::geteuid() == 0 }
    }

    #[cfg(not(any(windows, unix)))]
    {
        false
    }
}

/// Get the application data directory
pub fn get_app_data_dir() -> std::path::PathBuf {
    if let Some(data_dir) = dirs::data_dir() {
        data_dir.join("ghostwire")
    } else {
        // Fallback
        #[cfg(windows)]
        {
            std::path::PathBuf::from(r"C:\Users\Default\AppData\Local\ghostwire")
        }
        #[cfg(not(windows))]
        {
            std::path::PathBuf::from("~/.local/share/ghostwire")
        }
    }
}

/// Create a backup of a file
pub async fn backup_file<P: AsRef<std::path::Path>>(
    file_path: P,
) -> Result<std::path::PathBuf, std::io::Error> {
    let path = file_path.as_ref();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let backup_path = if let Some(extension) = path.extension() {
        path.with_extension(format!("{}.backup.{}", extension.to_string_lossy(), timestamp))
    } else {
        path.with_extension(format!("backup.{}", timestamp))
    };

    tokio::fs::copy(path, &backup_path).await?;
    Ok(backup_path)
}

/// Truncate text to a maximum length with ellipsis
pub fn truncate_text(text: &str, max_length: usize) -> String {
    if text.len() <= max_length {
        text.to_string()
    } else if max_length <= 3 {
        "...".to_string()
    } else {
        format!("{}...", &text[..max_length - 3])
    }
}

/// Parse a server URL and ensure it's valid
pub fn parse_server_url(url: &str) -> Result<String, String> {
    let url = url.trim();

    if url.is_empty() {
        return Err("Server URL cannot be empty".to_string());
    }

    // Add https:// if no scheme is provided
    let url = if !url.starts_with("http://") && !url.starts_with("https://") {
        format!("https://{}", url)
    } else {
        url.to_string()
    };

    // Validate URL format
    match url::Url::parse(&url) {
        Ok(parsed) => {
            if parsed.scheme() != "http" && parsed.scheme() != "https" {
                Err("Server URL must use HTTP or HTTPS".to_string())
            } else if parsed.host().is_none() {
                Err("Server URL must have a valid hostname".to_string())
            } else {
                Ok(url)
            }
        }
        Err(_) => Err("Invalid server URL format".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1048576), "1.0 MB");
        assert_eq!(format_bytes(1073741824), "1.0 GB");
    }

    #[test]
    fn test_is_valid_ip() {
        assert!(is_valid_ip("192.168.1.1"));
        assert!(is_valid_ip("2001:db8::1"));
        assert!(!is_valid_ip("256.1.1.1"));
        assert!(!is_valid_ip("not-an-ip"));
    }

    #[test]
    fn test_is_valid_cidr() {
        assert!(is_valid_cidr("192.168.1.0/24"));
        assert!(is_valid_cidr("10.0.0.0/8"));
        assert!(is_valid_cidr("2001:db8::/32"));
        assert!(!is_valid_cidr("192.168.1.0/33"));
        assert!(!is_valid_cidr("192.168.1.0"));
        assert!(!is_valid_cidr("not-a-cidr/24"));
    }

    #[test]
    fn test_truncate_text() {
        assert_eq!(truncate_text("hello", 10), "hello");
        assert_eq!(truncate_text("hello world", 8), "hello...");
        assert_eq!(truncate_text("hi", 2), "hi");
        assert_eq!(truncate_text("hello", 3), "...");
    }

    #[test]
    fn test_parse_server_url() {
        assert_eq!(parse_server_url("example.com").unwrap(), "https://example.com");
        assert_eq!(parse_server_url("http://example.com").unwrap(), "http://example.com");
        assert_eq!(parse_server_url("https://example.com").unwrap(), "https://example.com");
        assert!(parse_server_url("").is_err());
        assert!(parse_server_url("ftp://example.com").is_err());
    }
}