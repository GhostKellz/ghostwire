/// Utility functions for gwctl
///
/// Common helper functions used across different command modules.

use anyhow::Result;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Expand shell-style paths like ~ and environment variables
pub fn expand_path(path: &str) -> Result<std::path::PathBuf> {
    let expanded = shellexpand::full(path)?;
    Ok(std::path::PathBuf::from(expanded.as_ref()))
}

/// Check if a file exists and is readable
pub fn check_file_readable(path: &Path) -> bool {
    path.exists() && path.is_file()
}

/// Get current timestamp as RFC3339 string
pub fn current_timestamp() -> String {
    chrono::Utc::now().to_rfc3339()
}

/// Parse duration string (e.g., "5m", "1h", "30s")
pub fn parse_duration(s: &str) -> Result<std::time::Duration> {
    let s = s.trim().to_lowercase();

    if s.ends_with('s') {
        let num: u64 = s[..s.len()-1].parse()?;
        Ok(std::time::Duration::from_secs(num))
    } else if s.ends_with('m') {
        let num: u64 = s[..s.len()-1].parse()?;
        Ok(std::time::Duration::from_secs(num * 60))
    } else if s.ends_with('h') {
        let num: u64 = s[..s.len()-1].parse()?;
        Ok(std::time::Duration::from_secs(num * 3600))
    } else if s.ends_with('d') {
        let num: u64 = s[..s.len()-1].parse()?;
        Ok(std::time::Duration::from_secs(num * 86400))
    } else {
        // Try parsing as seconds
        let num: u64 = s.parse()?;
        Ok(std::time::Duration::from_secs(num))
    }
}

/// Validate IP address or CIDR
pub fn validate_ip_or_cidr(s: &str) -> Result<()> {
    if s.contains('/') {
        // CIDR notation
        use ipnet::IpNet;
        s.parse::<IpNet>()?;
    } else {
        // IP address
        use std::net::IpAddr;
        s.parse::<IpAddr>()?;
    }
    Ok(())
}

/// Generate a random ID
pub fn generate_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Format timestamp for display
pub fn format_timestamp_relative(timestamp: &str) -> String {
    if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(timestamp) {
        let now = chrono::Utc::now();
        let diff = now.signed_duration_since(parsed.with_timezone(&chrono::Utc));

        if diff.num_seconds() < 60 {
            "just now".to_string()
        } else if diff.num_minutes() < 60 {
            format!("{}m ago", diff.num_minutes())
        } else if diff.num_hours() < 24 {
            format!("{}h ago", diff.num_hours())
        } else if diff.num_days() < 7 {
            format!("{}d ago", diff.num_days())
        } else {
            parsed.format("%Y-%m-%d").to_string()
        }
    } else {
        timestamp.to_string()
    }
}

/// Validate node name/ID format
pub fn validate_node_identifier(id: &str) -> Result<()> {
    if id.is_empty() {
        anyhow::bail!("Node identifier cannot be empty");
    }

    if id.len() > 64 {
        anyhow::bail!("Node identifier too long (max 64 characters)");
    }

    // Check for valid characters (alphanumeric, dash, underscore)
    if !id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        anyhow::bail!("Node identifier contains invalid characters (only alphanumeric, -, _ allowed)");
    }

    Ok(())
}

/// Validate username format
pub fn validate_username(username: &str) -> Result<()> {
    if username.is_empty() {
        anyhow::bail!("Username cannot be empty");
    }

    if username.len() < 3 {
        anyhow::bail!("Username too short (minimum 3 characters)");
    }

    if username.len() > 32 {
        anyhow::bail!("Username too long (maximum 32 characters)");
    }

    // Check for valid characters
    if !username.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.') {
        anyhow::bail!("Username contains invalid characters");
    }

    // Cannot start with dash
    if username.starts_with('-') {
        anyhow::bail!("Username cannot start with dash");
    }

    Ok(())
}

/// Validate email format (basic validation)
pub fn validate_email(email: &str) -> Result<()> {
    if !email.contains('@') || !email.contains('.') {
        anyhow::bail!("Invalid email format");
    }

    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        anyhow::bail!("Invalid email format");
    }

    Ok(())
}

/// Safe truncate string for display
pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

/// Parse key=value pairs from command line
pub fn parse_key_value_pairs(pairs: &[String]) -> Result<std::collections::HashMap<String, String>> {
    let mut result = std::collections::HashMap::new();

    for pair in pairs {
        if let Some((key, value)) = pair.split_once('=') {
            result.insert(key.to_string(), value.to_string());
        } else {
            anyhow::bail!("Invalid key=value pair: {}", pair);
        }
    }

    Ok(result)
}

/// Confirm dangerous operation
pub fn confirm_operation(message: &str, force: bool) -> Result<bool> {
    if force {
        return Ok(true);
    }

    use dialoguer::Confirm;
    Ok(Confirm::new()
        .with_prompt(message)
        .default(false)
        .interact()?)
}

/// Load file content with error context
pub async fn load_file_content(path: &Path) -> Result<String> {
    tokio::fs::read_to_string(path).await
        .with_context(|| format!("Failed to read file: {}", path.display()))
}

/// Save content to file with backup
pub async fn save_file_with_backup(path: &Path, content: &str) -> Result<()> {
    // Create backup if file exists
    if path.exists() {
        let backup_path = path.with_extension(format!("{}.backup",
            path.extension().and_then(|s| s.to_str()).unwrap_or("txt")));

        if let Err(e) = tokio::fs::copy(path, &backup_path).await {
            eprintln!("Warning: Failed to create backup: {}", e);
        }
    }

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }

    tokio::fs::write(path, content).await
        .with_context(|| format!("Failed to write file: {}", path.display()))
}

/// Calculate file hash for integrity checking
pub async fn calculate_file_hash(path: &Path) -> Result<String> {
    use sha2::{Sha256, Digest};

    let content = tokio::fs::read(path).await
        .with_context(|| format!("Failed to read file: {}", path.display()))?;

    let mut hasher = Sha256::new();
    hasher.update(&content);
    let hash = hasher.finalize();

    Ok(format!("{:x}", hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("30s").unwrap(), std::time::Duration::from_secs(30));
        assert_eq!(parse_duration("5m").unwrap(), std::time::Duration::from_secs(300));
        assert_eq!(parse_duration("2h").unwrap(), std::time::Duration::from_secs(7200));
        assert_eq!(parse_duration("1d").unwrap(), std::time::Duration::from_secs(86400));
        assert_eq!(parse_duration("60").unwrap(), std::time::Duration::from_secs(60));
    }

    #[test]
    fn test_validate_node_identifier() {
        assert!(validate_node_identifier("node-123").is_ok());
        assert!(validate_node_identifier("node_test").is_ok());
        assert!(validate_node_identifier("test123").is_ok());
        assert!(validate_node_identifier("").is_err());
        assert!(validate_node_identifier("node with spaces").is_err());
        assert!(validate_node_identifier("node@example").is_err());
    }

    #[test]
    fn test_validate_username() {
        assert!(validate_username("user123").is_ok());
        assert!(validate_username("user-test").is_ok());
        assert!(validate_username("user.test").is_ok());
        assert!(validate_username("ab").is_err()); // too short
        assert!(validate_username("-user").is_err()); // starts with dash
        assert!(validate_username("user@test").is_err()); // invalid char
    }

    #[test]
    fn test_validate_email() {
        assert!(validate_email("user@example.com").is_ok());
        assert!(validate_email("test.user@domain.org").is_ok());
        assert!(validate_email("invalid").is_err());
        assert!(validate_email("@example.com").is_err());
        assert!(validate_email("user@").is_err());
    }

    #[test]
    fn test_parse_key_value_pairs() {
        let pairs = vec!["key1=value1".to_string(), "key2=value2".to_string()];
        let result = parse_key_value_pairs(&pairs).unwrap();

        assert_eq!(result.get("key1"), Some(&"value1".to_string()));
        assert_eq!(result.get("key2"), Some(&"value2".to_string()));

        let invalid = vec!["invalid_pair".to_string()];
        assert!(parse_key_value_pairs(&invalid).is_err());
    }
}