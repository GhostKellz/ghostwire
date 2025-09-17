/// Machines/Nodes API operations
///
/// API functions for managing machines in the GhostWire network.

use gloo_net::http::Request;
use chrono::{DateTime, Utc};

use crate::types::{Node, User, ApiResponse};

/// Fetch all machines from the API
pub async fn fetch_machines() -> Result<Vec<Node>, String> {
    // Mock data for now - would normally call the API
    Ok(vec![
        Node {
            id: "node1".to_string(),
            name: "laptop-alice".to_string(),
            node_key: "nodekey_alice123".to_string(),
            machine_key: "machinekey_alice456".to_string(),
            ip_addresses: vec!["100.64.0.1".to_string()],
            user: "alice".to_string(),
            hostname: "alice-laptop".to_string(),
            given_name: Some("Alice's Laptop".to_string()),
            online: true,
            last_seen: Some(Utc::now() - chrono::Duration::minutes(5)),
            created_at: Utc::now() - chrono::Duration::hours(24),
            updated_at: Utc::now() - chrono::Duration::minutes(5),
            expires_at: None,
            tags: vec!["dev".to_string(), "laptop".to_string()],
            forced_tags: vec![],
            invalid_tags: vec![],
            register_method: "authkey".to_string(),
            ephemeral: false,
            pre_auth_key_used: Some("preauth_key_123".to_string()),
            version: Some("1.54.0".to_string()),
            os: Some("linux".to_string()),
            arch: Some("amd64".to_string()),
        },
        Node {
            id: "node2".to_string(),
            name: "server-production".to_string(),
            node_key: "nodekey_server789".to_string(),
            machine_key: "machinekey_server101".to_string(),
            ip_addresses: vec!["100.64.0.2".to_string(), "fd7a:115c:a1e0::2".to_string()],
            user: "admin".to_string(),
            hostname: "prod-server-01".to_string(),
            given_name: Some("Production Server".to_string()),
            online: true,
            last_seen: Some(Utc::now() - chrono::Duration::minutes(1)),
            created_at: Utc::now() - chrono::Duration::days(7),
            updated_at: Utc::now() - chrono::Duration::minutes(1),
            expires_at: None,
            tags: vec!["production".to_string(), "server".to_string()],
            forced_tags: vec!["server".to_string()],
            invalid_tags: vec![],
            register_method: "cli".to_string(),
            ephemeral: false,
            pre_auth_key_used: None,
            version: Some("1.54.0".to_string()),
            os: Some("linux".to_string()),
            arch: Some("amd64".to_string()),
        },
        Node {
            id: "node3".to_string(),
            name: "mobile-bob".to_string(),
            node_key: "nodekey_bob321".to_string(),
            machine_key: "machinekey_bob654".to_string(),
            ip_addresses: vec!["100.64.0.3".to_string()],
            user: "bob".to_string(),
            hostname: "bob-phone".to_string(),
            given_name: Some("Bob's Phone".to_string()),
            online: false,
            last_seen: Some(Utc::now() - chrono::Duration::hours(2)),
            created_at: Utc::now() - chrono::Duration::days(3),
            updated_at: Utc::now() - chrono::Duration::hours(2),
            expires_at: None,
            tags: vec!["mobile".to_string()],
            forced_tags: vec![],
            invalid_tags: vec![],
            register_method: "oauth".to_string(),
            ephemeral: true,
            pre_auth_key_used: None,
            version: Some("1.52.1".to_string()),
            os: Some("android".to_string()),
            arch: Some("arm64".to_string()),
        },
    ])
}

/// Fetch users for filtering
pub async fn fetch_users() -> Result<Vec<User>, String> {
    // Mock data for now
    Ok(vec![
        User {
            id: "user1".to_string(),
            name: "alice".to_string(),
            email: Some("alice@example.com".to_string()),
            provider: "oidc".to_string(),
            provider_id: Some("alice_oidc_123".to_string()),
            created_at: Utc::now() - chrono::Duration::days(30),
            updated_at: Utc::now() - chrono::Duration::days(1),
            role: "user".to_string(),
            active: true,
            last_login: Some(Utc::now() - chrono::Duration::hours(1)),
        },
        User {
            id: "user2".to_string(),
            name: "admin".to_string(),
            email: Some("admin@example.com".to_string()),
            provider: "local".to_string(),
            provider_id: None,
            created_at: Utc::now() - chrono::Duration::days(90),
            updated_at: Utc::now() - chrono::Duration::minutes(30),
            role: "admin".to_string(),
            active: true,
            last_login: Some(Utc::now() - chrono::Duration::minutes(30)),
        },
        User {
            id: "user3".to_string(),
            name: "bob".to_string(),
            email: Some("bob@example.com".to_string()),
            provider: "oidc".to_string(),
            provider_id: Some("bob_oidc_456".to_string()),
            created_at: Utc::now() - chrono::Duration::days(10),
            updated_at: Utc::now() - chrono::Duration::hours(3),
            role: "user".to_string(),
            active: true,
            last_login: Some(Utc::now() - chrono::Duration::hours(3)),
        },
    ])
}

/// Delete a machine
pub async fn delete_machine(machine_id: &str) -> Result<(), String> {
    // This would normally make an API call
    log::info!("Deleting machine: {}", machine_id);
    Ok(())
}

/// Update machine tags
pub async fn update_machine_tags(machine_id: &str, tags: Vec<String>) -> Result<Node, String> {
    // This would normally make an API call
    log::info!("Updating machine {} tags: {:?}", machine_id, tags);

    // Return a mock updated machine for now
    Err("Not implemented".to_string())
}

/// Move machine to different user
pub async fn move_machine_to_user(machine_id: &str, user_id: &str) -> Result<Node, String> {
    // This would normally make an API call
    log::info!("Moving machine {} to user {}", machine_id, user_id);

    Err("Not implemented".to_string())
}

/// Rename a machine
pub async fn rename_machine(machine_id: &str, new_name: &str) -> Result<Node, String> {
    // This would normally make an API call
    log::info!("Renaming machine {} to {}", machine_id, new_name);

    Err("Not implemented".to_string())
}