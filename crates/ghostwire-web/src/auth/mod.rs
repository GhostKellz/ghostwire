/// Authentication management for the web interface
///
/// Handles login/logout, session management, token storage, and authentication state.

use leptos::*;
use serde::{Deserialize, Serialize};
use gloo_net::http::Request;
use wasm_bindgen::prelude::*;

use crate::types::{AuthSession, User, ApiResponse};

/// Authentication context and state management
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub session: ReadSignal<Option<AuthSession>>,
    pub set_session: WriteSignal<Option<AuthSession>>,
    pub login: Action<LoginRequest, Result<(), String>>,
    pub logout: Action<(), ()>,
    pub is_loading: ReadSignal<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub user: User,
    pub expires_at: String,
}

/// Authentication provider component
#[component]
pub fn AuthProvider(children: Children) -> impl IntoView {
    let (session, set_session) = create_signal::<Option<AuthSession>>(None);
    let (is_loading, set_loading) = create_signal(false);

    // Check for existing session on mount
    create_effect(move |_| {
        if let Some(stored_session) = get_stored_session() {
            set_session.set(Some(stored_session));
        }
    });

    // Login action
    let login = create_action(move |request: &LoginRequest| {
        let request = request.clone();
        async move {
            set_loading.set(true);

            let result = perform_login(request).await;

            match result {
                Ok(auth_session) => {
                    store_session(&auth_session);
                    set_session.set(Some(auth_session));
                    set_loading.set(false);
                    Ok(())
                }
                Err(error) => {
                    set_loading.set(false);
                    Err(error)
                }
            }
        }
    });

    // Logout action
    let logout = create_action(move |_: &()| {
        async move {
            clear_stored_session();
            set_session.set(None);

            // Redirect to login page
            let navigate = use_navigate();
            navigate("/auth/login", Default::default());
        }
    });

    let auth_context = AuthContext {
        session,
        set_session,
        login,
        logout,
        is_loading,
    };

    provide_context(auth_context);

    children()
}

/// Hook to access authentication context
pub fn use_auth() -> AuthContext {
    use_context::<AuthContext>()
        .expect("AuthContext must be provided by AuthProvider")
}

/// Perform login API call
async fn perform_login(request: LoginRequest) -> Result<AuthSession, String> {
    let response = Request::post("/api/auth/login")
        .header("Content-Type", "application/json")
        .json(&request)
        .map_err(|e| format!("Failed to create request: {}", e))?
        .send()
        .await
        .map_err(|e| format!("Network error: {}", e))?;

    if response.ok() {
        let login_response: ApiResponse<LoginResponse> = response
            .json()
            .await
            .map_err(|e| format!("Failed to parse response: {}", e))?;

        if login_response.success {
            if let Some(data) = login_response.data {
                let expires_at = chrono::DateTime::parse_from_rfc3339(&data.expires_at)
                    .map_err(|e| format!("Invalid date format: {}", e))?
                    .with_timezone(&chrono::Utc);

                // Get user permissions from token or separate API call
                let permissions = get_user_permissions(&data.token, &data.user.id).await?;

                Ok(AuthSession {
                    user: data.user,
                    token: data.token,
                    expires_at,
                    permissions,
                })
            } else {
                Err("No login data received".to_string())
            }
        } else {
            Err(login_response.error.unwrap_or_else(|| "Login failed".to_string()))
        }
    } else {
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        Err(format!("Login failed: {}", error_text))
    }
}

/// Get user permissions
async fn get_user_permissions(token: &str, user_id: &str) -> Result<crate::types::Permissions, String> {
    // This would normally fetch from the API
    // For now, return default permissions
    Ok(crate::types::Permissions {
        ui_access: true,
        read_machines: true,
        write_machines: true,
        read_users: true,
        write_users: false,
        read_network: true,
        write_network: false,
        read_policy: true,
        write_policy: false,
        read_settings: true,
        write_settings: false,
        generate_auth_keys: true,
    })
}

/// Store session in localStorage
fn store_session(session: &AuthSession) {
    if let Ok(window) = web_sys::window() {
        if let Ok(Some(storage)) = window.local_storage() {
            if let Ok(session_json) = serde_json::to_string(session) {
                let _ = storage.set_item("ghostwire_session", &session_json);
            }
        }
    }
}

/// Get stored session from localStorage
fn get_stored_session() -> Option<AuthSession> {
    if let Ok(window) = web_sys::window() {
        if let Ok(Some(storage)) = window.local_storage() {
            if let Ok(Some(session_json)) = storage.get_item("ghostwire_session") {
                if let Ok(session) = serde_json::from_str::<AuthSession>(&session_json) {
                    // Check if session is still valid
                    if session.expires_at > chrono::Utc::now() {
                        return Some(session);
                    }
                }
            }
        }
    }
    None
}

/// Clear stored session
fn clear_stored_session() {
    if let Ok(window) = web_sys::window() {
        if let Ok(Some(storage)) = window.local_storage() {
            let _ = storage.remove_item("ghostwire_session");
        }
    }
}

/// Check if user has specific permission
pub fn has_permission(session: &AuthSession, permission: &str) -> bool {
    match permission {
        "ui_access" => session.permissions.ui_access,
        "read_machines" => session.permissions.read_machines,
        "write_machines" => session.permissions.write_machines,
        "read_users" => session.permissions.read_users,
        "write_users" => session.permissions.write_users,
        "read_network" => session.permissions.read_network,
        "write_network" => session.permissions.write_network,
        "read_policy" => session.permissions.read_policy,
        "write_policy" => session.permissions.write_policy,
        "read_settings" => session.permissions.read_settings,
        "write_settings" => session.permissions.write_settings,
        "generate_auth_keys" => session.permissions.generate_auth_keys,
        _ => false,
    }
}