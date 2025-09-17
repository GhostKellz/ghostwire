/// Validation utilities for forms and user input

use crate::types::ValidationError;

pub fn validate_email(email: &str) -> Result<(), ValidationError> {
    if email.is_empty() {
        return Err(ValidationError {
            field: "email".to_string(),
            message: "Email is required".to_string(),
        });
    }

    if !email.contains('@') || !email.contains('.') {
        return Err(ValidationError {
            field: "email".to_string(),
            message: "Invalid email format".to_string(),
        });
    }

    Ok(())
}

pub fn validate_username(username: &str) -> Result<(), ValidationError> {
    if username.is_empty() {
        return Err(ValidationError {
            field: "username".to_string(),
            message: "Username is required".to_string(),
        });
    }

    if username.len() < 3 {
        return Err(ValidationError {
            field: "username".to_string(),
            message: "Username must be at least 3 characters".to_string(),
        });
    }

    if username.len() > 32 {
        return Err(ValidationError {
            field: "username".to_string(),
            message: "Username cannot exceed 32 characters".to_string(),
        });
    }

    if !username.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Err(ValidationError {
            field: "username".to_string(),
            message: "Username can only contain alphanumeric characters, hyphens, and underscores".to_string(),
        });
    }

    Ok(())
}

pub fn validate_password(password: &str) -> Result<(), ValidationError> {
    if password.is_empty() {
        return Err(ValidationError {
            field: "password".to_string(),
            message: "Password is required".to_string(),
        });
    }

    if password.len() < 8 {
        return Err(ValidationError {
            field: "password".to_string(),
            message: "Password must be at least 8 characters".to_string(),
        });
    }

    Ok(())
}