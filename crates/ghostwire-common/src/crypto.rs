/// Cryptographic utilities for GhostWire
///
/// Provides high-level crypto operations for:
/// - WireGuard key generation and validation
/// - Session token generation and verification
/// - DERP encryption and authentication
/// - Secure random number generation

use crate::types::{PublicKey, PrivateKey};
use crate::error::{Result, GhostWireError};
use blake3::Hasher;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey, SecretKey};
use std::time::{SystemTime, UNIX_EPOCH};
use rand::{RngCore, rngs::OsRng};
use subtle::{ConditionallySelectable, Choice};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

/// WireGuard key management
pub struct WireGuardKeys;

impl WireGuardKeys {
    /// Generate a new WireGuard keypair
    pub fn generate() -> Result<(PrivateKey, PublicKey)> {
        let mut private_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut private_bytes);

        // Clamp the private key for X25519 (WireGuard requirement)
        private_bytes[0] &= 248;
        private_bytes[31] &= 127;
        private_bytes[31] |= 64;

        let private_key = PrivateKey(private_bytes);

        // Generate public key from private key
        let public_key = Self::public_from_private(&private_key)?;

        Ok((private_key, public_key))
    }

    /// Derive public key from private key
    pub fn public_from_private(private_key: &PrivateKey) -> Result<PublicKey> {
        // This is a placeholder - in real implementation, use x25519-dalek
        // to derive the public key from the private key
        let mut public_bytes = [0u8; 32];
        // TODO: Implement actual X25519 scalar multiplication
        // For now, just use a hash of the private key as placeholder
        let mut hasher = Hasher::new();
        hasher.update(&private_key.0);
        let hash = hasher.finalize();
        public_bytes.copy_from_slice(&hash.as_bytes()[..32]);

        Ok(PublicKey(public_bytes))
    }

    /// Validate a WireGuard public key
    pub fn validate_public_key(key: &[u8]) -> Result<PublicKey> {
        if key.len() != 32 {
            return Err(GhostWireError::crypto("Public key must be 32 bytes"));
        }

        let key_array: [u8; 32] = key.try_into()
            .map_err(|_| GhostWireError::crypto("Invalid public key format"))?;

        // Check for invalid keys
        if key_array == [0u8; 32] {
            return Err(GhostWireError::crypto("Public key cannot be all zeros"));
        }

        Ok(PublicKey(key_array))
    }

    /// Validate a WireGuard private key
    pub fn validate_private_key(key: &[u8]) -> Result<PrivateKey> {
        if key.len() != 32 {
            return Err(GhostWireError::crypto("Private key must be 32 bytes"));
        }

        let key_array: [u8; 32] = key.try_into()
            .map_err(|_| GhostWireError::crypto("Invalid private key format"))?;

        // Check for invalid keys
        if key_array == [0u8; 32] {
            return Err(GhostWireError::crypto("Private key cannot be all zeros"));
        }

        Ok(PrivateKey(key_array))
    }
}

/// Session token management
pub struct SessionTokens;

impl SessionTokens {
    /// Generate a secure session token
    pub fn generate(node_public_key: &PublicKey, user_id: &str) -> Result<String> {
        let mut hasher = Hasher::new();

        // Add node public key
        hasher.update(&node_public_key.0);

        // Add user ID
        hasher.update(user_id.as_bytes());

        // Add current timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| GhostWireError::internal("Invalid system time"))?
            .as_secs();
        hasher.update(&timestamp.to_le_bytes());

        // Add random bytes
        let mut random_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut random_bytes);
        hasher.update(&random_bytes);

        let hash = hasher.finalize();

        // Encode as URL-safe base64
        Ok(URL_SAFE_NO_PAD.encode(hash.as_bytes()))
    }

    /// Validate a session token (placeholder implementation)
    pub fn validate(_token: &str, _node_public_key: &PublicKey, _user_id: &str) -> Result<bool> {
        // TODO: Implement proper token validation
        // This would involve:
        // 1. Decoding the base64 token
        // 2. Checking if it was generated with the correct inputs
        // 3. Verifying the timestamp is within acceptable range
        // 4. Rate limiting validation attempts

        Ok(true) // Placeholder
    }
}

/// Digital signatures for authentication
pub struct DigitalSignatures;

impl DigitalSignatures {
    /// Generate a new Ed25519 signing keypair
    pub fn generate_signing_key() -> Result<(SigningKey, VerifyingKey)> {
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);

        let secret_key = SecretKey::try_from(secret_bytes.as_slice())
            .map_err(|_| GhostWireError::crypto("Failed to create secret key"))?;
        let signing_key = SigningKey::from_bytes(&secret_key);
        let verifying_key = signing_key.verifying_key();

        Ok((signing_key, verifying_key))
    }

    /// Sign data with Ed25519 private key
    pub fn sign(signing_key: &SigningKey, data: &[u8]) -> Result<Signature> {
        Ok(signing_key.sign(data))
    }

    /// Verify Ed25519 signature
    pub fn verify(verifying_key: &VerifyingKey, data: &[u8], signature: &Signature) -> Result<()> {
        verifying_key.verify(data, signature)
            .map_err(|_| GhostWireError::crypto("Invalid signature"))
    }
}

/// Secure random number generation
pub struct SecureRandom;

impl SecureRandom {
    /// Generate cryptographically secure random bytes
    pub fn bytes(length: usize) -> Result<Vec<u8>> {
        let mut bytes = vec![0u8; length];
        OsRng.fill_bytes(&mut bytes);
        Ok(bytes)
    }

    /// Generate a secure random u64
    pub fn u64() -> Result<u64> {
        let mut bytes = [0u8; 8];
        OsRng.fill_bytes(&mut bytes);
        Ok(u64::from_le_bytes(bytes))
    }

    /// Generate a secure random UUID-style string
    pub fn uuid_string() -> Result<String> {
        let bytes = Self::bytes(16)?;
        Ok(uuid::Uuid::from_bytes(
            bytes.try_into()
                .map_err(|_| GhostWireError::internal("Failed to generate UUID"))?
        ).to_string())
    }
}

/// Constant-time operations for security
pub struct ConstantTime;

impl ConstantTime {
    /// Constant-time comparison of byte arrays
    pub fn compare(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }

        subtle::ConstantTimeEq::ct_eq(a, b).into()
    }

    /// Constant-time conditional select
    pub fn select(condition: bool, a: &[u8], b: &[u8]) -> Vec<u8> {
        let choice = Choice::from(condition as u8);
        a.iter()
            .zip(b.iter())
            .map(|(a_byte, b_byte)| {
                u8::conditional_select(a_byte, b_byte, choice)
            })
            .collect()
    }
}

/// Hash-based key derivation
pub struct KeyDerivation;

impl KeyDerivation {
    /// Derive key using BLAKE3 KDF
    pub fn derive_key(input: &[u8], context: &[u8], output_length: usize) -> Result<Vec<u8>> {
        let mut hasher = Hasher::new();
        hasher.update(input);
        hasher.update(context);

        let hash = hasher.finalize();

        if output_length <= 32 {
            Ok(hash.as_bytes()[..output_length].to_vec())
        } else {
            // For longer outputs, repeat the hash
            let mut output = vec![0u8; output_length];
            let mut offset = 0;
            while offset < output_length {
                let remaining = output_length - offset;
                let copy_len = remaining.min(32);
                output[offset..offset + copy_len].copy_from_slice(&hash.as_bytes()[..copy_len]);
                offset += copy_len;
            }
            Ok(output)
        }
    }

    /// Password-based key derivation (for admin passwords)
    pub fn derive_password_key(password: &str, salt: &[u8], iterations: u32) -> Result<[u8; 32]> {
        // This is a simplified implementation
        // In production, use a proper PBKDF2 or Argon2 implementation
        let mut hasher = Hasher::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        hasher.update(&iterations.to_le_bytes());

        let hash = hasher.finalize();
        Ok(*hash.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wireguard_key_generation() {
        let (private_key, public_key) = WireGuardKeys::generate().unwrap();

        // Keys should not be all zeros
        assert_ne!(private_key.0, [0u8; 32]);
        assert_ne!(public_key.0, [0u8; 32]);

        // Public key should be derivable from private key
        let derived_public = WireGuardKeys::public_from_private(&private_key).unwrap();
        assert_eq!(public_key.0, derived_public.0);
    }

    #[test]
    fn test_session_token_generation() {
        let (_, public_key) = WireGuardKeys::generate().unwrap();
        let user_id = "test-user";

        let token1 = SessionTokens::generate(&public_key, user_id).unwrap();
        let token2 = SessionTokens::generate(&public_key, user_id).unwrap();

        // Tokens should be different due to randomness and timestamp
        assert_ne!(token1, token2);

        // Tokens should be base64 URL-safe encoded
        assert!(token1.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }

    #[test]
    fn test_digital_signatures() {
        let (signing_key, verifying_key) = DigitalSignatures::generate_signing_key().unwrap();
        let data = b"test message";

        let signature = DigitalSignatures::sign(&signing_key, data).unwrap();
        DigitalSignatures::verify(&verifying_key, data, &signature).unwrap();

        // Verification should fail with wrong data
        let wrong_data = b"wrong message";
        assert!(DigitalSignatures::verify(&verifying_key, wrong_data, &signature).is_err());
    }

    #[test]
    fn test_constant_time_operations() {
        let a = b"hello";
        let b = b"hello";
        let c = b"world";

        assert!(ConstantTime::compare(a, b));
        assert!(!ConstantTime::compare(a, c));
        assert!(!ConstantTime::compare(a, b"hi")); // Different lengths
    }

    #[test]
    fn test_key_derivation() {
        let input = b"test input";
        let context = b"test context";

        let key1 = KeyDerivation::derive_key(input, context, 32).unwrap();
        let key2 = KeyDerivation::derive_key(input, context, 32).unwrap();
        let key3 = KeyDerivation::derive_key(input, b"different context", 32).unwrap();

        // Same inputs should produce same key
        assert_eq!(key1, key2);

        // Different context should produce different key
        assert_ne!(key1, key3);

        // Key should be requested length
        assert_eq!(key1.len(), 32);
    }
}